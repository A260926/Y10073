# 实验样本证据链

这是一个面向断网多站点实验的 Python Web 应用。样本状态不由当前行直接保存，而由不可变事件链推导。错误记录只能追加 `correction` 事件引用原事件，应用不会更新或删除既有事件行。

## 安装与演示

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m evidence_chain --host 127.0.0.1 --port 5203
```

打开 <http://127.0.0.1:5203/>，页面标题为“实验样本证据链”。空数据库首次启动会写入演示数据，其中包含一个隔离后因缺段补齐而自动入库的示例，以及一个仍被隔离的篡改包。

运行时只依赖 Python 标准库；`[test]` 额外安装 pytest。测试不会访问网络。

## 事件与排序

每个站点维护独立、从 1 开始、严格递增的序号。事件结构为：

- `event_id`：全局唯一的稳定 ID。
- `site_id`、`sequence`：站点内位置。
- `sample_id`：事件作用对象；站点密钥轮换事件可使用站点自身 ID。
- `event_type`：`sample_collected`、`sample_processed`、`sample_aliquoted`、`sample_destroyed`、`correction`、`reconciliation`、`key_rotated`。
- `payload`：仅包含可签名业务字段。
- `recorded_at`：记录/处理时间，可能晚于实际发生时间。
- `effective_at`：业务事实实际发生时间。
- `prev_hash`：本站点前一事件哈希；1 号事件使用字面量 `GENESIS`。
- `event_hash`：本条事件哈希。

站点链排序固定为 `(site_id, sequence)`。样本默认事实时间线按 `(effective_at, site_id, sequence, event_id)` 排序；记录时间线按 `(recorded_at, site_id, sequence, event_id)` 排序。末级键保证规则完全确定、可解释。跨站点没有统一逻辑时钟，因此不会把不同站点压缩成同一序号。

当前状态先选有效 `effective_at <= as_of` 的事件，再应用上面的有效时间排序。`correction` 从自身 `effective_at` 开始替换被引用事件的业务语义，但被引用事件仍保留在来源链中。`recorded_at` 和 `effective_at` 在界面中分别展示。

## 规范化、摘要与签名

哈希和签名使用 SHA-256。规范化 JSON 为 UTF-8、无多余空白、排序键、不转义非 ASCII：

```python
json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

事件哈希对以下精确字段的规范化对象计算 SHA-256：`event_id`、`site_id`、`sequence`、`sample_id`、`event_type`、`payload`、`recorded_at`、`effective_at`、`prev_hash`。

导出包的 `signature` 不参与自身摘要。待签名对象固定包含：

- `format`：`evidence-chain-package/v1`
- `site_id`
- `start_sequence`
- `end_sequence`
- `start_prev_hash`
- `events`
- `created_at`

签名算法为纯 Python Ed25519（RFC 8032）。该实现随应用提供，适合离线测试和内网演示。生产部署应替换为经过审计的密码学库或 HSM，并保留算法版本字段以便升级。

导出包只包含站点公钥指纹和签名，不包含私钥。本地私钥保存在 SQLite `site_private_keys` 表中，不写入导出 JSON；生产环境应改为受控密钥库。

## 密钥轮换

站点可调用轮换接口，应用会：

1. 生成新的 Ed25519 密钥对。
2. 追加一条 `key_rotated` 事件，载荷包含新公钥的 Base64、公钥指纹、`valid_from_sequence`（即轮换事件序号）和轮换时间。
3. 用旧私钥签名包含轮换事件的导出包；中心验证该事件后才信任新公钥。
4. 后续以轮换事件序号为起点的包由新私钥签名。

为避免一个包内出现多段信任边界，`key_rotated` 事件若存在必须是包中最后一个事件。中心只接受本地已登记公钥、或由有效链上轮换事件证明的公钥。

## 导入、隔离与并发

导入会在一个事务中完成签名、站点、序号、前序哈希、事件哈希、事件 ID 内容一致性和载荷校验。任何失败都写入 `packages` 的 `quarantined` 状态，事件只进入 `package_events`，不会有一半事件混入主 `events` 表。

重复导入完全相同的包会返回首次结果，不会重复追加。若包的前序哈希等于当前链尾，相邻导入会使用 SQLite 事务和短暂等待，避免多线程因提交顺序不同制造缺口。若前序位置高于当前链尾，则作为缺段隔离；缺口包到达并提交后，系统只按严格序号补齐等待中的包。分叉、篡改、相同 `event_id` 不同内容始终隔离。补齐或失败重试只处理包，不会额外追加 `reconciliation`。

两个合法站点对同一样本给出并行事实时，两条事实都保留。状态会标记冲突；用户显式追加 `reconciliation` 事件，列出候选事件并声明 `adopted_event_id`，状态推导才采用被选择分支。

## JSON API

- `GET /api/health`
- `GET /api/sites`
- `POST /api/sites`：`{"site_id":"S3","display_name":"站点三"}`
- `POST /api/sites/register-remote`：登记外部站点公钥。
- `GET /api/events?sample_id=...`
- `POST /api/events`：本地录入业务事件。
- `POST /api/samples/<sample_id>/correction`
- `POST /api/samples/<sample_id>/reconciliation`
- `POST /api/sites/<site_id>/rotate-key`
- `POST /api/packages/export`：`{"site_id":"S1","start_sequence":1,"end_sequence":3}`
- `POST /api/packages/import`
- `GET /api/quarantine`
- `POST /api/quarantine/<package_id>/retry`
- `GET /api/samples/<sample_id>/provenance`
- `GET /api/samples/<sample_id>/state?as_of=2026-01-01T00:00:00Z`

时间字段使用带时区偏移的 ISO 8601 字符串；示例和测试使用 `Z`。
