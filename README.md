# 实验样本证据链

`evidence_chain` 是一个可完全离线运行的 Python Web 应用，用于记录多站点实验样本从采集、处理、分装到销毁的证据链。浏览器界面和 JSON API 共用同一个 SQLite 持久层。

## 安装与演示

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m evidence_chain --host 127.0.0.1 --port 5203
```

打开 `http://127.0.0.1:5203/`。空数据库会自动创建预置演示，页面标题为“实验样本证据链”，并包含：

- `GAMMA`：第 2 个包先到中心并进入隔离，第 1 个包到达后自动补齐、释放，隔离记录仍保留。
- `DELTA`：事件内容被篡改，事件哈希不符，持续隔离，不会写入主链。
- `S-100`：两个合法站点并行报告事实，先保留两条候选状态，再由 `CENTER` 追加显式 `reconciliation` 事件说明采用哪条。
- `S-200`：包含采集、处理、分装、销毁以及 correction 事件。

生产启动时不要暴露内置测试密钥。可用 `--no-demo` 关闭自动演示：

```bash
.venv/bin/python -m evidence_chain --host 127.0.0.1 --port 5203 --db instance/prod.db --no-demo
```

## 不可变事件模型

事件类型：

- `collected`：采集。
- `processed`：处理。
- `aliquoted`：分装。
- `destroyed`：销毁。
- `correction`：纠错，只追加新事件，引用原事件 ID，并包含要覆盖的 payload 字段。
- `reconciliation`：中心或授权站点对并行事实的显式裁决。

旧事件行永不更新、永不删除。纠错事件不会直接改旧行；派生状态时，先按 `(effective_at, recorded_at, site_id, seq, event_id)` 应用 correction patch，再做归约。事件也不允许引用另一个 correction 作为纠错目标。

每个站点维护独立序列：

```text
seq 1, 2, 3, ...
chain_hash(n) = SHA-256(chain_hash(n-1) || event_hash(n))
chain_hash(0) = 64 个 ASCII 0
```

站点导入另一个站点的包前，中心需要先注册该站点的公钥。中心导入的 reconciliation 事件是中心自己站点序列中的普通追加事件。

## 时间语义

每条业务事件都有两个时间：

- `effective_at`：样本事件实际发生的时间。
- `recorded_at`：系统记录该事件的时间。

允许补录，因此 `recorded_at` 可以晚于 `effective_at`，但不能更早。浏览器表格分别显示两列；时间点查询支持：

- `basis=effective`：按实际发生时间截止，默认值。
- `basis=recorded`：按中心/站点可知时间截止。

固定排序规则为：

```text
effective_at, recorded_at, site_id, seq, event_id
```

所有时间都规范化为带时区的 ISO-8601 UTC 字符串，避免站点本地时区造成歧义。站点内生命周期仍以该站点自己的单调 `seq` 校验，防止销毁后再追加物理事件。

## 规范化序列化与摘要

事件哈希使用 SHA-256：

```json
{
  "schema": "evidence-chain-event/v1",
  "event": {
    "event_id": "...",
    "site_id": "...",
    "seq": 1,
    "sample_id": "...",
    "type": "collected",
    "payload": {},
    "effective_at": "...",
    "recorded_at": "..."
  }
}
```

摘要前使用 canonical JSON：

- UTF-8。
- 对象键按 Unicode/字典序排序。
- 无额外空白。
- 不转义非 ASCII 字符。
- 允许有限整数和有限浮点数；拒绝 `NaN`、`Infinity`、二进制和无法跨 JSON 表达的类型。

包内 `event_hashes` 必须逐事件匹配；包的 `prev_hash` 必须等于中心已知该站点链头。若事件内容、事件顺序、前序哈希或序号范围不匹配，整包进入 quarantine，事务中不会写入一半事件。

## 签名包与私钥边界

包格式为 `evidence-chain-package/v1`。签名算法是 Ed25519（RFC 8032），签名对象是“去掉 `signature` 字段后的整个包”的 canonical JSON。包中包含：

- 站点 ID、起止序号、前序哈希。
- 事件集合和每个事件的 SHA-256 哈希。
- 包创建时间。
- 可选的密钥轮换声明。
- `signature.kid`、`signature.alg=Ed25519`、`signature.sig`。

创建本地站点时，SQLite 中保存测试用的 32 字节 Ed25519 seed；远程站点只注册公钥。导出包只包含公钥和签名，不包含私钥或 seed。不要把测试数据库中的 seed 用于生产；生产部署应将私钥保存在站点侧的受控密钥存储中，中心只保留公钥。

## 密钥轮换

密钥轮换是站点侧操作：

1. 调用 `POST /api/sites/{site_id}/rotate-key` 生成新的 pending keypair。
2. 下一次导出时，包仍由旧私钥签名，但携带 `key` 声明：新 `kid`、新公钥、`effective_after_seq=包尾序号`。
3. 中心验证旧签名后，在同一事务中写入该包事件、推进链头、登记新公钥、退休旧 key，并把站点当前 key 指到新 `kid`。
4. 后续包必须由新私钥签名。

如果轮换时没有新事件，也允许导出一个 `start_seq=end_seq=当前链尾 seq` 的 key-only 包。密钥轮换声明和事件在同一个事务内生效，避免“事件已接受但公钥未切换”的半完成状态。

## 导入、隔离与补齐

中心只接受满足以下条件的整包：

- 包格式和 JSON 结构正确。
- 签名由该站点当前可信公钥验证通过。
- 序号紧接中心链头，或前序缺段包已在 quarantine 中等待。
- `prev_hash` 等于中心链头。
- 事件哈希、序号、站点 ID、时间字段和引用关系全部有效。
- 相同事件 ID 的内容哈希必须相同；不同内容即“同 ID 分叉”。

以下情况进入 quarantine：缺段、`prev_hash` 分叉、事件哈希不符、签名失败、未知站点、事件 ID 相同但内容不同、包内引用不存在等。quarantine 保存原始包和原因；主链不变。

后段先到时先隔离；前段到达并通过校验后，中心在同一个提交事务内写入前段，然后按“最小起点且紧接链头”的顺序自动释放连续后段。并发导入相邻包时使用进程内写锁和 SQLite `BEGIN IMMEDIATE`，提交顺序不同也不会留下链缺口。重复导入相同包返回同一批次和同一 accepted 结果；重试幂等，不会额外追加 reconciliation。

## 并行事实与裁决

两个合法站点可对同一样本报告不同状态。在没有裁决前，派生状态为：

```json
{"status": "parallel_facts", "candidates": [ ... ], "resolution": null}
```

系统不会静默选择其中一条。必须追加 `reconciliation`：

```json
{
  "type": "reconciliation",
  "payload": {
    "selected_event_ids": ["ALPHA-e2"],
    "rejected_event_ids": ["BETA-e2"],
    "reason": "Alpha 具备完整温控记录"
  }
}
```

两条事实仍保留在事件表和来源链中；裁决之后的派生状态采用 selected 分支，并返回裁决事件、理由、记录时间和生效时间。

## JSON API

- `GET /api/health`：健康检查。
- `POST /api/sites`：新建本地测试站点，返回 seed，仅用于离线测试。
- `POST /api/sites` with `{"remote":true,...}`：在中心注册远程站点公钥。
- `GET /api/sites` / `GET /api/sites/{site_id}`：站点、链头、key 和事件。
- `POST /api/events`：在本地站点追加事件。
- `POST /api/sites/{site_id}/rotate-key`：本地站点轮换密钥。
- `POST /api/sites/{site_id}/exports`：导出下一个签名包，可选 `max_events`。
- `GET /api/exports/{id}`：读取已保存的签名包。
- `POST /api/imports`：导入包。
- `GET /api/imports`：导入批次。
- `GET /api/quarantine`：隔离、忽略和已释放记录。
- `POST /api/quarantine/{id}/retry`：幂等重试。
- `POST /api/quarantine/{id}/ignore`：标记忽略。
- `GET /api/samples`：样本列表和派生状态。
- `GET /api/samples/{sample_id}?at=...&basis=effective|recorded`：完整来源链和时间点派生状态。

## 离线与测试

运行时只用 Python 标准库；测试额外使用 pytest。测试套件不访问网络，覆盖重复包、乱序到达、缺段补齐、哈希不符、分叉、事件 ID 冲突、并行事实、纠错、密钥轮换、并发相邻包和时间点归约。

```bash
.venv/bin/pytest -q
```
