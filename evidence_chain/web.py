from __future__ import annotations

import html
import json
from urllib.parse import urlencode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .store import EvidenceError, Store


def _pretty(value: object) -> str:
    return html.escape(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


class EvidenceHandler(BaseHTTPRequestHandler):
    server_version = "EvidenceChain/0.1"

    def _send_json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        return

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise EvidenceError("invalid_json", "请求体不是合法 JSON") from exc
        if not isinstance(value, dict):
            raise EvidenceError("invalid_json", "请求 JSON 必须是对象")
        return value

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self.render_page()
            elif parsed.path == "/api/health":
                self._send_json({"ok": True})
            elif parsed.path == "/api/sites":
                self._send_json({"sites": self.store.list_sites()})
            elif parsed.path == "/api/events":
                query = parse_qs(parsed.query)
                self._send_json(
                    {
                        "events": self.store.list_events(
                            sample_id=query.get("sample_id", [None])[0]
                        )
                    }
                )
            elif parsed.path == "/api/quarantine":
                self._send_json({"packages": self.store.list_packages(True)})
            elif parsed.path == "/api/packages":
                self._send_json({"packages": self.store.list_packages(False)})
            else:
                parts = [part for part in parsed.path.split("/") if part]
                if len(parts) == 4 and parts[:2] == ["api", "samples"]:
                    sample_id = parts[2]
                    if parts[3] == "provenance":
                        self._send_json(self.store.provenance(sample_id))
                        return
                    if parts[3] == "state":
                        query = parse_qs(parsed.query)
                        as_of = query.get("as_of", [None])[0]
                        self._send_json(self.store.derive_state(sample_id, as_of))
                        return
                self._send_json({"error": "not_found"}, 404)
        except EvidenceError as exc:
            self._send_json({"error": exc.code, "message": str(exc)}, exc.status)
        except Exception as exc:
            self._send_json({"error": "internal_error", "message": str(exc)}, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            path = parsed.path
            if self.headers.get("Content-Type", "").startswith(
                "application/x-www-form-urlencoded"
            ):
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode("utf-8"))
                def form_value(name: str) -> str:
                    return form.get(name, [""])[0]

                if path == "/sites/create":
                    self.store.create_site(
                        form_value("site_id"), form_value("display_name")
                    )
                elif path == "/events/create":
                    self.store.add_event(
                        form_value("site_id"),
                        form_value("sample_id"),
                        form_value("event_type"),
                        json.loads(form_value("payload") or "{}"),
                        form_value("effective_at"),
                        form_value("recorded_at") or None,
                    )
                elif path == "/packages/import":
                    self.store.import_package(json.loads(form_value("package_json")))
                elif path.startswith("/api/samples/") and path.endswith("/correction"):
                    sample_id = path.strip("/").split("/")[2]
                    self.store.add_event(
                        form.get("site_id", [""])[0],
                        sample_id,
                        "correction",
                        {
                            "original_event_id": form_value("original_event_id"),
                            "corrects_type": form_value("corrects_type"),
                            "corrected_payload": json.loads(
                                form_value("corrected_payload") or "{}"
                            ),
                        },
                        form_value("effective_at"),
                    )
                elif path.startswith("/api/sites/") and path.endswith("/rotate-key"):
                    self.store.rotate_key(path.strip("/").split("/")[2])
                elif path.startswith("/quarantine/") and path.endswith("/retry"):
                    package_id = path.strip("/").split("/")[1]
                    self.store.retry_package(package_id)
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            data = self.read_json()
            if path == "/api/sites":
                result = self.store.create_site(
                    data["site_id"], data.get("display_name", "")
                )
            elif path == "/api/sites/register-remote":
                result = self.store.register_remote_site(
                    data["site_id"],
                    data["public_key_b64"],
                    data.get("display_name", ""),
                    int(data.get("valid_from_sequence", 1)),
                )
            elif path == "/api/events":
                result = self.store.add_event(
                    site_id=data["site_id"],
                    sample_id=data["sample_id"],
                    event_type=data["event_type"],
                    payload=data["payload"],
                    effective_at=data["effective_at"],
                    recorded_at=data.get("recorded_at"),
                    event_id=data.get("event_id"),
                )
            elif path == "/api/packages/export":
                result = self.store.export_package(
                    data["site_id"],
                    int(data["start_sequence"]),
                    int(data["end_sequence"]),
                )
            elif path == "/api/packages/import":
                result = self.store.import_package(data.get("package", data))
                self._send_json(result, 200 if result["status"] == "accepted" else 202)
                return
            else:
                parts = [part for part in path.split("/") if part]
                if (
                    len(parts) == 4
                    and parts[0] == "api"
                    and parts[1] == "sites"
                    and parts[3] == "rotate-key"
                ):
                    result = self.store.rotate_key(
                        parts[2],
                        data.get("effective_at"),
                        data.get("recorded_at"),
                        data.get("event_id"),
                    )
                elif (
                    len(parts) == 4
                    and parts[0] == "api"
                    and parts[1] == "samples"
                    and parts[3] == "correction"
                ):
                    payload = {
                        "original_event_id": data["original_event_id"],
                        "corrects_type": data["corrects_type"],
                        "corrected_payload": data["corrected_payload"],
                        "corrected_effective_at": data.get("corrected_effective_at"),
                    }
                    result = self.store.add_event(
                        data["site_id"],
                        parts[2],
                        "correction",
                        payload,
                        data["effective_at"],
                        data.get("recorded_at"),
                    )
                elif (
                    len(parts) == 4
                    and parts[0] == "api"
                    and parts[1] == "samples"
                    and parts[3] == "reconciliation"
                ):
                    payload = {
                        "candidate_event_ids": data["candidate_event_ids"],
                        "adopted_event_id": data["adopted_event_id"],
                        "reason": data.get("reason", "人工采用其中一条并行事实"),
                    }
                    result = self.store.add_event(
                        data["site_id"],
                        parts[2],
                        "reconciliation",
                        payload,
                        data["effective_at"],
                        data.get("recorded_at"),
                    )
                elif len(parts) == 4 and parts[1] == "quarantine" and parts[3] == "retry":
                    result = self.store.retry_package(parts[2])
                else:
                    self._send_json({"error": "not_found"}, 404)
                    return
            self._send_json(result, 201)
        except EvidenceError as exc:
            self._send_json({"error": exc.code, "message": str(exc)}, exc.status)
        except json.JSONDecodeError as exc:
            self._send_json({"error": "invalid_json", "message": str(exc)}, 400)
        except KeyError as exc:
            self._send_json({"error": "missing_field", "message": f"缺少 {exc}"}, 400)
        except Exception as exc:
            self._send_json({"error": "internal_error", "message": str(exc)}, 500)

    def render_page(self) -> None:
        sites = self.store.list_sites()
        packages = self.store.list_packages(False)
        query = parse_qs(urlparse(self.path).query)
        quarantined = [item for item in packages if item["status"] == "quarantined"]
        sample_id = query.get("sample_id", ["X-001"])[0]
        provenance = self.store.provenance(sample_id)
        state = provenance["derived_state"]
        page = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>实验样本证据链</title>
<style>
body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:2rem;background:#f7f7f4;color:#20231f}}
h1{{margin:.2rem 0 1rem}} .grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
section{{background:white;border:1px solid #ddd;border-radius:10px;padding:1rem;box-shadow:0 1px 2px #0001}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}td,th{{border-bottom:1px solid #eee;padding:.45rem;text-align:left;vertical-align:top}}
code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}} pre{{white-space:pre-wrap;overflow:auto;background:#20231f;color:#eef;padding:.75rem;border-radius:8px}}
.ok{{color:#166534;font-weight:700}} .bad{{color:#991b1b;font-weight:700}} .muted{{color:#666}}
</style></head><body>
<h1>实验样本证据链</h1>
<p class="muted">排序：站点链按 site_id, sequence；有效时间线按 effective_at, site_id, sequence, event_id；记录时间线按 recorded_at, site_id, sequence, event_id。</p>
<form method="get" action="/"><input name="sample_id" value="{html.escape(sample_id)}"><button>查看样本</button> <a href="/api/samples/{html.escape(sample_id)}/provenance">来源链 JSON</a> · <a href="/api/samples/{html.escape(sample_id)}/state">派生状态 JSON</a></form>
<div class="grid">
<section><h2>站点</h2><table><tr><th>站点</th><th>类型</th><th>公钥指纹</th></tr>
{''.join(f'<tr><td>{html.escape(s["site_id"])}</td><td>{"本地" if s["is_local"] else "远端登记"}</td><td><code>{html.escape(s["public_keys"][-1]["fingerprint"][:16] if s["public_keys"] else "")}</code></td></tr>' for s in sites)}
</table></section>
<section><h2>包状态</h2><table><tr><th>站点</th><th>范围</th><th>状态/原因</th></tr>
{''.join(f'<tr><td>{html.escape(p["site_id"])}</td><td>{p["start_sequence"]}–{p["end_sequence"]}</td><td><span class="{"ok" if p["status"]=="accepted" else "bad"}">{p["status"]}</span> {html.escape(p["reason"] or "")}</td></tr>' for p in packages)}
</table><p>预置隔离后补齐示例：缺段包先进入 quarantine，缺口到达后按严格序号自动释放；篡改包仍保留在隔离区。</p></section>
</div>
<section style="margin-top:1rem"><h2>样本 {sample_id} 的完整来源链</h2>
<p>当前派生阶段：<strong>{html.escape(state["current_stage"] or "无")}</strong>；冲突：{state["has_conflict"]}。所有事件均不可变，correction 和 reconciliation 只追加事实。</p>
<table><tr><th>链序</th><th>事件</th><th>effective_at</th><th>recorded_at</th><th>载荷</th></tr>
{''.join(f'<tr><td>{html.escape(e["site_id"])}#{e["sequence"]}</td><td>{html.escape(e["event_type"])}<br><code>{html.escape(e["event_id"][:18])}</code></td><td>{html.escape(e["effective_at"])}</td><td>{html.escape(e["recorded_at"])}</td><td><pre>{_pretty(e["payload"])}</pre></td></tr>' for e in provenance["events_chain_order"])}
</table></section>
<div class="grid" style="margin-top:1rem">
<section><h2>新建站点</h2>
<form method="post" action="/sites/create">
<p><input name="site_id" placeholder="站点 ID，例如 S3" required></p>
<p><input name="display_name" placeholder="显示名称"></p>
<button>新建站点并生成测试密钥</button>
</form></section>
<section><h2>录入事件</h2>
<form method="post" action="/events/create">
<p><input name="site_id" placeholder="本地站点 ID" required> <input name="sample_id" placeholder="样本 ID" required></p>
<p><select name="event_type"><option>sample_collected</option><option>sample_processed</option><option>sample_aliquoted</option><option>sample_destroyed</option></select></p>
<p><textarea name="payload" rows="4" cols="50">{{"sample_type":"全血","location":"冷柜 A1","collector":"甲"}}</textarea></p>
<p><input name="effective_at" placeholder="effective_at" required> <input name="recorded_at" placeholder="recorded_at（可晚）"></p>
<button>追加不可变事件</button>
</form></section>
<section><h2>纠错 / 仲裁 / 轮换</h2>
<form method="post" action="/api/samples/PLACEHOLDER/correction" onsubmit="this.action=this.action.replace('PLACEHOLDER',this.elements.correction_sample.value);return true">
<p><input name="correction_sample" placeholder="样本 ID" required> <input name="site_id" placeholder="执行站点" required></p>
<p><input name="original_event_id" placeholder="原事件 ID" required> <input name="corrects_type" placeholder="原类型" value="sample_collected"></p>
<p><textarea name="corrected_payload" rows="3" cols="42" placeholder='{{"sample_type":"全血","location":"新位置","collector":"甲"}}'></textarea></p>
<p><input name="effective_at" placeholder="correction effective_at" required></p><button>追加 correction</button>
</form>
<form method="post" action="/api/sites/PLACEHOLDER/rotate-key" onsubmit="this.action=this.action.replace('PLACEHOLDER',this.elements.rotate_site.value)">
<hr><p><input name="rotate_site" placeholder="要轮换密钥的本地站点 ID"></p><button>追加 key_rotated 并生成新密钥</button></form>
<p class="muted">并行事实仲裁请向 <code>/api/samples/&lt;sample_id&gt;/reconciliation</code> POST JSON，字段为 site_id、candidate_event_ids、adopted_event_id、effective_at。</p>
</section>
</div>
<section style="margin-top:1rem"><h2>导入签名包 / 隔离重试</h2>
<form method="post" action="/packages/import">
<textarea name="package_json" rows="8" style="width:100%" placeholder="粘贴导出的 JSON 包"></textarea><br>
<button>导入包</button>
</form>
{''.join(f'<form method="post" action="/quarantine/{html.escape(p["package_id"])}/retry"><button>重试隔离包 {html.escape(p["site_id"])} {p["start_sequence"]}–{p["end_sequence"]}（{html.escape(p["reason"] or "")}）</button></form>' for p in quarantined)}
</section>
<section style="margin-top:1rem"><h2>JSON 示例</h2><pre>{_pretty({"state": state, "quarantine": quarantined})}</pre></section>
</body></html>"""
        self._send_html(page)


def create_app(host: str, port: int, database: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), EvidenceHandler)
    server.store = Store(database)  # type: ignore[attr-defined]
    return server
