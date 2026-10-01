from __future__ import annotations

import json
import re
from typing import Any

from .demo import seed_demo
from .storage import EvidenceError, NotFound, Store


class App:
    def __init__(self, store: Store | None = None, db_path: str = "instance/evidence.db", *, demo: bool = False):
        self.store = store or Store(db_path)
        self.demo = demo
        if demo:
            seed_demo(self.store)

    def __call__(self, environ: dict[str, Any], start_response):
        if environ["REQUEST_METHOD"] == "OPTIONS":
            return self._json(start_response, 204, {})
        try:
            return self._route(environ, start_response)
        except EvidenceError as exc:
            return self._json(start_response, exc.status, {"error": str(exc)})
        except Exception as exc:
            return self._json(start_response, 500, {"error": f"internal error: {exc}"})

    def _route(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ["REQUEST_METHOD"]
        if path == "/" and method == "GET":
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [PAGE.encode("utf-8")]
        if path == "/api/health" and method == "GET":
            return self._json(start_response, 200, {"ok": True, "name": "evidence-chain"})

        match = re.fullmatch(r"/api/sites(?:/([^/]+))?", path)
        if match:
            site_id = match.group(1)
            if method == "GET":
                return self._json(start_response, 200, self.store.get_site(site_id) if site_id else self.store.list_sites())
            if method == "POST" and site_id is None:
                body = self._body(environ)
                remote = bool(body.pop("remote", False))
                if remote:
                    result = self.store.register_remote_site(
                        body["site_id"], body["name"], body["kid"], body["public_key"]
                    )
                else:
                    result = self.store.create_site(body["site_id"], body["name"])
                return self._json(start_response, 201, result)

        if path == "/api/events" and method == "GET":
            return self._json(start_response, 200, self.store.list_events())
        if path == "/api/events" and method == "POST":
            return self._json(start_response, 201, self.store.record_event(self._body(environ)))

        if path == "/api/samples" and method == "GET":
            return self._json(start_response, 200, self.store.list_samples())
        sample = re.fullmatch(r"/api/samples/([^/]+)", path)
        if sample and method == "GET":
            query = self._query(environ)
            return self._json(start_response, 200, self.store.get_sample(
                sample.group(1), at=query.get("at"), basis=query.get("basis", "effective")
            ))

        if path == "/api/imports" and method == "GET":
            return self._json(start_response, 200, self.store.list_imports())
        if path == "/api/imports" and method == "POST":
            return self._json(start_response, 200, self.store.import_package(self._body(environ)))

        if path == "/api/quarantine" and method == "GET":
            return self._json(start_response, 200, self.store.list_quarantine())
        qretry = re.fullmatch(r"/api/quarantine/(\d+)/retry", path)
        if qretry and method == "POST":
            return self._json(start_response, 200, self.store.retry_quarantine(int(qretry.group(1))))
        qignore = re.fullmatch(r"/api/quarantine/(\d+)/ignore", path)
        if qignore and method == "POST":
            return self._json(start_response, 200, self.store.ignore_quarantine(int(qignore.group(1))))

        if path == "/api/exports" and method == "GET":
            return self._json(start_response, 200, self.store.list_exports())
        export = re.fullmatch(r"/api/sites/([^/]+)/exports", path)
        if export and method == "POST":
            body = self._body(environ)
            max_events = body.get("max_events")
            return self._json(start_response, 201, self.store.export_next_package(
                export.group(1), max_events=max_events
            ))
        export_get = re.fullmatch(r"/api/exports/(\d+)", path)
        if export_get and method == "GET":
            return self._json(start_response, 200, self.store.get_export(int(export_get.group(1))))

        rotate = re.fullmatch(r"/api/sites/([^/]+)/rotate-key", path)
        if rotate and method == "POST":
            return self._json(start_response, 201, self.store.rotate_key(rotate.group(1)))

        raise NotFound("route not found")

    @staticmethod
    def _body(environ) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            raw = environ["wsgi.input"].read(length).decode("utf-8")
            return json.loads(raw or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise EvidenceError("JSON request body must be an object")
        return data

    @staticmethod
    def _query(environ) -> dict[str, str]:
        from urllib.parse import parse_qs

        parsed = parse_qs(environ.get("QUERY_STRING", ""))
        return {key: values[-1] for key, values in parsed.items() if values}

    @staticmethod
    def _json(start_response, status: int, payload: Any):
        status_text = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 404: "Not Found", 409: "Conflict", 500: "Internal Server Error"}[status]
        data = b"" if status == 204 else json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        start_response(f"{status} {status_text}", [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(data))),
        ])
        return [data]


from .static_page import PAGE  # noqa: E402
