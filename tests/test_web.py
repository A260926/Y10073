from __future__ import annotations

import json

from evidence_chain.web import App
from evidence_chain.storage import Store


class DummyStart:
    def __init__(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


def request(app, path: str, method: str = "GET", payload=None):
    data = b"" if payload is None else json.dumps(payload).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(data)),
        "wsgi.input": _Reader(data),
    }
    started = DummyStart()
    body = b"".join(app(environ, started))
    return started.status, started.headers, json.loads(body.decode()) if body else None


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, length: int) -> bytes:
        return self.data[:length]


def test_page_and_demo_api_are_available():
    store = Store(":memory:")
    app = App(store=store, demo=True)
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "QUERY_STRING": "",
        "CONTENT_LENGTH": "0",
        "wsgi.input": _Reader(b""),
    }
    started = DummyStart()
    html = b"".join(app(environ, started)).decode()
    assert started.status == "200 OK"
    assert "实验样本证据链" in html
    assert "预置示例" in html
    status, _, quarantine = request(app, "/api/quarantine")
    assert status == "200 OK"
    assert any(row["site_id"] == "GAMMA" and row["status"] == "accepted" for row in quarantine)
