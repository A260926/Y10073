from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from . import crypto
from .serialization import (
    canonical_hash,
    canonical_json,
    event_hash,
    key_fingerprint,
    now_iso,
    package_fingerprint,
    package_unsigned,
    parse_timestamp,
)

GENESIS = "GENESIS"
PACKAGE_FORMAT = "evidence-chain-package/v1"
ALGORITHM = "Ed25519-RFC8032"
SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

SAMPLE_EVENT_TYPES = {
    "sample_collected",
    "sample_processed",
    "sample_aliquoted",
    "sample_destroyed",
}
EVENT_TYPES = SAMPLE_EVENT_TYPES | {
    "correction",
    "reconciliation",
    "key_rotated",
}
BUSINESS_KEYS = {
    "sample_collected": ["sample_type", "location", "collector"],
    "sample_processed": ["process", "operator", "location"],
    "sample_aliquoted": ["aliquot_id", "container", "volume", "unit"],
    "sample_destroyed": ["method", "operator", "location"],
}
STAGE_RANK = {
    "sample_collected": 1,
    "sample_processed": 2,
    "sample_aliquoted": 3,
    "sample_destroyed": 4,
}


class EvidenceError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class Store:
    def __init__(self, path: str | Path = "evidence.db", timeout: float = 5.0):
        self.path = str(path)
        self.timeout = timeout
        self.gate_wait_seconds = 2.0
        self._import_turns: dict[str, int] = {}
        self._import_condition = threading.Condition()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _wait_for_import_gate(self, site_id: str, sequence: int) -> bool:
        deadline = time.monotonic() + self.gate_wait_seconds
        with self._import_condition:
            while True:
                turn = self._import_turns.setdefault(site_id, 1)
                if sequence == turn:
                    return True
                if sequence < turn:
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._import_condition.wait(remaining)

    def _complete_import_gate(self, site_id: str, sequence: int) -> None:
        with self._import_condition:
            if self._import_turns.get(site_id, 1) == sequence:
                self._import_turns[site_id] = sequence + 1
                self._import_condition.notify_all()

    @contextmanager
    def connect(self, transaction: bool = False):
        conn = sqlite3.connect(self.path, timeout=self.timeout)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            if transaction:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if transaction:
                conn.commit()
        except Exception:
            if transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect(True) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sites (
                  site_id TEXT PRIMARY KEY,
                  display_name TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  is_local INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS site_public_keys (
                  site_id TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  public_key_b64 TEXT NOT NULL,
                  valid_from_sequence INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY (site_id, fingerprint),
                  FOREIGN KEY(site_id) REFERENCES sites(site_id)
                );
                CREATE TABLE IF NOT EXISTS site_private_keys (
                  site_id TEXT NOT NULL,
                  fingerprint TEXT NOT NULL,
                  private_seed_b64 TEXT NOT NULL,
                  valid_from_sequence INTEGER NOT NULL,
                  rotated_at TEXT,
                  PRIMARY KEY (site_id, fingerprint),
                  FOREIGN KEY(site_id) REFERENCES sites(site_id)
                );
                CREATE TABLE IF NOT EXISTS events (
                  event_id TEXT PRIMARY KEY,
                  site_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL,
                  sample_id TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  recorded_at TEXT NOT NULL,
                  effective_at TEXT NOT NULL,
                  prev_hash TEXT NOT NULL,
                  event_hash TEXT NOT NULL UNIQUE,
                  UNIQUE(site_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS events_sample_idx ON events(sample_id);
                CREATE INDEX IF NOT EXISTS events_site_seq_idx ON events(site_id, sequence);
                CREATE TABLE IF NOT EXISTS packages (
                  package_id TEXT PRIMARY KEY,
                  fingerprint TEXT NOT NULL UNIQUE,
                  site_id TEXT NOT NULL,
                  start_sequence INTEGER NOT NULL,
                  end_sequence INTEGER NOT NULL,
                  status TEXT NOT NULL,
                  reason TEXT,
                  envelope_json TEXT NOT NULL,
                  result_json TEXT,
                  imported_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS package_events (
                  package_id TEXT NOT NULL,
                  event_id TEXT NOT NULL,
                  site_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL,
                  event_hash TEXT NOT NULL,
                  envelope_json TEXT NOT NULL,
                  accepted INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY(package_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS package_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  package_id TEXT NOT NULL,
                  status TEXT NOT NULL,
                  reason TEXT,
                  created_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _validate_identifier(name: str, value: object) -> str:
        if not isinstance(value, str) or not SITE_ID_RE.match(value):
            raise EvidenceError("invalid_identifier", f"{name} 格式无效")
        return value

    @staticmethod
    def _validate_sequence(value: object, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise EvidenceError("invalid_range", f"{name} 必须是整数")
        return value

    @staticmethod
    def _json_dumps(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def create_site(
        self, site_id: str, display_name: str = "", event_id: str | None = None
    ) -> dict:
        self._validate_identifier("site_id", site_id)
        if not display_name:
            display_name = site_id
        timestamp = now_iso()
        seed = crypto.generate_seed()
        public = crypto.public_key_from_seed(seed)
        fingerprint = key_fingerprint(public)
        with self.connect(True) as conn:
            try:
                conn.execute(
                    "INSERT INTO sites(site_id, display_name, created_at, is_local) VALUES (?,?,?,1)",
                    (site_id, display_name, timestamp),
                )
                conn.execute(
                    "INSERT INTO site_public_keys VALUES (?,?,?,?,?)",
                    (site_id, fingerprint, crypto.b64encode(public).decode(), 1, timestamp),
                )
                conn.execute(
                    "INSERT INTO site_private_keys(site_id, fingerprint, private_seed_b64, valid_from_sequence) VALUES (?,?,?,?)",
                    (site_id, fingerprint, crypto.b64encode(seed).decode(), 1),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceError("site_exists", "站点已存在", 409) from exc
        return self.get_site(site_id)

    def register_remote_site(
        self,
        site_id: str,
        public_key_b64: str,
        display_name: str = "",
        valid_from_sequence: int = 1,
    ) -> dict:
        self._validate_identifier("site_id", site_id)
        if valid_from_sequence != 1:
            raise EvidenceError("invalid_key", "登记远端站点初始公钥必须从序号 1 开始")
        try:
            public = crypto.b64decode(public_key_b64.encode())
        except Exception as exc:
            raise EvidenceError("invalid_key", "公钥不是合法 Base64") from exc
        if len(public) != 32:
            raise EvidenceError("invalid_key", "Ed25519 公钥必须为 32 字节")
        fingerprint = key_fingerprint(public)
        timestamp = now_iso()
        with self.connect(True) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sites(site_id, display_name, created_at, is_local) VALUES (?,?,?,0)",
                (site_id, display_name or site_id, timestamp),
            )
            try:
                conn.execute(
                    "INSERT INTO site_public_keys VALUES (?,?,?,?,?)",
                    (site_id, fingerprint, public_key_b64, 1, timestamp),
                )
            except sqlite3.IntegrityError:
                pass
        return self.get_site(site_id)

    def get_site(self, site_id: str) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if row is None:
                raise EvidenceError("unknown_site", "未知站点", 404)
            keys = conn.execute(
                "SELECT fingerprint, public_key_b64, valid_from_sequence FROM site_public_keys WHERE site_id=? ORDER BY valid_from_sequence",
                (site_id,),
            ).fetchall()
        return {
            "site_id": row["site_id"],
            "display_name": row["display_name"],
            "created_at": row["created_at"],
            "is_local": bool(row["is_local"]),
            "public_keys": [dict(key) for key in keys],
        }

    def list_sites(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT site_id FROM sites ORDER BY site_id").fetchall()
        return [self.get_site(row["site_id"]) for row in rows]

    @staticmethod
    def _validate_event_payload(event_type: str, payload: object) -> dict:
        if not isinstance(payload, dict):
            raise EvidenceError("invalid_payload", "payload 必须是对象")
        if event_type in SAMPLE_EVENT_TYPES:
            required = BUSINESS_KEYS[event_type]
            for key in required:
                if key not in payload or payload[key] in (None, ""):
                    raise EvidenceError("invalid_payload", f"{event_type} 缺少 {key}")
            for key, value in payload.items():
                if not isinstance(key, str):
                    raise EvidenceError("invalid_payload", "payload 键必须是字符串")
                if not isinstance(value, (str, int, float, bool)) and value is not None:
                    raise EvidenceError("invalid_payload", f"字段 {key} 类型不受支持")
                if isinstance(value, float) and not math.isfinite(value):
                    raise EvidenceError("invalid_payload", f"字段 {key} 不能是 NaN 或无穷值")
        elif event_type == "correction":
            corrected_type = payload.get("corrects_type")
            if corrected_type not in SAMPLE_EVENT_TYPES:
                raise EvidenceError("invalid_payload", "corrects_type 必须是业务事件类型")
            if not isinstance(payload.get("original_event_id"), str):
                raise EvidenceError("invalid_payload", "original_event_id 必须是字符串")
            if not isinstance(payload.get("corrected_payload"), dict):
                raise EvidenceError("invalid_payload", "corrected_payload 必须是对象")
            corrected_effective_at = payload.get("corrected_effective_at")
            if corrected_effective_at is not None:
                parse_timestamp(corrected_effective_at)
            Store._validate_event_payload(
                corrected_type, payload["corrected_payload"]
            )
        elif event_type == "reconciliation":
            candidates = payload.get("candidate_event_ids")
            adopted = payload.get("adopted_event_id")
            if not isinstance(candidates, list) or len(candidates) < 2:
                raise EvidenceError("invalid_payload", "reconciliation 至少需要两个候选事件")
            if not all(isinstance(item, str) for item in candidates):
                raise EvidenceError("invalid_payload", "候选事件 ID 必须是字符串")
            if adopted not in candidates:
                raise EvidenceError("invalid_payload", "adopted_event_id 必须在候选集合中")
            if len(set(candidates)) != len(candidates):
                raise EvidenceError("invalid_payload", "候选事件不能重复")
        elif event_type == "key_rotated":
            for key in ("new_public_key_b64", "new_key_fingerprint", "algorithm"):
                if not isinstance(payload.get(key), str) or not payload[key]:
                    raise EvidenceError("invalid_payload", f"密钥轮换缺少 {key}")
            if payload["algorithm"] != ALGORITHM:
                raise EvidenceError("invalid_payload", "不支持的签名算法")
            try:
                if len(crypto.b64decode(payload["new_public_key_b64"])) != 32:
                    raise EvidenceError("invalid_key", "轮换公钥必须是 32 字节 Ed25519 公钥")
            except EvidenceError:
                raise
            except Exception as exc:
                raise EvidenceError("invalid_key", "轮换公钥不是合法 Base64") from exc
        return dict(payload)

    @staticmethod
    def _validate_corrected_effective_time(
        payload: dict, recorded_at: str
    ) -> None:
        corrected_effective_at = payload.get("corrected_effective_at")
        if (
            corrected_effective_at is not None
            and parse_timestamp(corrected_effective_at) > parse_timestamp(recorded_at)
        ):
            raise EvidenceError(
                "invalid_timestamp",
                "corrected_effective_at 不能晚于 correction 的 recorded_at",
            )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> dict:
        return {
            "event_id": row["event_id"],
            "site_id": row["site_id"],
            "sequence": row["sequence"],
            "sample_id": row["sample_id"],
            "event_type": row["event_type"],
            "payload": json.loads(row["payload_json"]),
            "recorded_at": row["recorded_at"],
            "effective_at": row["effective_at"],
            "prev_hash": row["prev_hash"],
            "event_hash": row["event_hash"],
        }

    def list_events(
        self,
        sample_id: str | None = None,
        site_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if sample_id is not None:
            clauses.append("sample_id=?")
            params.append(sample_id)
        if site_id is not None:
            clauses.append("site_id=?")
            params.append(site_id)
        if start is not None:
            clauses.append("sequence>=?")
            params.append(start)
        if end is not None:
            clauses.append("sequence<=?")
            params.append(end)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = (
            "SELECT * FROM events" + where + " ORDER BY site_id, sequence, event_id"
        )
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._event_from_row(row) for row in rows]

    def get_event(self, event_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
        return self._event_from_row(row) if row else None

    def _current_sequence(self, conn: sqlite3.Connection, site_id: str) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(sequence),0) AS seq FROM events WHERE site_id=?",
            (site_id,),
        ).fetchone()
        return int(row["seq"])

    def _current_hash(self, conn: sqlite3.Connection, site_id: str) -> str:
        row = conn.execute(
            "SELECT event_hash FROM events WHERE site_id=? ORDER BY sequence DESC LIMIT 1",
            (site_id,),
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def _ensure_local_site(self, conn: sqlite3.Connection, site_id: str) -> None:
        row = conn.execute(
            "SELECT is_local FROM sites WHERE site_id=?", (site_id,)
        ).fetchone()
        if row is None:
            raise EvidenceError("unknown_site", "未知站点", 404)
        if not row["is_local"]:
            raise EvidenceError("remote_site", "该站点在本库中是只读远端站点", 403)

    def _active_private_key(
        self, conn: sqlite3.Connection, site_id: str, sequence: int
    ) -> tuple[bytes, str]:
        row = conn.execute(
            """
            SELECT private_seed_b64, fingerprint FROM site_private_keys
            WHERE site_id=? AND valid_from_sequence<=?
            ORDER BY valid_from_sequence DESC LIMIT 1
            """,
            (site_id, sequence),
        ).fetchone()
        if row is None:
            raise EvidenceError("missing_key", "缺少站点签名私钥")
        return crypto.b64decode(row["private_seed_b64"]), row["fingerprint"]

    def _previous_private_key(
        self, conn: sqlite3.Connection, site_id: str, rotation_sequence: int
    ) -> tuple[bytes, str]:
        if rotation_sequence <= 1:
            row = conn.execute(
                """
                SELECT private_seed_b64, fingerprint FROM site_private_keys
                WHERE site_id=? ORDER BY valid_from_sequence LIMIT 1
                """,
                (site_id,),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT private_seed_b64, fingerprint FROM site_private_keys
                WHERE site_id=? AND valid_from_sequence<?
                ORDER BY valid_from_sequence DESC LIMIT 1
                """,
                (site_id, rotation_sequence),
            ).fetchone()
        if row is None:
            raise EvidenceError("missing_key", "缺少轮换前签名私钥")
        return crypto.b64decode(row["private_seed_b64"]), row["fingerprint"]

    def _validate_references(
        self, conn: sqlite3.Connection, event: dict, all_events: list[dict] | None
    ) -> None:
        event_type = event["event_type"]
        payload = event["payload"]
        if event_type not in {"correction", "reconciliation"}:
            return
        candidates = all_events if all_events is not None else self.list_events()
        by_id = {item["event_id"]: item for item in candidates}

        if event_type == "correction":
            target = by_id.get(payload["original_event_id"])
            if target is None:
                raise EvidenceError(
                    "invalid_reference", "correction 引用的原事件不存在"
                )
            if target["sample_id"] != event["sample_id"]:
                raise EvidenceError("invalid_reference", "correction 必须引用同一样本")
            if target["event_type"] not in SAMPLE_EVENT_TYPES:
                raise EvidenceError("invalid_reference", "不能纠错 reconciliation 或密钥事件")
            if target["event_type"] != payload["corrects_type"]:
                raise EvidenceError("invalid_reference", "纠错类型与原事件业务类型不一致")
            if target["site_id"] == event["site_id"] and target["sequence"] >= event["sequence"]:
                raise EvidenceError("invalid_reference", "同站点 correction 不能引用未来事件")
            return

        for candidate_id in payload["candidate_event_ids"]:
            candidate = by_id.get(candidate_id)
            if candidate is None:
                raise EvidenceError("invalid_reference", "reconciliation 候选事件不存在")
            if candidate["sample_id"] != event["sample_id"]:
                raise EvidenceError("invalid_reference", "候选事件必须属于同一样本")
            if candidate["event_type"] not in SAMPLE_EVENT_TYPES and candidate["event_type"] != "correction":
                raise EvidenceError("invalid_reference", "候选必须是业务事实或其纠错")
            if candidate["site_id"] == event["site_id"] and candidate["sequence"] >= event["sequence"]:
                raise EvidenceError("invalid_reference", "同站点 reconciliation 不能引用未来事件")

    def add_event(
        self,
        site_id: str,
        sample_id: str,
        event_type: str,
        payload: dict,
        effective_at: str,
        recorded_at: str | None = None,
        event_id: str | None = None,
    ) -> dict:
        self._validate_identifier("site_id", site_id)
        self._validate_identifier("sample_id", sample_id)
        if event_type not in EVENT_TYPES:
            raise EvidenceError("invalid_event_type", "未知事件类型")
        if event_type == "key_rotated":
            raise EvidenceError("invalid_event_type", "密钥轮换必须使用专门接口")
        payload = self._validate_event_payload(event_type, payload)
        try:
            effective_dt = parse_timestamp(effective_at)
            recorded_dt = parse_timestamp(recorded_at or now_iso())
        except ValueError as exc:
            raise EvidenceError("invalid_timestamp", str(exc)) from exc
        if recorded_dt < effective_dt:
            raise EvidenceError("invalid_timestamp", "recorded_at 不能早于 effective_at")
        if event_type == "correction":
            self._validate_corrected_effective_time(payload, recorded_at or now_iso())
        event_id = event_id or f"evt_{uuid.uuid4().hex}"

        with self.connect(True) as conn:
            self._ensure_local_site(conn, site_id)
            sequence = self._current_sequence(conn, site_id) + 1
            event = {
                "event_id": event_id,
                "site_id": site_id,
                "sequence": sequence,
                "sample_id": sample_id,
                "event_type": event_type,
                "payload": payload,
                "recorded_at": recorded_at or now_iso(),
                "effective_at": effective_at,
                "prev_hash": self._current_hash(conn, site_id),
            }
            event["event_hash"] = event_hash(event)
            self._validate_references(conn, event, None)
            self._insert_event(conn, event)
        return self.get_event(event_id)

    @staticmethod
    def _insert_event(conn: sqlite3.Connection, event: dict) -> None:
        conn.execute(
            """
            INSERT INTO events(event_id, site_id, sequence, sample_id, event_type,
                               payload_json, recorded_at, effective_at, prev_hash, event_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event["event_id"],
                event["site_id"],
                event["sequence"],
                event["sample_id"],
                event["event_type"],
                json.dumps(event["payload"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                event["recorded_at"],
                event["effective_at"],
                event["prev_hash"],
                event["event_hash"],
            ),
        )

    def rotate_key(
        self,
        site_id: str,
        effective_at: str | None = None,
        recorded_at: str | None = None,
        event_id: str | None = None,
    ) -> dict:
        self._validate_identifier("site_id", site_id)
        try:
            effective_dt = parse_timestamp(effective_at or now_iso())
            recorded_dt = parse_timestamp(recorded_at or now_iso())
        except ValueError as exc:
            raise EvidenceError("invalid_timestamp", str(exc)) from exc
        if recorded_dt < effective_dt:
            raise EvidenceError("invalid_timestamp", "recorded_at 不能早于 effective_at")
        seed = crypto.generate_seed()
        public = crypto.public_key_from_seed(seed)
        fingerprint = key_fingerprint(public)

        with self.connect(True) as conn:
            self._ensure_local_site(conn, site_id)
            sequence = self._current_sequence(conn, site_id) + 1
            timestamp = recorded_at or now_iso()
            payload = {
                "new_public_key_b64": crypto.b64encode(public).decode(),
                "new_key_fingerprint": fingerprint,
                "algorithm": ALGORITHM,
                "valid_from_sequence": sequence,
            }
            event = {
                "event_id": event_id or f"evt_{uuid.uuid4().hex}",
                "site_id": site_id,
                "sequence": sequence,
                "sample_id": site_id,
                "event_type": "key_rotated",
                "payload": payload,
                "recorded_at": timestamp,
                "effective_at": effective_at or timestamp,
                "prev_hash": self._current_hash(conn, site_id),
            }
            event["event_hash"] = event_hash(event)
            self._insert_event(conn, event)
            conn.execute(
                "UPDATE site_private_keys SET rotated_at=? WHERE site_id=? AND rotated_at IS NULL",
                (timestamp, site_id),
            )
            conn.execute(
                "INSERT INTO site_public_keys VALUES (?,?,?,?,?)",
                (site_id, fingerprint, crypto.b64encode(public).decode(), sequence, timestamp),
            )
            conn.execute(
                "INSERT INTO site_private_keys(site_id, fingerprint, private_seed_b64, valid_from_sequence) VALUES (?,?,?,?)",
                (site_id, fingerprint, crypto.b64encode(seed).decode(), sequence),
            )
        return self.get_event(event["event_id"])

    def export_package(
        self, site_id: str, start_sequence: int, end_sequence: int
    ) -> dict:
        self._validate_identifier("site_id", site_id)
        start_sequence = Store._validate_sequence(start_sequence, "start_sequence")
        end_sequence = Store._validate_sequence(end_sequence, "end_sequence")
        if start_sequence < 1 or end_sequence < start_sequence:
            raise EvidenceError("invalid_range", "导出序号范围无效")
        with self.connect(True) as conn:
            self._ensure_local_site(conn, site_id)
            current = self._current_sequence(conn, site_id)
            if end_sequence > current:
                raise EvidenceError("invalid_range", "结束序号超过当前链尾")
            rows = conn.execute(
                "SELECT * FROM events WHERE site_id=? AND sequence BETWEEN ? AND ? ORDER BY sequence",
                (site_id, start_sequence, end_sequence),
            ).fetchall()
            events = [self._event_from_row(row) for row in rows]
            if len(events) != end_sequence - start_sequence + 1:
                raise EvidenceError("missing_events", "源站点本地链存在缺口")
            if start_sequence == 1:
                start_prev_hash = GENESIS
            else:
                previous = conn.execute(
                    "SELECT event_hash FROM events WHERE site_id=? AND sequence=?",
                    (site_id, start_sequence - 1),
                ).fetchone()
                start_prev_hash = previous["event_hash"]
            signer_sequence = start_sequence
            rotations = [
                event for event in events if event["event_type"] == "key_rotated"
            ]
            if len(rotations) > 1:
                raise EvidenceError("multiple_rotations", "一个导出包不能包含多次轮换")
            if rotations and rotations[0]["sequence"] != end_sequence:
                raise EvidenceError("rotation_not_terminal", "轮换事件必须是包的最后事件")
            if rotations:
                seed, fingerprint = self._previous_private_key(
                    conn, site_id, rotations[0]["sequence"]
                )
            else:
                seed, fingerprint = self._active_private_key(
                    conn, site_id, start_sequence
                )

        envelope = {
            "format": PACKAGE_FORMAT,
            "algorithm": ALGORITHM,
            "signer_key_fingerprint": fingerprint,
            "site_id": site_id,
            "start_sequence": start_sequence,
            "end_sequence": end_sequence,
            "start_prev_hash": start_prev_hash,
            "events": events,
            "created_at": now_iso(),
        }
        signature = crypto.sign(seed, canonical_json(package_unsigned(envelope)))
        envelope["signature"] = crypto.b64encode(signature).decode()
        return envelope

    def _safe_envelope_json(self, envelope: object) -> str:
        try:
            return json.dumps(
                envelope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except Exception:
            return json.dumps({"invalid": True}, separators=(",", ":"))

    def _result_from_package_row(self, row: sqlite3.Row) -> dict:
        result = json.loads(row["result_json"]) if row["result_json"] else None
        if result:
            return result
        return {
            "status": row["status"],
            "reason": row["reason"],
            "package_id": row["package_id"],
            "site_id": row["site_id"],
            "start_sequence": row["start_sequence"],
            "end_sequence": row["end_sequence"],
        }

    def _add_package_log(
        self, conn: sqlite3.Connection, package_id: str, status: str, reason: str | None
    ) -> None:
        conn.execute(
            "INSERT INTO package_logs(package_id,status,reason,created_at) VALUES (?,?,?,?)",
            (package_id, status, reason, now_iso()),
        )

    def _record_static_quarantine(self, envelope: object, exc: EvidenceError) -> dict:
        package_id = f"pkg_{uuid.uuid4().hex}"
        timestamp = now_iso()
        raw = self._safe_envelope_json(envelope)
        parsed = envelope if isinstance(envelope, dict) else {}
        site_id = str(parsed.get("site_id", "UNKNOWN"))
        start = parsed.get("start_sequence")
        end = parsed.get("end_sequence")
        events_for_evidence: list[dict] = []
        if isinstance(envelope, dict) and isinstance(envelope.get("events"), list):
            for raw_event in envelope["events"]:
                if not isinstance(raw_event, dict):
                    continue
                events_for_evidence.append(
                    {
                        "event_id": str(raw_event.get("event_id", "unknown"))[:128],
                        "site_id": site_id[:64],
                        "sequence": raw_event.get("sequence")
                        if isinstance(raw_event.get("sequence"), int)
                        else 0,
                        "event_hash": str(raw_event.get("event_hash", ""))[:128],
                        "raw": raw_event,
                    }
                )
        with self.connect(True) as conn:
            conn.execute(
                """
                INSERT INTO packages(package_id,fingerprint,site_id,start_sequence,end_sequence,
                                     status,reason,envelope_json,imported_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    package_id,
                    canonical_hash(envelope if envelope is not None else {"invalid": True}),
                    site_id[:64],
                    start if isinstance(start, int) else 0,
                    end if isinstance(end, int) else 0,
                    "quarantined",
                    exc.code,
                    raw,
                    timestamp,
                    timestamp,
                ),
            )
            self._add_package_log(conn, package_id, "quarantined", exc.code)
            for item in events_for_evidence:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO package_events(package_id,event_id,site_id,sequence,
                                                   event_hash,envelope_json,accepted)
                    VALUES (?,?,?,?,?,?,0)
                    """,
                    (
                        package_id,
                        item["event_id"],
                        item["site_id"],
                        item["sequence"],
                        item["event_hash"],
                        self._safe_envelope_json(item["raw"]),
                    ),
                )
        return {
            "status": "quarantined",
            "reason": exc.code,
            "message": str(exc),
            "package_id": package_id,
        }

    def validate_envelope_static(self, envelope: object) -> dict:
        if not isinstance(envelope, dict):
            raise EvidenceError("invalid_package", "导入内容必须是 JSON 对象")
        required = {
            "format",
            "algorithm",
            "signer_key_fingerprint",
            "site_id",
            "start_sequence",
            "end_sequence",
            "start_prev_hash",
            "events",
            "created_at",
            "signature",
        }
        missing = required - set(envelope)
        if missing:
            raise EvidenceError("invalid_package", f"导出包缺少字段: {sorted(missing)}")
        if envelope["format"] != PACKAGE_FORMAT:
            raise EvidenceError("invalid_format", "不支持的导出包格式")
        if envelope["algorithm"] != ALGORITHM:
            raise EvidenceError("unsupported_algorithm", "不支持的签名算法")
        if not isinstance(envelope["signer_key_fingerprint"], str):
            raise EvidenceError("invalid_signature", "签名公钥指纹必须是字符串")
        site_id = envelope["site_id"]
        if not isinstance(site_id, str) or not SITE_ID_RE.match(site_id):
            raise EvidenceError("invalid_identifier", "站点标识无效")
        start = envelope["start_sequence"]
        end = envelope["end_sequence"]
        start = self._validate_sequence(start, "start_sequence")
        end = self._validate_sequence(end, "end_sequence")
        if start < 1 or end < start:
            raise EvidenceError("invalid_range", "导出包序号范围无效")
        if not isinstance(envelope["start_prev_hash"], str):
            raise EvidenceError("invalid_hash", "前序哈希必须是字符串")
        if not isinstance(envelope["events"], list):
            raise EvidenceError("invalid_package", "events 必须是数组")
        if len(envelope["events"]) != end - start + 1:
            raise EvidenceError("invalid_range", "事件数量与序号范围不一致")
        parse_timestamp(envelope["created_at"])
        if not isinstance(envelope["signature"], str):
            raise EvidenceError("invalid_signature", "签名必须是 Base64 字符串")

        events = []
        event_fields = {
            "event_id",
            "site_id",
            "sequence",
            "sample_id",
            "event_type",
            "payload",
            "recorded_at",
            "effective_at",
            "prev_hash",
        }
        seen_ids: set[str] = set()
        previous_hash = envelope["start_prev_hash"]
        for offset, event in enumerate(envelope["events"]):
            sequence = start + offset
            if not isinstance(event, dict):
                raise EvidenceError("invalid_event", "事件必须是对象")
            if set(event) != event_fields | {"event_hash"}:
                raise EvidenceError("invalid_event", "事件字段不完整")
            if event["site_id"] != site_id:
                raise EvidenceError("site_mismatch", "事件站点与导出包不一致")
            if not isinstance(event["sequence"], int) or isinstance(event["sequence"], bool):
                raise EvidenceError("sequence_mismatch", "事件序号必须是整数")
            if event["sequence"] != sequence:
                raise EvidenceError("sequence_mismatch", "事件序号不连续或位置错误")
            if not isinstance(event["event_id"], str) or not event["event_id"]:
                raise EvidenceError("invalid_event", "event_id 必须是非空字符串")
            if event["event_id"] in seen_ids:
                raise EvidenceError("duplicate_event_id", "导出包内 event_id 重复")
            seen_ids.add(event["event_id"])
            if not isinstance(event["sample_id"], str) or not event["sample_id"]:
                raise EvidenceError("invalid_event", "sample_id 必须是非空字符串")
            if event["event_type"] not in EVENT_TYPES:
                raise EvidenceError("invalid_event_type", "未知事件类型")
            recorded = parse_timestamp(event["recorded_at"])
            effective = parse_timestamp(event["effective_at"])
            if recorded < effective:
                raise EvidenceError("invalid_timestamp", "recorded_at 不能早于 effective_at")
            if event["event_type"] == "correction":
                self._validate_corrected_effective_time(
                    event["payload"], event["recorded_at"]
                )
            if event["prev_hash"] != previous_hash:
                raise EvidenceError("hash_mismatch", "事件前序哈希不匹配")
            payload = self._validate_event_payload(event["event_type"], event["payload"])
            normalized = {
                "event_id": event["event_id"],
                "site_id": event["site_id"],
                "sequence": event["sequence"],
                "sample_id": event["sample_id"],
                "event_type": event["event_type"],
                "payload": payload,
                "recorded_at": event["recorded_at"],
                "effective_at": event["effective_at"],
                "prev_hash": event["prev_hash"],
            }
            normalized["event_hash"] = event_hash(normalized)
            if event.get("event_hash") != normalized["event_hash"]:
                raise EvidenceError("hash_mismatch", "事件哈希不匹配")
            events.append(normalized)
            previous_hash = normalized["event_hash"]

        rotations = [event for event in events if event["event_type"] == "key_rotated"]
        if len(rotations) > 1:
            raise EvidenceError("multiple_rotations", "一个导出包不能包含多次轮换")
        if rotations and rotations[0]["sequence"] != end:
            raise EvidenceError("rotation_not_terminal", "轮换事件必须是包的最后事件")

        normalized_envelope = {
            "format": envelope["format"],
            "algorithm": envelope["algorithm"],
            "signer_key_fingerprint": envelope["signer_key_fingerprint"],
            "site_id": site_id,
            "start_sequence": start,
            "end_sequence": end,
            "start_prev_hash": envelope["start_prev_hash"],
            "events": events,
            "created_at": envelope["created_at"],
            "signature": envelope["signature"],
        }
        try:
            signature = crypto.b64decode(envelope["signature"].encode())
        except Exception as exc:
            raise EvidenceError("invalid_signature", "签名不是合法 Base64") from exc
        if len(signature) != 64:
            raise EvidenceError("invalid_signature", "Ed25519 签名必须为 64 字节")
        normalized_envelope["_fingerprint"] = package_fingerprint(normalized_envelope)
        normalized_envelope["_signature_bytes"] = signature
        return normalized_envelope

    def _get_public_keys(
        self,
        conn: sqlite3.Connection,
        site_id: str,
        fingerprint: str,
        rotation: dict | None,
    ) -> list[bytes]:
        if rotation is not None:
            payload = rotation["payload"]
            if payload["new_key_fingerprint"] == fingerprint:
                raise EvidenceError("invalid_signature", "轮换包必须由旧密钥签名")
        row = conn.execute(
            """
            SELECT public_key_b64 FROM site_public_keys
            WHERE site_id=? AND fingerprint=?
            ORDER BY valid_from_sequence DESC LIMIT 1
            """,
            (site_id, fingerprint),
        ).fetchone()
        if row is None:
            return []
        return [crypto.b64decode(row["public_key_b64"])]

    def _verify_envelope_signature(
        self, conn: sqlite3.Connection, envelope: dict
    ) -> None:
        site_id = envelope["site_id"]
        site = conn.execute("SELECT site_id FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if site is None:
            raise EvidenceError("unknown_site", "中心未登记该站点")
        rotation = next(
            (event for event in envelope["events"] if event["event_type"] == "key_rotated"),
            None,
        )
        public_keys = self._get_public_keys(
            conn,
            site_id,
            envelope["signer_key_fingerprint"],
            rotation,
        )
        if not public_keys:
            raise EvidenceError("unknown_key", "中心不信任该签名公钥")
        message = canonical_json(package_unsigned({k: v for k, v in envelope.items() if k != "_signature_bytes"}))
        if not any(
            crypto.verify(public, message, envelope["_signature_bytes"])
            for public in public_keys
        ):
            raise EvidenceError("invalid_signature", "包签名验证失败")

    def _check_chain_and_references(
        self, conn: sqlite3.Connection, envelope: dict
    ) -> None:
        site_id = envelope["site_id"]
        rotation = next(
            (event for event in envelope["events"] if event["event_type"] == "key_rotated"),
            None,
        )

        if envelope["start_sequence"] == 1:
            if envelope["start_prev_hash"] != GENESIS:
                raise EvidenceError("hash_mismatch", "1 号包前序哈希必须是 GENESIS")
        else:
            previous = conn.execute(
                "SELECT event_hash FROM events WHERE site_id=? AND sequence=?",
                (site_id, envelope["start_sequence"] - 1),
            ).fetchone()
            expected_previous = previous["event_hash"] if previous else None
            if expected_previous is not None:
                if expected_previous != envelope["start_prev_hash"]:
                    raise EvidenceError("fork_detected", "包前序哈希与既有链分叉")

        current_sequence = self._current_sequence(conn, site_id)
        if envelope["start_sequence"] > current_sequence + 1:
            raise EvidenceError("awaiting_predecessor", "并发提交中等待前序包")

        existing_by_id = {
            row["event_id"]: row
            for row in conn.execute(
                "SELECT * FROM events WHERE site_id=?", (site_id,)
            ).fetchall()
        }
        existing_by_sequence = {
            row["sequence"]: row for row in existing_by_id.values()
        }
        all_current = [
            self._event_from_row(row)
            for row in conn.execute(
                "SELECT * FROM events ORDER BY site_id, sequence"
            ).fetchall()
        ]
        combined = {event["event_id"]: event for event in all_current}
        combined.update({event["event_id"]: event for event in envelope["events"]})

        for incoming in envelope["events"]:
            same_sequence = existing_by_sequence.get(incoming["sequence"])
            if (
                same_sequence is not None
                and same_sequence["event_hash"] != incoming["event_hash"]
            ):
                raise EvidenceError("fork_detected", "相同站点序号存在不同事件")
            existing = existing_by_id.get(incoming["event_id"])
            if existing is not None:
                if existing["sequence"] != incoming["sequence"]:
                    raise EvidenceError("event_id_conflict", "相同事件 ID 但序号不同")
                if existing["event_hash"] != incoming["event_hash"]:
                    raise EvidenceError("event_id_conflict", "相同事件 ID 但内容不同")
            else:
                global_row = conn.execute(
                    "SELECT site_id FROM events WHERE event_id=?",
                    (incoming["event_id"],),
                ).fetchone()
                if global_row is not None:
                    raise EvidenceError("event_id_conflict", "事件 ID 已被其它站点使用")
                self._validate_references(
                    conn, incoming, list(combined.values())
                )

        if rotation is not None:
            self._validate_rotation_against_database(conn, rotation)

    def _overlaps_committed_chain(
        self, conn: sqlite3.Connection, envelope: dict
    ) -> bool:
        row = conn.execute(
            """
            SELECT 1 FROM events
            WHERE site_id=? AND sequence BETWEEN ? AND ?
            LIMIT 1
            """,
            (
                envelope["site_id"],
                envelope["start_sequence"],
                envelope["end_sequence"],
            ),
        ).fetchone()
        return row is not None

    def _validate_rotation_against_database(
        self, conn: sqlite3.Connection, rotation: dict
    ) -> None:
        payload = rotation["payload"]
        if payload["valid_from_sequence"] != rotation["sequence"]:
            raise EvidenceError("invalid_payload", "轮换生效序号必须等于轮换事件序号")
        fingerprint = key_fingerprint(crypto.b64decode(payload["new_public_key_b64"]))
        if fingerprint != payload["new_key_fingerprint"]:
            raise EvidenceError("invalid_key", "轮换公钥与指纹不一致")
        duplicate = conn.execute(
            """
            SELECT event_id FROM events
            WHERE site_id=? AND event_type='key_rotated' AND sequence=?
            """,
            (rotation["site_id"], rotation["sequence"]),
        ).fetchone()
        if duplicate is not None and duplicate["event_id"] != rotation["event_id"]:
            raise EvidenceError("fork_detected", "相同序号已有不同轮换事件")

    def _persist_quarantine(
        self,
        conn: sqlite3.Connection,
        package_id: str,
        envelope: dict,
        reason: str,
        accepted: bool = False,
    ) -> dict:
        timestamp = now_iso()
        result = {
            "status": "quarantined",
            "reason": reason,
            "package_id": package_id,
            "site_id": envelope["site_id"],
            "start_sequence": envelope["start_sequence"],
            "end_sequence": envelope["end_sequence"],
        }
        stored = {key: value for key, value in envelope.items() if not key.startswith("_")}
        conn.execute(
            """
            INSERT INTO packages(package_id,fingerprint,site_id,start_sequence,end_sequence,
                             status,reason,envelope_json,result_json,imported_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                package_id,
                envelope["_fingerprint"],
                envelope["site_id"],
                envelope["start_sequence"],
                envelope["end_sequence"],
                "quarantined",
                reason,
                self._json_dumps(stored),
                None,
                timestamp,
                timestamp,
            ),
        )
        self._add_package_log(conn, package_id, "quarantined", reason)
        for event in envelope["events"]:
            conn.execute(
                """
                INSERT OR IGNORE INTO package_events(package_id,event_id,site_id,sequence,
                                               event_hash,envelope_json,accepted)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    package_id,
                    event["event_id"],
                    event["site_id"],
                    event["sequence"],
                    event["event_hash"],
                    self._json_dumps(event),
                    1 if accepted else 0,
                ),
            )
        return result

    def _persist_accepted(
        self, conn: sqlite3.Connection, package_id: str, envelope: dict
    ) -> tuple[list[dict], dict]:
        timestamp = now_iso()
        inserted: list[dict] = []
        for event in envelope["events"]:
            existing = conn.execute(
                "SELECT event_id FROM events WHERE event_id=?", (event["event_id"],)
            ).fetchone()
            if existing is None:
                self._insert_event(conn, event)
                inserted.append(event)
            conn.execute(
                """
                INSERT INTO package_events(package_id,event_id,site_id,sequence,
                                      event_hash,envelope_json,accepted)
                VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(package_id, event_id) DO UPDATE SET accepted=1
                """,
                (
                    package_id,
                    event["event_id"],
                    event["site_id"],
                    event["sequence"],
                    event["event_hash"],
                    self._json_dumps(event),
                ),
            )
            rotation = event["event_type"] == "key_rotated"
            if rotation:
                payload = event["payload"]
                conn.execute(
                    "INSERT OR IGNORE INTO site_public_keys VALUES (?,?,?,?,?)",
                    (
                        event["site_id"],
                        payload["new_key_fingerprint"],
                        payload["new_public_key_b64"],
                        payload["valid_from_sequence"],
                        event["recorded_at"],
                    ),
                )
        result = {
            "status": "accepted",
            "package_id": package_id,
            "site_id": envelope["site_id"],
            "start_sequence": envelope["start_sequence"],
            "end_sequence": envelope["end_sequence"],
            "inserted_event_count": len(inserted),
            "inserted_event_ids": [event["event_id"] for event in inserted],
        }
        stored = {key: value for key, value in envelope.items() if not key.startswith("_")}
        conn.execute(
            """
            INSERT INTO packages(package_id,fingerprint,site_id,start_sequence,end_sequence,
                             status,reason,envelope_json,result_json,imported_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(package_id) DO UPDATE SET
              status=excluded.status,
              reason=excluded.reason,
              envelope_json=excluded.envelope_json,
              result_json=excluded.result_json,
              updated_at=excluded.updated_at
            """,
            (
                package_id,
                envelope["_fingerprint"],
                envelope["site_id"],
                envelope["start_sequence"],
                envelope["end_sequence"],
                "accepted",
                None,
                self._json_dumps(stored),
                self._json_dumps(result),
                timestamp,
                timestamp,
            ),
        )
        self._add_package_log(conn, package_id, "accepted", None)
        return inserted, result

    def _release_waiting(self, conn: sqlite3.Connection, site_id: str) -> int:
        released = 0
        while True:
            current = self._current_sequence(conn, site_id)
            row = conn.execute(
                """
                SELECT * FROM packages
                WHERE site_id=? AND status='quarantined' AND start_sequence=?
                ORDER BY imported_at, package_id LIMIT 1
                """,
                (site_id, current + 1),
            ).fetchone()
            if row is None:
                return released
            envelope = self.validate_envelope_static(json.loads(row["envelope_json"]))
            try:
                self._verify_envelope_signature(conn, envelope)
                self._check_chain_and_references(conn, envelope)
            except EvidenceError as exc:
                if exc.code == "missing_gap":
                    return released
                timestamp = now_iso()
                conn.execute(
                    "UPDATE packages SET status='quarantined', reason=?, updated_at=? WHERE package_id=?",
                    (exc.code, timestamp, row["package_id"]),
                )
                self._add_package_log(conn, row["package_id"], "quarantined", exc.code)
                return released
            _, result = self._persist_accepted(conn, row["package_id"], envelope)
            released += 1
        return released

    def _import_once(self, envelope: dict, package_id: str) -> dict:
        with self.connect(True) as conn:
            duplicate = conn.execute(
                "SELECT * FROM packages WHERE fingerprint=?",
                (envelope["_fingerprint"],),
            ).fetchone()
            if duplicate is not None:
                return self._result_from_package_row(duplicate)
            self._verify_envelope_signature(conn, envelope)
            self._check_chain_and_references(conn, envelope)
            self._persist_accepted(conn, package_id, envelope)
            self._release_waiting(conn, envelope["site_id"])
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM packages WHERE package_id=?", (package_id,)
            ).fetchone()
        return self._result_from_package_row(row)

    def import_package(self, envelope: object) -> dict:
        try:
            normalized = self.validate_envelope_static(envelope)
        except EvidenceError as exc:
            return self._record_static_quarantine(envelope, exc)

        package_id = f"pkg_{uuid.uuid4().hex}"
        try:
            with self.connect() as conn:
                self._verify_envelope_signature(conn, normalized)
        except EvidenceError as exc:
            with self.connect(True) as conn:
                duplicate = conn.execute(
                    "SELECT * FROM packages WHERE fingerprint=?",
                    (normalized["_fingerprint"],),
                ).fetchone()
                if duplicate is not None:
                    return self._result_from_package_row(duplicate)
                return self._persist_quarantine(
                    conn, package_id, normalized, exc.code
                )
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                with self.connect() as read_conn:
                    overlaps_committed = self._overlaps_committed_chain(
                        read_conn, normalized
                    )
                if not overlaps_committed:
                    gate_ready = self._wait_for_import_gate(
                        normalized["site_id"], normalized["start_sequence"]
                    )
                    if not gate_ready:
                        raise EvidenceError("missing_gap", "导入包前存在缺口")
                result = self._import_once(normalized, package_id)
                self._complete_import_gate(normalized["site_id"], normalized["start_sequence"])
                return result
            except sqlite3.OperationalError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
            except EvidenceError as exc:
                if exc.code in {"sequence_ahead", "awaiting_predecessor"}:
                    if time.monotonic() >= deadline:
                        if exc.code == "sequence_ahead":
                            return self._record_static_quarantine(
                                normalized,
                                EvidenceError("lock_timeout", "等待站点链锁超时", 503),
                            )
                        exc = EvidenceError("missing_gap", "导入包前存在缺口")
                    else:
                        time.sleep(0.02)
                        continue
                with self.connect(True) as conn:
                    duplicate = conn.execute(
                        "SELECT * FROM packages WHERE fingerprint=?",
                        (normalized["_fingerprint"],),
                    ).fetchone()
                    if duplicate is not None:
                        return self._result_from_package_row(duplicate)
                    return self._persist_quarantine(
                        conn, package_id, normalized, exc.code
                    )
        return self._record_static_quarantine(
            normalized,
            EvidenceError("lock_timeout", "等待站点链锁超时", 503),
        )

    def list_packages(self, quarantine_only: bool = False) -> list[dict]:
        query = "SELECT * FROM packages"
        if quarantine_only:
            query += " WHERE status='quarantined'"
        query += " ORDER BY site_id, start_sequence, imported_at, package_id"
        with self.connect() as conn:
            rows = conn.execute(query).fetchall()
        packages = []
        for row in rows:
            item = dict(
                package_id=row["package_id"],
                fingerprint=row["fingerprint"],
                site_id=row["site_id"],
                start_sequence=row["start_sequence"],
                end_sequence=row["end_sequence"],
                status=row["status"],
                reason=row["reason"],
                imported_at=row["imported_at"],
                updated_at=row["updated_at"],
            )
            with self.connect() as conn:
                item["event_count"] = conn.execute(
                    "SELECT COUNT(*) AS n FROM package_events WHERE package_id=?",
                    (row["package_id"],),
                ).fetchone()["n"]
            packages.append(item)
        return packages

    def retry_package(self, package_id: str) -> dict:
        with self.connect(True) as conn:
            row = conn.execute(
                "SELECT * FROM packages WHERE package_id=?", (package_id,)
            ).fetchone()
            if row is None:
                raise EvidenceError("unknown_package", "未知隔离包", 404)
            if row["status"] != "quarantined":
                return self._result_from_package_row(row)
            stored_envelope = json.loads(row["envelope_json"])
            normalized = self.validate_envelope_static(stored_envelope)
            try:
                self._verify_envelope_signature(conn, normalized)
                self._check_chain_and_references(conn, normalized)
                _, result = self._persist_accepted(conn, package_id, normalized)
                self._release_waiting(conn, normalized["site_id"])
            except EvidenceError as exc:
                timestamp = now_iso()
                conn.execute(
                    "UPDATE packages SET reason=?, updated_at=? WHERE package_id=?",
                    (exc.code, timestamp, package_id),
                )
                self._add_package_log(conn, package_id, "quarantined", exc.code)
                return self._result_from_package_row(
                    conn.execute(
                        "SELECT * FROM packages WHERE package_id=?", (package_id,)
                    ).fetchone()
                )
        return result

    @staticmethod
    def _time_key(event: dict, field: str) -> tuple[datetime, str, int, str]:
        return (
            parse_timestamp(event[field]),
            event["site_id"],
            event["sequence"],
            event["event_id"],
        )

    def _sorted_sample_events(self, events: list[dict], field: str) -> list[dict]:
        return sorted(events, key=lambda event: self._time_key(event, field))

    def _business_facts(self, events: list[dict], as_of: datetime | None) -> list[dict]:
        by_id = {event["event_id"]: event for event in events}
        facts: list[dict] = []
        for event in events:
            if event["event_type"] not in SAMPLE_EVENT_TYPES:
                continue
            if as_of is not None and parse_timestamp(event["effective_at"]) > as_of:
                continue
            latest_correction = None
            for candidate in events:
                if (
                    candidate["event_type"] == "correction"
                    and candidate["payload"]["original_event_id"] == event["event_id"]
                    and parse_timestamp(candidate["effective_at"])
                    <= (as_of or parse_timestamp(candidate["effective_at"]))
                ):
                    if latest_correction is None or self._time_key(
                        candidate, "effective_at"
                    ) > self._time_key(latest_correction, "effective_at"):
                        latest_correction = candidate
            if latest_correction is None:
                fact = dict(event)
            else:
                fact = {
                    **event,
                    "event_type": event["event_type"],
                    "payload": latest_correction["payload"]["corrected_payload"],
                    "effective_at": latest_correction["payload"].get(
                        "corrected_effective_at", event["effective_at"]
                    ),
                    "derived_from_event_id": event["event_id"],
                    "corrected_by_event_id": latest_correction["event_id"],
                }
            if as_of is not None and parse_timestamp(fact["effective_at"]) > as_of:
                continue
            facts.append(fact)

        rejected: set[str] = set()
        reconciliations = []
        for event in self._sorted_sample_events(
            [
                item
                for item in events
                if item["event_type"] == "reconciliation"
                and (as_of is None or parse_timestamp(item["effective_at"]) <= as_of)
            ],
            "effective_at",
        ):
            adopted = event["payload"]["adopted_event_id"]
            original_adopted = adopted
            correction = by_id.get(adopted)
            if correction and correction["event_type"] == "correction":
                original_adopted = correction["payload"]["original_event_id"]
            for candidate in event["payload"]["candidate_event_ids"]:
                original = candidate
                candidate_event = by_id.get(candidate)
                if candidate_event and candidate_event["event_type"] == "correction":
                    original = candidate_event["payload"]["original_event_id"]
                if candidate != adopted and original != original_adopted:
                    rejected.add(original)
                    rejected.add(candidate)
            reconciliations.append(event)

        return [
            fact
            for fact in self._sorted_sample_events(facts, "effective_at")
            if fact["event_id"] not in rejected
        ]

    def derive_state(
        self, sample_id: str, as_of: str | datetime | None = None
    ) -> dict:
        cutoff = None
        if isinstance(as_of, str):
            cutoff = parse_timestamp(as_of)
        elif isinstance(as_of, datetime):
            cutoff = as_of if as_of.tzinfo else parse_timestamp(as_of.isoformat() + "Z")
        events = self.list_events(sample_id=sample_id)
        facts = self._business_facts(events, cutoff)
        stages: dict[int, dict] = {}
        conflicts: dict[str, list[str]] = {}
        for fact in facts:
            rank = STAGE_RANK[fact["event_type"]]
            existing = stages.get(rank)
            if existing is None:
                stages[rank] = fact
            elif existing["event_id"] == fact["event_id"]:
                continue
            else:
                conflicts.setdefault(fact["event_type"], []).extend(
                    [
                        existing.get("derived_from_event_id", existing["event_id"]),
                        fact.get("derived_from_event_id", fact["event_id"]),
                    ]
                )

        current = stages[max(stages)] if stages else None
        unique_conflicts = {
            key: sorted(set(values)) for key, values in conflicts.items() if values
        }
        reconciliation_events = [
            event
            for event in self._sorted_sample_events(events, "effective_at")
            if event["event_type"] == "reconciliation"
            and (cutoff is None or parse_timestamp(event["effective_at"]) <= cutoff)
        ]
        return {
            "sample_id": sample_id,
            "as_of": cutoff.isoformat().replace("+00:00", "Z") if cutoff else None,
            "current_stage": current["event_type"] if current else None,
            "current_fact": current,
            "has_conflict": bool(unique_conflicts),
            "conflicts": unique_conflicts,
            "facts": facts,
            "reconciliations": reconciliation_events,
            "sort_rule": "effective_at, site_id, sequence, event_id",
        }

    def provenance(self, sample_id: str) -> dict:
        events = self.list_events(sample_id=sample_id)
        return {
            "sample_id": sample_id,
            "events_chain_order": events,
            "effective_timeline": self._sorted_sample_events(events, "effective_at"),
            "recorded_timeline": self._sorted_sample_events(events, "recorded_at"),
            "chain_sort_rule": "site_id, sequence",
            "effective_sort_rule": "effective_at, site_id, sequence, event_id",
            "recorded_sort_rule": "recorded_at, site_id, sequence, event_id",
            "derived_state": self.derive_state(sample_id),
        }
