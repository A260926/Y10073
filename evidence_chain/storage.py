from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .ed25519 import generate_seed, public_key
from .packages import (
    GENESIS_HASH,
    PACKAGE_FORMAT,
    build_signed_package,
    event_hash,
    package_content_hash,
    verify_signature,
)
from .state import PHYSICAL_TYPES, provenance
from .timeutils import normalized_utc, parse_utc, utc_now


class EvidenceError(ValueError):
    status = 400


class NotFound(EvidenceError):
    status = 404


class Conflict(EvidenceError):
    status = 409


def _loads(value: str | bytes | None, default: Any = None) -> Any:
    return json.loads(value) if value is not None else default


def _dumps(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  site_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  last_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  current_kid TEXT,
  FOREIGN KEY(current_kid) REFERENCES site_keys(kid)
);
CREATE TABLE IF NOT EXISTS site_keys (
  kid TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  private_seed_hex TEXT,
  status TEXT NOT NULL CHECK(status IN ('active','retired','pending')),
  effective_after_seq INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(site_id) REFERENCES sites(site_id)
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  sample_id TEXT NOT NULL,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  imported_batch_id INTEGER,
  UNIQUE(site_id, seq),
  FOREIGN KEY(site_id) REFERENCES sites(site_id),
  FOREIGN KEY(imported_batch_id) REFERENCES import_batches(id)
);
CREATE INDEX IF NOT EXISTS events_sample ON events(sample_id, effective_at, recorded_at, site_id, seq);
CREATE TABLE IF NOT EXISTS import_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_hash TEXT NOT NULL,
  site_id TEXT,
  start_seq INTEGER,
  end_seq INTEGER,
  status TEXT NOT NULL CHECK(status IN ('accepted','quarantined','duplicate','ignored')),
  reason TEXT,
  package_json TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  original_batch_id INTEGER,
  released_at TEXT
);
CREATE INDEX IF NOT EXISTS import_batches_lookup ON import_batches(content_hash);
CREATE INDEX IF NOT EXISTS import_batches_retry ON import_batches(status, site_id, start_seq);
CREATE TABLE IF NOT EXISTS export_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  start_seq INTEGER NOT NULL,
  end_seq INTEGER NOT NULL,
  content_hash TEXT NOT NULL UNIQUE,
  package_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(site_id) REFERENCES sites(site_id)
);
CREATE TABLE IF NOT EXISTS key_rotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  old_kid TEXT NOT NULL,
  new_kid TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','applied')),
  created_at TEXT NOT NULL,
  applied_after_seq INTEGER,
  UNIQUE(new_kid),
  FOREIGN KEY(site_id) REFERENCES sites(site_id)
);
"""


def connect(path: str | Path = "instance/evidence.db") -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL" if path != ":memory:" else "PRAGMA journal_mode=MEMORY")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO schema_meta(key,value) VALUES('version','1')")
    return conn


class Store:
    def __init__(self, path: str | Path = "instance/evidence.db", conn: sqlite3.Connection | None = None):
        self._owns = conn is None
        self.conn = conn or connect(path)
        self._lock = threading.RLock()

    def close(self) -> None:
        if self._owns:
            self.conn.close()

    def _rows(self, query: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(query, args).fetchall()]

    def _event(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        data = dict(row)
        data["payload"] = _loads(data["payload"], {})
        return data

    @staticmethod
    def _public_event(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": event["event_id"],
            "site_id": event["site_id"],
            "seq": event["seq"],
            "sample_id": event["sample_id"],
            "type": event["type"],
            "payload": event["payload"],
            "effective_at": event["effective_at"],
            "recorded_at": event["recorded_at"],
        }

    def _begin(self) -> None:
        self.conn.execute("BEGIN IMMEDIATE")

    def create_site(self, site_id: str, name: str, *, seed: bytes | None = None, kid: str | None = None) -> dict[str, str]:
        import re

        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", site_id):
            raise EvidenceError("site_id must contain 2-64 letters, digits, _ or -")
        seed = generate_seed() if seed is None else seed
        if len(seed) != 32:
            raise EvidenceError("private seed must be 32 bytes")
        kid = kid or f"{site_id}-k1"
        public_hex = public_key(seed).hex()
        now = utc_now()
        with self._lock:
            self._begin()
            try:
                if self.conn.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone():
                    raise Conflict("site already exists")
                self.conn.execute(
                    "INSERT INTO sites(site_id,name,last_seq,last_hash,created_at,current_kid) VALUES(?,?,?,?,?,NULL)",
                    (site_id, name, 0, GENESIS_HASH, now),
                )
                self.conn.execute(
                    "INSERT INTO site_keys(kid,site_id,public_key,private_seed_hex,status,effective_after_seq,created_at) VALUES(?,?,?,?, 'active', 0, ?)",
                    (kid, site_id, public_hex, seed.hex(), now),
                )
                self.conn.execute("UPDATE sites SET current_kid=? WHERE site_id=?", (kid, site_id))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"site_id": site_id, "kid": kid, "public_key": public_hex, "private_seed_hex": seed.hex()}

    def register_remote_site(self, site_id: str, name: str, kid: str, public_key_hex: str) -> dict[str, str]:
        try:
            public_bytes = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            raise EvidenceError("public key must be 64 hex characters") from exc
        if len(public_bytes) != 32:
            raise EvidenceError("public key must be 64 hex characters")
        now = utc_now()
        with self._lock:
            self._begin()
            try:
                if self.conn.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone():
                    raise Conflict("site already exists")
                self.conn.execute(
                    "INSERT INTO sites(site_id,name,last_seq,last_hash,created_at,current_kid) VALUES(?,?,?,?,?,NULL)",
                    (site_id, name, 0, GENESIS_HASH, now),
                )
                self.conn.execute(
                    "INSERT INTO site_keys(kid,site_id,public_key,private_seed_hex,status,effective_after_seq,created_at) VALUES(?,?,?,NULL,'active',0,?)",
                    (kid, site_id, public_key_hex, now),
                )
                self.conn.execute("UPDATE sites SET current_kid=? WHERE site_id=?", (kid, site_id))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"site_id": site_id, "kid": kid, "public_key": public_key_hex}

    def list_sites(self) -> list[dict[str, Any]]:
        with self._lock:
            sites = self._rows(
                """SELECT s.site_id,s.name,s.last_seq,s.last_hash,s.created_at,s.current_kid,
                          k.public_key,k.status
                   FROM sites s LEFT JOIN site_keys k ON k.kid=s.current_kid
                   ORDER BY s.site_id"""
            )
            pending = self._rows(
                """SELECT site_id,new_kid,created_at FROM key_rotations
                   WHERE status='pending' ORDER BY id"""
            )
            pending_by_site: dict[str, list[dict[str, str]]] = {}
            for row in pending:
                pending_by_site.setdefault(row["site_id"], []).append(row)
            for site in sites:
                site["pending_rotations"] = pending_by_site.get(site["site_id"], [])
            return sites

    @staticmethod
    def _validate_event_body(body: dict[str, Any], *, require_assigned: bool = True) -> tuple[str, str, str, dict[str, Any], str, str]:
        required = ("site_id", "sample_id", "type", "payload")
        missing = [key for key in required if key not in body]
        if missing:
            raise EvidenceError(f"event missing fields: {', '.join(missing)}")
        allowed_fields = {
            "event_id", "site_id", "seq", "sample_id", "type", "payload",
            "effective_at", "recorded_at",
        }
        unexpected_fields = sorted(set(body) - allowed_fields)
        if unexpected_fields:
            raise EvidenceError(f"event contains unsupported fields: {', '.join(unexpected_fields)}")
        optional_for_recording = {"event_id", "seq"}
        required_fields = allowed_fields if require_assigned else allowed_fields - optional_for_recording
        missing_fields = sorted(required_fields - set(body))
        if missing_fields:
            raise EvidenceError(f"event missing fields: {', '.join(missing_fields)}")
        site_id = body["site_id"]
        sample_id = body["sample_id"]
        event_type = body["type"]
        payload = body["payload"]
        if not all(isinstance(value, str) and value for value in (site_id, sample_id, event_type)):
            raise EvidenceError("site_id, sample_id and type must be non-empty strings")
        if not isinstance(payload, dict):
            raise EvidenceError("event payload must be an object")
        allowed = {"collected", "processed", "aliquoted", "destroyed", "correction", "reconciliation"}
        if event_type not in allowed:
            raise EvidenceError(f"unsupported event type {event_type}")
        recorded = normalized_utc(body.get("recorded_at") or utc_now(), "recorded_at")
        effective = normalized_utc(body.get("effective_at") or recorded, "effective_at")
        if parse_utc(recorded, "recorded_at") < parse_utc(effective, "effective_at"):
            raise EvidenceError("recorded_at cannot be earlier than effective_at")
        required_payload: dict[str, set[str]] = {
            "collected": {"sample_type", "location", "operator"},
            "processed": {"process", "location", "operator"},
            "aliquoted": {"aliquot_id", "volume_ml", "location", "operator"},
            "destroyed": {"reason", "location", "operator"},
        }
        if event_type in required_payload:
            absent = sorted(required_payload[event_type] - set(payload))
            if absent:
                raise EvidenceError(f"{event_type} payload requires: {', '.join(absent)}")
            if any(not isinstance(payload[key], (str, int, float, bool)) or payload[key] == "" for key in required_payload[event_type]):
                raise EvidenceError(f"{event_type} required payload values must be non-empty scalars")
        if event_type == "correction":
            target_id = payload.get("target_event_id")
            patch = payload.get("patch")
            if not isinstance(target_id, str) or not target_id or not isinstance(patch, dict):
                raise EvidenceError("correction payload requires target_event_id and patch object")
            if not all(isinstance(key, str) and key for key in patch):
                raise EvidenceError("correction patch keys must be non-empty strings")
        if event_type == "reconciliation":
            selected = payload.get("selected_event_ids")
            rejected = payload.get("rejected_event_ids", [])
            if (
                not isinstance(selected, list)
                or len(selected) != 1
                or not all(isinstance(item, str) for item in selected)
                or not isinstance(rejected, list)
                or not rejected
                or not all(isinstance(item, str) for item in rejected)
                or not isinstance(payload.get("reason"), str)
                or not payload.get("reason")
            ):
                raise EvidenceError("reconciliation requires exactly one selected event, at least one rejected event and reason")
        return site_id, sample_id, event_type, payload, effective, recorded

    def _known_event(self, event_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return self._event(row) if row else None

    def record_event(self, body: dict[str, Any]) -> dict[str, Any]:
        site_id, sample_id, event_type, payload, effective, recorded = self._validate_event_body(
            body, require_assigned=False
        )
        with self._lock:
            self._begin()
            try:
                site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
                if site is None:
                    raise EvidenceError(f"unknown site {site_id}")
                if "seq" in body and body["seq"] != int(site["last_seq"]) + 1:
                    raise EvidenceError("recorded seq must match the site's next sequence")
                self._validate_references(body={
                    **body,
                    "site_id": site_id,
                    "sample_id": sample_id,
                    "type": event_type,
                    "payload": payload,
                    "effective_at": effective,
                    "recorded_at": recorded,
                })
                seq = int(site["last_seq"]) + 1
                event_id = body.get("event_id") or f"{site_id}-e{seq}"
                if not isinstance(event_id, str) or not event_id:
                    raise EvidenceError("event_id must be a non-empty string")
                event = {
                    "event_id": event_id,
                    "site_id": site_id,
                    "seq": seq,
                    "sample_id": sample_id,
                    "type": event_type,
                    "payload": payload,
                    "effective_at": effective,
                    "recorded_at": recorded,
                }
                event["event_hash"] = event_hash(event)
                event["chain_hash"] = event_hash  # replaced below
                import hashlib

                chain = hashlib.sha256((site["last_hash"] + event["event_hash"]).encode("ascii")).hexdigest()
                event["chain_hash"] = chain
                self._check_local_lifecycle(site_id, sample_id, event_type)
                self.conn.execute(
                    """INSERT INTO events(event_id,site_id,seq,sample_id,type,payload,effective_at,
                       recorded_at,event_hash,chain_hash,imported_batch_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,NULL)""",
                    (
                        event["event_id"], site_id, seq, sample_id, event_type, _dumps(payload),
                        effective, recorded, event["event_hash"], chain
                    ),
                )
                self.conn.execute(
                    "UPDATE sites SET last_seq=?, last_hash=? WHERE site_id=?",
                    (seq, chain, site_id),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return event

    def _check_local_lifecycle(self, site_id: str, sample_id: str, event_type: str) -> None:
        if event_type not in PHYSICAL_TYPES:
            return
        latest = self.conn.execute(
            """SELECT type FROM events WHERE site_id=? AND sample_id=? AND type IN ('collected','processed','aliquoted','destroyed')
               ORDER BY seq DESC, event_id DESC LIMIT 1""",
            (site_id, sample_id),
        ).fetchone()
        if event_type == "collected":
            if latest is not None:
                raise Conflict("sample already has a collection event at this site")
        elif latest is None:
            raise Conflict("sample must be collected at the same site before this physical event")
        elif latest["type"] == "destroyed":
            raise Conflict("cannot append a physical event after destruction")

    def _validate_references(self, *, body: dict[str, Any], known: dict[str, dict[str, Any]] | None = None) -> None:
        event_type = body["type"]
        payload = body["payload"]

        def lookup(event_id: str) -> dict[str, Any] | None:
            if known is not None:
                return known.get(event_id)
            return self._known_event(event_id)

        if event_type == "correction":
            target = lookup(payload["target_event_id"])
            if target is None:
                raise EvidenceError("correction target event is unavailable")
            if target["type"] == "correction":
                raise EvidenceError("a correction cannot correct another correction")
            if target["sample_id"] != body["sample_id"]:
                raise EvidenceError("correction must reference an event for the same sample")
            if parse_utc(target["effective_at"], "target effective_at") > parse_utc(body["effective_at"], "effective_at"):
                raise EvidenceError("correction effective_at cannot precede its target")
            if parse_utc(target["recorded_at"], "target recorded_at") > parse_utc(body["recorded_at"], "recorded_at"):
                raise EvidenceError("correction recorded_at cannot precede its target")
        if event_type == "reconciliation":
            selected_ids = payload["selected_event_ids"]
            rejected_ids = payload["rejected_event_ids"]
            if len(set(selected_ids)) != len(selected_ids) or len(set(rejected_ids)) != len(rejected_ids):
                raise EvidenceError("reconciliation references must be unique")
            if set(selected_ids) & set(rejected_ids):
                raise EvidenceError("an event cannot be both selected and rejected")
            for event_id in selected_ids + rejected_ids:
                target = lookup(event_id)
                if target is None:
                    raise EvidenceError(f"reconciliation target {event_id} is unavailable")
                if target["sample_id"] != body["sample_id"] or target["type"] not in PHYSICAL_TYPES:
                    raise EvidenceError("reconciliation target must be a physical event for the same sample")
                if parse_utc(target["effective_at"], "target effective_at") > parse_utc(body["effective_at"], "effective_at"):
                    raise EvidenceError("reconciliation effective_at cannot precede its target")
                if parse_utc(target["recorded_at"], "target recorded_at") > parse_utc(body["recorded_at"], "recorded_at"):
                    raise EvidenceError("reconciliation recorded_at cannot precede its target")

    def rotate_key(self, site_id: str, *, new_kid: str | None = None, seed: bytes | None = None) -> dict[str, str]:
        seed = generate_seed() if seed is None else seed
        now = utc_now()
        with self._lock:
            self._begin()
            try:
                site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
                if site is None:
                    raise NotFound("unknown site")
                if self.conn.execute("SELECT 1 FROM key_rotations WHERE site_id=? AND status='pending'", (site_id,)).fetchone():
                    raise Conflict("a key rotation is already pending export")
                number = self.conn.execute("SELECT COUNT(*) c FROM site_keys WHERE site_id=?", (site_id,)).fetchone()["c"] + 1
                new_kid = new_kid or f"{site_id}-k{number}"
                public_hex = public_key(seed).hex()
                self.conn.execute(
                    "INSERT INTO site_keys(kid,site_id,public_key,private_seed_hex,status,effective_after_seq,created_at) VALUES(?,?,?,?, 'pending', 0, ?)",
                    (new_kid, site_id, public_hex, seed.hex(), now),
                )
                self.conn.execute(
                    "INSERT INTO key_rotations(site_id,old_kid,new_kid,status,created_at) VALUES(?,?,?, 'pending', ?)",
                    (site_id, site["current_kid"], new_kid, now),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"site_id": site_id, "old_kid": site["current_kid"], "new_kid": new_kid, "public_key": public_hex}

    def _private_key(self, site_id: str, kid: str) -> str:
        row = self.conn.execute(
            "SELECT private_seed_hex FROM site_keys WHERE site_id=? AND kid=? AND status='active'",
            (site_id, kid),
        ).fetchone()
        if row is None or not row["private_seed_hex"]:
            raise Conflict("this central database has no private seed for the site; rotate at the site database")
        return row["private_seed_hex"]

    def export_next_package(self, site_id: str, *, max_events: int | None = None) -> dict[str, Any]:
        with self._lock:
            self._begin()
            try:
                site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
                if site is None:
                    raise NotFound("unknown site")
                last_exported = self.conn.execute(
                    "SELECT COALESCE(MAX(end_seq),0) m FROM export_batches WHERE site_id=?",
                    (site_id,),
                ).fetchone()["m"]
                pending = self.conn.execute(
                    "SELECT * FROM key_rotations WHERE site_id=? AND status='pending' ORDER BY id LIMIT 1",
                    (site_id,),
                ).fetchone()
                events_rows = self.conn.execute(
                    "SELECT * FROM events WHERE site_id=? AND seq>? ORDER BY seq,event_id",
                    (site_id, last_exported),
                ).fetchall()
                if max_events is not None and max_events > 0:
                    events_rows = events_rows[:max_events]
                if not events_rows and pending is None:
                    raise Conflict("no unexported events or pending key rotation")
                old_kid = site["current_kid"]
                seed_hex = self._private_key(site_id, old_kid)
                if events_rows:
                    events = [self._public_event(self._event(row)) for row in events_rows]
                    start_seq = int(events[0]["seq"])
                    end_seq = int(events[-1]["seq"])
                    prev = self._prev_hash_for_export(site, start_seq)
                    key_claim = None
                    if pending is not None:
                        new_key = self.conn.execute(
                            "SELECT * FROM site_keys WHERE kid=?", (pending["new_kid"],)
                        ).fetchone()
                        key_claim = {
                            "kid": pending["new_kid"],
                            "public_key": new_key["public_key"],
                            "effective_after_seq": end_seq,
                        }
                    package = build_signed_package(
                        site_id=site_id,
                        start_seq=start_seq,
                        end_seq=end_seq,
                        prev_hash=prev,
                        events=events,
                        created_at=utc_now(),
                        kid=old_kid,
                        seed_hex=seed_hex,
                        key_claim=key_claim,
                    )
                    if pending is not None:
                        self._apply_local_rotation(pending, end_seq, old_kid)
                else:
                    end_seq = int(site["last_seq"])
                    new_key = self.conn.execute(
                        "SELECT * FROM site_keys WHERE kid=?", (pending["new_kid"],)
                    ).fetchone()
                    key_claim = {
                        "kid": pending["new_kid"],
                        "public_key": new_key["public_key"],
                        "effective_after_seq": end_seq,
                    }
                    package = build_signed_package(
                        site_id=site_id,
                        start_seq=end_seq,
                        end_seq=end_seq,
                        prev_hash=site["last_hash"],
                        events=[],
                        created_at=utc_now(),
                        kid=old_kid,
                        seed_hex=seed_hex,
                        key_claim=key_claim,
                    )
                    self._apply_local_rotation(pending, end_seq, old_kid)
                content_hash = package_content_hash(package)
                cur = self.conn.execute(
                    """INSERT INTO export_batches(site_id,start_seq,end_seq,content_hash,package_json,created_at)
                       VALUES(?,?,?,?,?,?)""",
                    (site_id, package["start_seq"], package["end_seq"], content_hash, _dumps(package), package["created_at"]),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return self.get_export(cur.lastrowid)

    def _prev_hash_for_export(self, site: sqlite3.Row, start_seq: int) -> str:
        if start_seq == 1:
            return GENESIS_HASH
        row = self.conn.execute(
            "SELECT end_seq,package_json FROM export_batches WHERE site_id=? ORDER BY end_seq DESC,id DESC LIMIT 1",
            (site["site_id"],),
        ).fetchone()
        if row and int(row["end_seq"]) == start_seq - 1:
            prior = _loads(row["package_json"])
            return self._package_end_hash(prior)
        prev_event = self.conn.execute(
            "SELECT chain_hash FROM events WHERE site_id=? AND seq=?",
            (site["site_id"], start_seq - 1),
        ).fetchone()
        return prev_event["chain_hash"]

    @staticmethod
    def _package_end_hash(package: dict[str, Any]) -> str:
        if not package.get("events"):
            return package["prev_hash"]
        import hashlib

        current = package["prev_hash"]
        for value in package["event_hashes"]:
            current = hashlib.sha256((current + value).encode("ascii")).hexdigest()
        return current

    def _apply_local_rotation(self, pending: sqlite3.Row, effective_after_seq: int, old_kid: str) -> None:
        self.conn.execute(
            "UPDATE site_keys SET status='retired' WHERE kid=? AND site_id=?",
            (old_kid, pending["site_id"]),
        )
        self.conn.execute(
            "UPDATE site_keys SET status='active',effective_after_seq=? WHERE kid=?",
            (effective_after_seq, pending["new_kid"]),
        )
        self.conn.execute(
            "UPDATE sites SET current_kid=? WHERE site_id=?",
            (pending["new_kid"], pending["site_id"]),
        )
        self.conn.execute(
            "UPDATE key_rotations SET status='applied', applied_after_seq=? WHERE id=?",
            (effective_after_seq, pending["id"]),
        )

    def list_exports(self, site_id: str | None = None) -> list[dict[str, Any]]:
        if site_id:
            rows = self._rows(
                "SELECT id,site_id,start_seq,end_seq,content_hash,created_at FROM export_batches WHERE site_id=? ORDER BY id",
                (site_id,),
            )
        else:
            rows = self._rows(
                "SELECT id,site_id,start_seq,end_seq,content_hash,created_at FROM export_batches ORDER BY id"
            )
        return rows

    def get_export(self, export_id: int) -> dict[str, Any]:
        row = self.conn.execute("SELECT package_json FROM export_batches WHERE id=?", (export_id,)).fetchone()
        if row is None:
            raise NotFound("export package not found")
        return _loads(row["package_json"])

    @staticmethod
    def _is_hex(value: Any, length: int) -> bool:
        if not isinstance(value, str) or len(value) != length:
            return False
        try:
            int(value, 16)
        except ValueError:
            return False
        return True

    def _validate_package_shape(self, package: Any) -> None:
        if not isinstance(package, dict):
            raise EvidenceError("package must be a JSON object")
        required = {
            "format", "site_id", "start_seq", "end_seq", "prev_hash",
            "events", "event_hashes", "created_at", "signature",
        }
        missing = sorted(required - set(package))
        if missing:
            raise EvidenceError(f"package missing fields: {', '.join(missing)}")
        unexpected = sorted(set(package) - required - {"key"})
        if unexpected:
            raise EvidenceError(f"package contains unsupported fields: {', '.join(unexpected)}")
        if package["format"] != PACKAGE_FORMAT:
            raise EvidenceError("unsupported package format")
        if not isinstance(package["site_id"], str) or not package["site_id"]:
            raise EvidenceError("package site_id must be a non-empty string")
        for key in ("start_seq", "end_seq"):
            if not isinstance(package[key], int) or isinstance(package[key], bool) or package[key] < 0:
                raise EvidenceError(f"{key} must be a non-negative integer")
        if package["start_seq"] > package["end_seq"]:
            raise EvidenceError("start_seq must be <= end_seq")
        if not self._is_hex(package["prev_hash"], 64):
            raise EvidenceError("prev_hash must be 64 hex characters")
        events = package["events"]
        hashes = package["event_hashes"]
        if not isinstance(events, list) or not isinstance(hashes, list) or len(events) != len(hashes):
            raise EvidenceError("events and event_hashes must be arrays of equal length")
        key_only = package["start_seq"] == package["end_seq"] and not events
        expected_length = 0 if key_only else package["end_seq"] - package["start_seq"] + 1
        if len(events) != expected_length:
            raise EvidenceError("event count does not match sequence range")
        normalized_utc(package["created_at"], "created_at")
        event_ids: set[str] = set()
        for index, event in enumerate(events):
            try:
                site_id, sample_id, event_type, payload, effective, recorded = self._validate_event_body(
                    event, require_assigned=True
                )
            except EvidenceError as exc:
                raise EvidenceError(f"event[{index}]: {exc}") from exc
            if site_id != package["site_id"]:
                raise EvidenceError(f"event[{index}] site_id does not match package")
            expected_seq = package["start_seq"] + index
            if event.get("seq") != expected_seq:
                raise EvidenceError(f"event[{index}] seq does not match its range position")
            if event["event_id"] in event_ids:
                raise EvidenceError(f"duplicate event_id inside package: {event['event_id']}")
            event_ids.add(event["event_id"])
            if hashes[index] != event_hash(event):
                raise EvidenceError(f"event hash mismatch at seq {expected_seq}")

    def import_package(self, raw_package: Any) -> dict[str, Any]:
        try:
            package = json.loads(canonical_json(raw_package).decode("utf-8"))
            self._validate_package_shape(package)
            content_hash = package_content_hash(package)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            site_id = raw_package.get("site_id") if isinstance(raw_package, dict) else None
            start_seq = raw_package.get("start_seq") if isinstance(raw_package, dict) else None
            end_seq = raw_package.get("end_seq") if isinstance(raw_package, dict) else None
            if not isinstance(site_id, str):
                site_id = None
            if not isinstance(start_seq, int) or isinstance(start_seq, bool) or start_seq < 0:
                start_seq = None
            if not isinstance(end_seq, int) or isinstance(end_seq, bool) or end_seq < 0:
                end_seq = None
            stored = self._store_malformed(raw_package, str(exc), site_id, start_seq, end_seq)
            return {"status": "quarantined", "reason": str(exc), "batch_id": stored}
        with self._lock:
            self._begin()
            try:
                result = self._import_locked(package, content_hash)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return result

    def _store_malformed(
        self,
        raw_package: Any,
        reason: str,
        site_id: str | None = None,
        start_seq: int | None = None,
        end_seq: int | None = None,
    ) -> int:
        with self._lock:
            self._begin()
            try:
                cur = self.conn.execute(
                    """INSERT INTO import_batches(content_hash,site_id,start_seq,end_seq,status,reason,
                       package_json,imported_at,original_batch_id,released_at)
                       VALUES(?,?,?,?,'quarantined',?,?,?,NULL,NULL)""",
                    ("malformed", site_id, start_seq, end_seq, reason, _dumps({"raw": raw_package}), utc_now()),
                )
                batch_id = int(cur.lastrowid)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return batch_id

    def _import_locked(self, package: dict[str, Any], content_hash: str) -> dict[str, Any]:
        duplicate = self.conn.execute(
            """SELECT * FROM import_batches
               WHERE content_hash=?
                 AND NOT (status='quarantined' AND reason='unknown site; register its public key at the center')
               ORDER BY id LIMIT 1""",
            (content_hash,),
        ).fetchone()
        if duplicate is not None:
            return {
                "status": duplicate["status"],
                "reason": duplicate["reason"],
                "batch_id": duplicate["id"],
                "repeated": True,
            }
        prior_unknown = self.conn.execute(
            """SELECT * FROM import_batches
               WHERE content_hash=?
                 AND status='quarantined'
                 AND reason='unknown site; register its public key at the center'
               ORDER BY id LIMIT 1""",
            (content_hash,),
        ).fetchone()
        equivalent = self.conn.execute(
            """SELECT * FROM import_batches
               WHERE status='accepted' AND site_id=? AND start_seq=? AND end_seq=?
                 AND package_json LIKE ?
               ORDER BY id LIMIT 1""",
            (
                package["site_id"],
                package["start_seq"],
                package["end_seq"],
                f'%"event_hashes": {_dumps(package["event_hashes"])}%',
            ),
        ).fetchone()
        if equivalent is not None:
            return {
                "status": equivalent["status"],
                "reason": "equivalent signed package was already imported",
                "batch_id": equivalent["id"],
                "repeated": True,
            }
        site_id = package["site_id"]
        site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        reason = self._acceptability_reason(package, site)
        if reason is not None:
            cur = self._insert_quarantined(package, content_hash, reason)
            return {"status": "quarantined", "reason": reason, "batch_id": cur}
        accepted_id = self._apply_package(package, content_hash, prior_unknown)
        released = self._release_ready_gaps(site_id)
        return {
            "status": "accepted",
            "batch_id": prior_unknown["id"] if prior_unknown is not None else accepted_id,
            "events": len(package["events"]),
            "released": released,
        }

    def _known_public_keys(self, site_id: str | None = None) -> dict[str, str]:
        query = "SELECT kid,public_key FROM site_keys"
        args: tuple[Any, ...] = ()
        if site_id is not None:
            query += " WHERE site_id=?"
            args = (site_id,)
        return {row["kid"]: row["public_key"] for row in self.conn.execute(query, args).fetchall()}

    def _acceptability_reason(self, package: dict[str, Any], site: sqlite3.Row | None) -> str | None:
        if site is None:
            return "unknown site; register its public key at the center"
        chain_reason = self._chain_range_reason(package, site)
        if chain_reason is not None:
            return chain_reason
        signature = package.get("signature", {})
        key_claim = package.get("key")
        if isinstance(key_claim, dict):
            claim_kid = key_claim.get("kid")
            if signature.get("kid") != site["current_kid"]:
                return "key rotation claim must be signed by the site's current key"
            if claim_kid != key_claim.get("kid") or not self._is_hex(key_claim.get("public_key", ""), 64):
                return "malformed key rotation claim"
            after = key_claim.get("effective_after_seq")
            if not isinstance(after, int) or isinstance(after, bool) or after != package["end_seq"]:
                return "key claim effective_after_seq must equal package end_seq"
            if self.conn.execute("SELECT 1 FROM site_keys WHERE kid=?", (claim_kid,)).fetchone():
                return "rotated key id already exists"
        try:
            verify_signature(package, self._known_public_keys(package["site_id"]))
        except Exception as exc:
            return f"invalid signature: {exc}"
        events = package["events"]
        import hashlib

        chain = package["prev_hash"]
        known = {row["event_id"]: self._event(row) for row in self.conn.execute("SELECT * FROM events").fetchall()}
        package_events = {event["event_id"]: event for event in events}
        for index, event in enumerate(events):
            chain = hashlib.sha256((chain + package["event_hashes"][index]).encode("ascii")).hexdigest()
            existing = self.conn.execute(
                "SELECT event_hash FROM events WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
            if existing is not None and existing["event_hash"] != package["event_hashes"][index]:
                return f"event id collision with different content: {event['event_id']}"
            if self.conn.execute(
                "SELECT 1 FROM events WHERE site_id=? AND seq=? AND event_id<>?",
                (event["site_id"], event["seq"], event["event_id"]),
            ).fetchone():
                return f"sequence {event['seq']} already contains a different event"
            try:
                self._validate_references(body=event, known={**known, **package_events})
            except EvidenceError as exc:
                return str(exc)
        return None

    def _chain_range_reason(self, package: dict[str, Any], site: sqlite3.Row) -> str | None:
        events = package["events"]
        if events:
            if package["start_seq"] > int(site["last_seq"]) + 1:
                return f"missing segment before seq {package['start_seq']}"
            if package["start_seq"] <= int(site["last_seq"]):
                return "sequence range overlaps imported chain"
            if package["prev_hash"] != site["last_hash"]:
                return "previous hash fork: package prev_hash does not match central chain head"
        elif package["prev_hash"] != site["last_hash"] or package["start_seq"] != int(site["last_seq"]):
            return "key-only package must be attached exactly at the current chain head"
        return None

    def _insert_quarantined(self, package: dict[str, Any], content_hash: str, reason: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO import_batches(content_hash,site_id,start_seq,end_seq,status,reason,
               package_json,imported_at,original_batch_id,released_at)
               VALUES(?,?,?,?, 'quarantined',?,?,?,NULL,NULL)""",
            (
                content_hash, package["site_id"], package["start_seq"], package["end_seq"],
                reason, _dumps(package), utc_now()
            ),
        )
        return int(cur.lastrowid)

    def _apply_package(self, package: dict[str, Any], content_hash: str, prior_unknown: sqlite3.Row | None = None) -> int:
        if prior_unknown is not None:
            self.conn.execute(
                """UPDATE import_batches
                   SET status='accepted', reason=NULL, site_id=?, start_seq=?, end_seq=?,
                       package_json=?, imported_at=imported_at, released_at=?
                   WHERE id=?""",
                (
                    package["site_id"], package["start_seq"], package["end_seq"],
                    _dumps(package), utc_now(), prior_unknown["id"]
                ),
            )
            batch_id = int(prior_unknown["id"])
        else:
            batch_cur = self.conn.execute(
                """INSERT INTO import_batches(content_hash,site_id,start_seq,end_seq,status,reason,
                   package_json,imported_at,original_batch_id,released_at)
                   VALUES(?,?,?,?,'accepted',NULL,?,?,NULL,NULL)""",
                (
                    content_hash, package["site_id"], package["start_seq"], package["end_seq"],
                    _dumps(package), utc_now()
                ),
            )
            batch_id = int(batch_cur.lastrowid)
        import hashlib
        chain = package["prev_hash"]
        for index, event in enumerate(package["events"]):
            chain = hashlib.sha256((chain + package["event_hashes"][index]).encode("ascii")).hexdigest()
            self.conn.execute(
                """INSERT INTO events(event_id,site_id,seq,sample_id,type,payload,effective_at,
                   recorded_at,event_hash,chain_hash,imported_batch_id)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event["event_id"], event["site_id"], event["seq"], event["sample_id"],
                    event["type"], _dumps(event["payload"]), event["effective_at"],
                    event["recorded_at"], package["event_hashes"][index], chain, batch_id
                ),
            )
        end_hash = chain
        end_seq = package["end_seq"]
        self.conn.execute(
            "UPDATE sites SET last_seq=?, last_hash=? WHERE site_id=?",
            (end_seq, end_hash, package["site_id"]),
        )
        key_claim = package.get("key")
        if isinstance(key_claim, dict):
            old_kid = package["signature"]["kid"]
            now = utc_now()
            self.conn.execute(
                """INSERT INTO site_keys(kid,site_id,public_key,private_seed_hex,status,
                   effective_after_seq,created_at)
                   VALUES(?,?,?,NULL,'active',?,?)""",
                (key_claim["kid"], package["site_id"], key_claim["public_key"], end_seq, now),
            )
            self.conn.execute(
                "UPDATE site_keys SET status='retired' WHERE site_id=? AND kid=?",
                (package["site_id"], old_kid),
            )
            self.conn.execute(
                "UPDATE sites SET current_kid=? WHERE site_id=?",
                (key_claim["kid"], package["site_id"]),
            )
        return batch_id

    def _release_ready_gaps(self, site_id: str) -> list[dict[str, Any]]:
        released: list[dict[str, Any]] = []
        while True:
            site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            candidate = self.conn.execute(
                """SELECT * FROM import_batches
                   WHERE site_id=? AND status='quarantined' AND start_seq=?
                   ORDER BY id LIMIT 1""",
                (site_id, int(site["last_seq"]) + 1),
            ).fetchone()
            if candidate is None:
                return released
            package = _loads(candidate["package_json"])
            content_hash = candidate["content_hash"]
            reason = self._acceptability_reason(package, site)
            if reason is not None:
                if candidate["reason"] != reason:
                    self.conn.execute(
                        "UPDATE import_batches SET reason=? WHERE id=?",
                        (reason, candidate["id"]),
                    )
                return released
            self.conn.execute(
                "UPDATE import_batches SET status='accepted', reason=NULL, released_at=? WHERE id=?",
                (utc_now(), candidate["id"]),
            )
            events = package["events"]
            chain = package["prev_hash"]
            import hashlib

            for index, event in enumerate(events):
                chain = hashlib.sha256((chain + package["event_hashes"][index]).encode("ascii")).hexdigest()
                self.conn.execute(
                    """INSERT INTO events(event_id,site_id,seq,sample_id,type,payload,effective_at,
                       recorded_at,event_hash,chain_hash,imported_batch_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        event["event_id"], event["site_id"], event["seq"], event["sample_id"],
                        event["type"], _dumps(event["payload"]), event["effective_at"],
                        event["recorded_at"], package["event_hashes"][index], chain, candidate["id"]
                    ),
                )
            self.conn.execute(
                "UPDATE sites SET last_seq=?, last_hash=? WHERE site_id=?",
                (package["end_seq"], chain, site_id),
            )
            key_claim = package.get("key")
            if isinstance(key_claim, dict):
                old_kid = package["signature"]["kid"]
                self.conn.execute(
                    """INSERT OR IGNORE INTO site_keys(kid,site_id,public_key,private_seed_hex,status,
                       effective_after_seq,created_at)
                       VALUES(?,?,?,NULL,'active',?,?)""",
                    (key_claim["kid"], site_id, key_claim["public_key"], package["end_seq"], utc_now()),
                )
                self.conn.execute(
                    "UPDATE site_keys SET status='retired' WHERE site_id=? AND kid=?",
                    (site_id, old_kid),
                )
                self.conn.execute(
                    "UPDATE sites SET current_kid=? WHERE site_id=?",
                    (key_claim["kid"], site_id),
                )
            released.append({"batch_id": candidate["id"], "end_seq": package["end_seq"]})

    def retry_quarantine(self, batch_id: int) -> dict[str, Any]:
        with self._lock:
            self._begin()
            try:
                row = self.conn.execute("SELECT * FROM import_batches WHERE id=?", (batch_id,)).fetchone()
                if row is None:
                    raise NotFound("quarantine batch not found")
                if row["status"] != "quarantined":
                    result = {"status": row["status"], "batch_id": batch_id, "repeated": True, "reason": row["reason"]}
                else:
                    package = _loads(row["package_json"])
                    if set(package) == {"raw"}:
                        try:
                            self._validate_package_shape(package["raw"])
                            reason = "malformed package became structurally valid unexpectedly"
                        except EvidenceError as exc:
                            reason = str(exc)
                        self.conn.execute("UPDATE import_batches SET reason=? WHERE id=?", (reason, batch_id))
                        result = {"status": "quarantined", "batch_id": batch_id, "reason": reason}
                        self.conn.execute("COMMIT")
                        return result
                    site = self.conn.execute("SELECT * FROM sites WHERE site_id=?", (row["site_id"],)).fetchone()
                    if site is not None and package["end_seq"] <= int(site["last_seq"]):
                        self.conn.execute(
                            "UPDATE import_batches SET status='accepted', reason=NULL, released_at=COALESCE(released_at,?) WHERE id=?",
                            (utc_now(), batch_id),
                        )
                        result = {"status": "accepted", "batch_id": batch_id, "repeated": True}
                        self.conn.execute("COMMIT")
                        return result
                    reason = self._acceptability_reason(package, site)
                    if reason is not None:
                        self.conn.execute(
                            "UPDATE import_batches SET reason=? WHERE id=?",
                            (reason, batch_id),
                        )
                        result = {"status": "quarantined", "batch_id": batch_id, "reason": reason}
                    else:
                        released = self._release_ready_gaps(row["site_id"])
                        result = {"status": "accepted", "batch_id": batch_id, "released": released}
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return result

    def ignore_quarantine(self, batch_id: int) -> dict[str, Any]:
        with self._lock:
            self._begin()
            try:
                row = self.conn.execute("SELECT * FROM import_batches WHERE id=?", (batch_id,)).fetchone()
                if row is None:
                    raise NotFound("quarantine batch not found")
                if row["status"] == "quarantined":
                    self.conn.execute("UPDATE import_batches SET status='ignored' WHERE id=?", (batch_id,))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"status": "ignored", "batch_id": batch_id}

    def list_quarantine(self) -> list[dict[str, Any]]:
        rows = self._rows(
            """SELECT id,content_hash,site_id,start_seq,end_seq,status,reason,imported_at,released_at
               FROM import_batches
               WHERE status IN ('quarantined','ignored','accepted')
                 AND (status <> 'accepted' OR released_at IS NOT NULL)
               ORDER BY imported_at,id"""
        )
        return rows

    def list_imports(self) -> list[dict[str, Any]]:
        return self._rows(
            """SELECT id,content_hash,site_id,start_seq,end_seq,status,reason,imported_at,released_at
               FROM import_batches ORDER BY imported_at,id"""
        )

    def list_events(self, *, site_id: str | None = None, sample_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list[Any] = []
        if site_id:
            sql += " AND site_id=?"
            args.append(site_id)
        if sample_id:
            sql += " AND sample_id=?"
            args.append(sample_id)
        sql += " ORDER BY site_id,seq,event_id"
        return [self._event(row) for row in self.conn.execute(sql, args).fetchall()]

    def list_samples(self) -> list[dict[str, Any]]:
        rows = self._rows(
            """SELECT sample_id,
                      MIN(effective_at) AS first_effective_at,
                      MAX(recorded_at) AS last_recorded_at,
                      COUNT(*) AS event_count,
                      GROUP_CONCAT(DISTINCT site_id) AS sites
               FROM events GROUP BY sample_id ORDER BY MIN(effective_at),sample_id"""
        )
        for row in rows:
            events = self.list_events(sample_id=row["sample_id"])
            state = provenance(events)["state"]
            row["derived_status"] = state.get("status")
            row["resolution"] = state.get("resolution")
        return rows

    def get_sample(self, sample_id: str, *, at: str | None = None, basis: str = "effective") -> dict[str, Any]:
        events = self.list_events(sample_id=sample_id)
        if not events:
            raise NotFound("sample not found")
        result = provenance(events, at=at, basis=basis)
        result["sample_id"] = sample_id
        return result

    def get_site(self, site_id: str) -> dict[str, Any]:
        site = self.conn.execute(
            """SELECT s.*,k.public_key FROM sites s
               LEFT JOIN site_keys k ON k.kid=s.current_kid
               WHERE s.site_id=?""",
            (site_id,),
        ).fetchone()
        if site is None:
            raise NotFound("site not found")
        data = dict(site)
        data["keys"] = self._rows(
            "SELECT kid,status,effective_after_seq,created_at,public_key FROM site_keys WHERE site_id=? ORDER BY created_at,kid",
            (site_id,),
        )
        data["events"] = self.list_events(site_id=site_id)
        data["exports"] = self.list_exports(site_id)
        return data
