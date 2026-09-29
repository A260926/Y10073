from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO 8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def event_hash(event: dict) -> str:
    return canonical_hash(
        {
            "event_id": event["event_id"],
            "site_id": event["site_id"],
            "sequence": event["sequence"],
            "sample_id": event["sample_id"],
            "event_type": event["event_type"],
            "payload": event["payload"],
            "recorded_at": event["recorded_at"],
            "effective_at": event["effective_at"],
            "prev_hash": event["prev_hash"],
        }
    )


def package_unsigned(envelope: dict) -> dict:
    return {
        "format": envelope["format"],
        "site_id": envelope["site_id"],
        "start_sequence": envelope["start_sequence"],
        "end_sequence": envelope["end_sequence"],
        "start_prev_hash": envelope["start_prev_hash"],
        "events": envelope["events"],
        "created_at": envelope["created_at"],
    }


def package_fingerprint(envelope: dict) -> str:
    return canonical_hash(package_unsigned(envelope))


def key_fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()
