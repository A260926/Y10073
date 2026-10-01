from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_hex, canonical_json
from .ed25519 import public_key, sign, verify

GENESIS_HASH = "0" * 64
PACKAGE_FORMAT = "evidence-chain-package/v1"


def event_hash(event: dict[str, Any]) -> str:
    body = {
        "event_id": event["event_id"],
        "site_id": event["site_id"],
        "seq": event["seq"],
        "sample_id": event["sample_id"],
        "type": event["type"],
        "payload": event["payload"],
        "effective_at": event["effective_at"],
        "recorded_at": event["recorded_at"],
    }
    return canonical_hex({"schema": "evidence-chain-event/v1", "event": body})


def event_hashes(events: list[dict[str, Any]]) -> list[str]:
    return [event_hash(event) for event in events]


def chain_hashes(events: list[dict[str, Any]], previous: str = GENESIS_HASH) -> list[str]:
    result: list[str] = []
    current = previous
    for event in events:
        current = hashlib.sha256((current + event_hash(event)).encode("ascii")).hexdigest()
        result.append(current)
    return result


def last_chain_hash(events: list[dict[str, Any]], previous: str = GENESIS_HASH) -> str:
    values = chain_hashes(events, previous)
    return values[-1] if values else previous


def signing_payload(package: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in package.items() if key != "signature"}


def package_content_hash(package: str | dict[str, Any]) -> str:
    return canonical_hex(signing_payload(package))


def make_public_key(seed: bytes) -> str:
    return public_key(seed).hex()


def build_signed_package(
    *,
    site_id: str,
    start_seq: int,
    end_seq: int,
    prev_hash: str,
    events: list[dict[str, Any]],
    created_at: str,
    kid: str,
    seed_hex: str,
    key_claim: dict[str, Any] | None = None,
) -> dict[str, Any]:
    package: dict[str, Any] = {
        "format": PACKAGE_FORMAT,
        "site_id": site_id,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "prev_hash": prev_hash,
        "events": events,
        "event_hashes": event_hashes(events),
        "created_at": created_at,
    }
    if key_claim is not None:
        package["key"] = key_claim
    seed = bytes.fromhex(seed_hex)
    message = canonical_json(signing_payload(package))
    package["signature"] = {"kid": kid, "alg": "Ed25519", "sig": sign(seed, message).hex()}
    return package


@dataclass(frozen=True)
class SignatureCheck:
    canonical: bytes
    kid: str


def verify_signature(package: dict[str, Any], known_public_keys: dict[str, str]) -> SignatureCheck:
    signature = package.get("signature")
    if not isinstance(signature, dict):
        raise ValueError("package.signature is required")
    kid = signature.get("kid")
    sig_hex = signature.get("sig")
    alg = signature.get("alg")
    if alg != "Ed25519" or not isinstance(kid, str) or not isinstance(sig_hex, str):
        raise ValueError("unsupported or malformed signature")
    public_hex = known_public_keys.get(kid)
    if public_hex is None:
        raise ValueError(f"unknown signing key {kid}")
    try:
        public_bytes = bytes.fromhex(public_hex)
        signature_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise ValueError("malformed hexadecimal key or signature") from exc
    message = canonical_json(signing_payload(package))
    verify(public_bytes, message, signature_bytes)
    return SignatureCheck(message, kid)
