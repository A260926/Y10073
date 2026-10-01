"""Deterministic canonical JSON used by hashes and signatures.

The wire format is UTF-8 JSON with sorted object keys, no insignificant
whitespace, no Unicode escaping and no NaN/Infinity. Floating point numbers
are intentionally rejected so hashes remain unambiguous across runtimes.
"""

from __future__ import annotations

import json
import math
from typing import Any


class CanonicalValueError(ValueError):
    pass


def _validate(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str) or isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalValueError(f"{path}: NaN and Infinity are not allowed in canonical data")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalValueError(f"{path}: object keys must be strings")
        for key, item in value.items():
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalValueError(f"{path}: unsupported JSON value type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_hex(value: Any) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(value)).hexdigest()
