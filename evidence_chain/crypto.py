from __future__ import annotations

import base64
import hashlib
import os

p = 2**255 - 19
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)
L = 2**252 + 27742317777372353535851937790883648493


def _inv(value: int) -> int:
    return pow(value, p - 2, p)


_by = 4 * _inv(5) % p
_x_sq = (_by * _by - 1) * _inv(d * _by * _by + 1) % p
_bx = pow(_x_sq, (p + 3) // 8, p)
if (_bx * _bx - _x_sq) % p != 0:
    _bx = _bx * I % p
if _bx > p - _bx:
    _bx = p - _bx
B = (_bx, _by)
IDENTITY = (0, 1)


def _point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + y1 * x2) * _inv(1 + product) % p
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2) % p
    return x3, y3


def _scalar_mult(value: int, point: tuple[int, int]) -> tuple[int, int]:
    result = IDENTITY
    addend = point
    while value:
        if value & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        value >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid point length")
    value = int.from_bytes(encoded, "little")
    parity = value >> 255
    y = value & ((1 << 255) - 1)
    x_sq = (y * y - 1) * _inv(d * y * y + 1) % p
    x = pow(x_sq, (p + 3) // 8, p)
    if (x * x - x_sq) % p != 0:
        x = x * I % p
    if (x & 1) != parity:
        x = p - x
    return (x, y)


def _secret_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    return int.from_bytes(scalar_bytes, "little"), digest[32:]


def generate_seed() -> bytes:
    return os.urandom(32)


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    scalar, _ = _secret_scalar(seed)
    return _encode_point(_fixed_base_scalar_mult(scalar))


def _build_base_table() -> list[list[tuple[int, int]]]:
    table = []
    base_power = B
    for _ in range(64):
        multiples = [IDENTITY]
        for multiple in range(1, 16):
            if multiple == 1:
                multiples.append(base_power)
            else:
                multiples.append(_point_add(multiples[-1], base_power))
        table.append(multiples)
        for _ in range(4):
            base_power = _point_add(base_power, base_power)
    return table


_BASE_TABLE: list[list[tuple[int, int]]] | None = None


def _fixed_base_scalar_mult(value: int) -> tuple[int, int]:
    global _BASE_TABLE
    if _BASE_TABLE is None:
        _BASE_TABLE = _build_base_table()
    result = IDENTITY
    for nibble_index in range(64):
        digit = (value >> (4 * nibble_index)) & 15
        if digit:
            result = _point_add(result, _BASE_TABLE[nibble_index][digit])
    return result


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _secret_scalar(seed)
    public_key = _encode_point(_scalar_mult(scalar, B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_encoded = _encode_point(_fixed_base_scalar_mult(r))
    k = int.from_bytes(
        hashlib.sha512(r_encoded + public_key + message).digest(), "little"
    ) % L
    s = (r + k * scalar) % L
    return r_encoded + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r_point = _decode_point(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        a_point = _decode_point(public_key)
        k = int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(),
            "little",
        ) % L
        expected = _point_add(r_point, _scalar_mult(k, a_point))
        provided = _fixed_base_scalar_mult(s)
        return expected == provided
    except Exception:
        return False


b64encode = base64.b64encode
b64decode = base64.b64decode
