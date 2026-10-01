"""Small RFC 8032 Ed25519 implementation.

The application only needs one signing algorithm in offline environments.
This implementation is compact but not constant-time; it is intended for the
shipped test/demo workflow rather than production hardware-key security.
"""

from __future__ import annotations

import hashlib
import hmac
import os

q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, q - 2, q)) % q
i = pow(2, (q - 1) // 4, q)


def _y_inv(y: int) -> int:
    xx = (y * y - 1) * pow(d * y * y + 1, q - 2, q) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * i) % q
    if x % 2 != 0:
        x = q - x
    return x


by = 4 * pow(5, q - 2, q) % q
bx = _y_inv(by)
base = (bx, by, 1, (bx * by) % q)
ident = (0, 1, 1, 0)


def point_add(p: tuple[int, int, int, int], r: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = r
    a = ((y1 - x1) * (y2 - x2)) % q
    b = ((y1 + x1) * (y2 + x2)) % q
    c = (2 * d * t1 * t2) % q
    dd = (2 * z1 * z2) % q
    e = (b - a) % q
    f = (dd - c) % q
    g = (dd + c) % q
    h = (b + a) % q
    return (e * f % q, g * h % q, f * g % q, e * h % q)


def scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = ident
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, q - 2, q)
    x = x * zinv % q
    y = y * zinv % q
    bits = y.to_bytes(32, "little")
    value = bytearray(bits)
    value[31] |= x << 7 & 0x80
    return bytes(value)


def decode_point(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    x = _y_inv(y)
    if (x * x - (y * y - 1) * pow(d * y * y + 1, q - 2, q)) % q != 0:
        raise ValueError("point is not on curve")
    if (x == 0 and sign) or x % 2 != sign:
        x = q - x
    point = (x, y, 1, x * y % q)
    if encode_point(point) != data:
        raise ValueError("non-canonical point encoding")
    return point


def _scalar_from_seed(seed: bytes) -> tuple[int, bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = bytearray(hashlib.sha512(seed).digest())
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    scalar = int.from_bytes(digest[:32], "little")
    return scalar, bytes(digest[32:]), bytes(digest[:32])


def public_key(seed: bytes) -> bytes:
    scalar, _, _ = _scalar_from_seed(seed)
    return encode_point(scalar_mult(base, scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix, _ = _scalar_from_seed(seed)
    public = encode_point(scalar_mult(base, scalar))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % l
    r_point = scalar_mult(base, r)
    r_bytes = encode_point(r_point)
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % l
    s = (r + k * scalar) % l
    return r_bytes + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> None:
    if len(public) != 32 or len(signature) != 64:
        raise ValueError("invalid Ed25519 key or signature length")
    r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= l:
        raise ValueError("Ed25519 signature S is out of range")
    r_point = decode_point(r_bytes)
    public_point = decode_point(public)
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % l
    check_left = scalar_mult(base, s)
    check_right = point_add(r_point, scalar_mult(public_point, k))
    if not hmac.compare_digest(encode_point(check_left), encode_point(check_right)):
        raise ValueError("Ed25519 signature mismatch")


def generate_seed() -> bytes:
    return os.urandom(32)
