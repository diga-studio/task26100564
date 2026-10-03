"""Per-worker PII encryption (crypto-shredding support).

Each worker's PII is encrypted with a dedicated random key. Erasing a
worker destroys the key, which makes the worker's ciphertexts -- wherever
they live (current DB, audit ledger, historical backups) -- unrecoverable.

Construction (stdlib only): a SHA-256 counter-mode keystream (CTR) plus
HMAC-SHA256 authentication (encrypt-then-MAC).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_KEY_BYTES = 32
_NONCE_BYTES = 16
_TAG_BYTES = 16


def generate_key() -> str:
    """Generate a new random per-worker key (hex-encoded)."""
    return os.urandom(_KEY_BYTES).hex()


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(key_hex: str, plaintext: str) -> str:
    """Encrypt a PII string; output is an opaque base64 token."""
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(_NONCE_BYTES)
    data = plaintext.encode("utf-8")
    stream = _keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:_TAG_BYTES]
    return base64.b64encode(nonce + tag + ciphertext).decode("ascii")


def decrypt(key_hex: str, token: str) -> str:
    """Decrypt a token produced by :func:`encrypt`."""
    key = bytes.fromhex(key_hex)
    raw = base64.b64decode(token.encode("ascii"))
    nonce, tag, ciphertext = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:_NONCE_BYTES + _TAG_BYTES], raw[_NONCE_BYTES + _TAG_BYTES:]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:_TAG_BYTES]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("PII token authentication failed")
    stream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")
