"""PII 加密原语：每 worker 独立密钥，擦除即销毁密钥（crypto-shredding）。

仅使用标准库实现：以 HMAC-SHA256 构造密钥流对明文异或加密，
并附加 HMAC 完整性标签。密钥本身永不进入账本与备份。
"""

import hashlib
import hmac
import os

KEY_BYTES = 32
NONCE_BYTES = 16
TAG_BYTES = 16
_BLOCK = hashlib.sha256().digest_size


def generate_key() -> bytes:
    return os.urandom(KEY_BYTES)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(key: bytes, plaintext: str) -> bytes:
    data = plaintext.encode("utf-8")
    nonce = os.urandom(NONCE_BYTES)
    stream = _keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:TAG_BYTES]
    return nonce + ciphertext + tag


def decrypt(key: bytes, blob: bytes) -> str:
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("ciphertext too short")
    nonce = blob[:NONCE_BYTES]
    tag = blob[-TAG_BYTES:]
    ciphertext = blob[NONCE_BYTES:-TAG_BYTES]
    expect = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:TAG_BYTES]
    if not hmac.compare_digest(tag, expect):
        raise ValueError("integrity check failed")
    stream = _keystream(key, nonce, len(ciphertext))
    data = bytes(a ^ b for a, b in zip(ciphertext, stream))
    return data.decode("utf-8")
