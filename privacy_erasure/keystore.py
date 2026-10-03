"""Separate key store for per-worker PII keys.

The key store is NEVER included in backups: destroying a worker's key
makes that worker's PII unrecoverable from every managed file and every
historical backup (crypto-shredding).
"""

from __future__ import annotations

import sqlite3
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    worker_id TEXT PRIMARY KEY,
    key_hex   TEXT NOT NULL
);
"""


class KeyStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def get(self, worker_id: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT key_hex FROM keys WHERE worker_id = ?", (worker_id,)
        ).fetchone()
        return row[0] if row else None

    def put(self, worker_id: str, key_hex: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO keys (worker_id, key_hex) VALUES (?, ?)",
            (worker_id, key_hex),
        )
        self._conn.commit()

    def delete(self, worker_id: str) -> None:
        self._conn.execute("DELETE FROM keys WHERE worker_id = ?", (worker_id,))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
