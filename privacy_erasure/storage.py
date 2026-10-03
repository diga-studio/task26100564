"""SQLite 账本与密钥库。

账本（ledger.sqlite3）内只存放密文 PII 与明文非 PII；
每 worker 的密钥单独存放于 keys/ 目录，永不进入备份。
"""

import base64
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    worker_id TEXT PRIMARY KEY,
    name_enc  BLOB NOT NULL,
    ssn_enc   BLOB NOT NULL,
    company   TEXT NOT NULL,
    state     TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    request_id  TEXT,
    op          TEXT NOT NULL,
    worker_id   TEXT,
    field       TEXT,
    old_pii_enc BLOB,
    new_pii_enc BLOB,
    old_value   TEXT,
    new_value   TEXT,
    detail      TEXT
);
CREATE TABLE IF NOT EXISTS erasures (
    worker_id  TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    erased_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    op         TEXT NOT NULL,
    worker_id  TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_workers (
    worker_id     TEXT PRIMARY KEY,
    registered_at TEXT NOT NULL
);
"""

# 恢复时仅替换业务状态表；审计、擦除、请求、known_workers 属账本，不回滚。
BUSINESS_TABLES = ("profiles",)

PII_FIELDS = ("name", "ssn")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _key_filename(worker_id: str) -> str:
    return base64.urlsafe_b64encode(worker_id.encode("utf-8")).decode("ascii") + ".key"


class KeyStore:
    """管理每 worker 的 PII 密钥文件；密钥不进入任何备份。"""

    def __init__(self, keys_dir: Path) -> None:
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, worker_id: str) -> Path:
        return self.keys_dir / _key_filename(worker_id)

    def create(self, worker_id: str) -> bytes:
        key = crypto.generate_key()
        self._path(worker_id).write_bytes(key)
        return key

    def load(self, worker_id: str) -> Optional[bytes]:
        path = self._path(worker_id)
        return path.read_bytes() if path.exists() else None

    def destroy(self, worker_id: str) -> None:
        path = self._path(worker_id)
        if path.exists():
            path.unlink()


class Ledger:
    """SQLite 账本：当前档案、追加式审计、擦除登记、请求去重。"""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- 当前档案（业务状态） ----

    def get_profile_row(self, worker_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM profiles WHERE worker_id = ?", (worker_id,)
        )
        return cur.fetchone()

    def insert_profile(self, worker_id: str, name_enc: bytes, ssn_enc: bytes,
                       company: str, state: str) -> None:
        self._conn.execute(
            "INSERT INTO profiles (worker_id, name_enc, ssn_enc, company, state, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (worker_id, name_enc, ssn_enc, company, state, utcnow()),
        )

    def update_profile(self, worker_id: str, name_enc: bytes, ssn_enc: bytes,
                       company: str, state: str) -> None:
        self._conn.execute(
            "UPDATE profiles SET name_enc=?, ssn_enc=?, company=?, state=?, updated_at=?"
            " WHERE worker_id=?",
            (name_enc, ssn_enc, company, state, utcnow(), worker_id),
        )

    def delete_profile(self, worker_id: str) -> None:
        self._conn.execute("DELETE FROM profiles WHERE worker_id = ?", (worker_id,))

    def replace_profiles(self, rows: List[dict]) -> None:
        self._conn.execute("DELETE FROM profiles")
        self._conn.executemany(
            "INSERT INTO profiles (worker_id, name_enc, ssn_enc, company, state, updated_at)"
            " VALUES (:worker_id, :name_enc, :ssn_enc, :company, :state, :updated_at)",
            rows,
        )

    # ---- 审计（追加式，不回滚） ----

    def append_audit(self, *, op: str, request_id: Optional[str] = None,
                     worker_id: Optional[str] = None, field: Optional[str] = None,
                     old_pii_enc: Optional[bytes] = None, new_pii_enc: Optional[bytes] = None,
                     old_value: Optional[str] = None, new_value: Optional[str] = None,
                     detail: Optional[dict] = None) -> None:
        self._conn.execute(
            "INSERT INTO audit (ts, request_id, op, worker_id, field,"
            " old_pii_enc, new_pii_enc, old_value, new_value, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (utcnow(), request_id, op, worker_id, field,
             old_pii_enc, new_pii_enc, old_value, new_value,
             json.dumps(detail, ensure_ascii=False) if detail is not None else None),
        )

    def get_all_audit_rows(self) -> List[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM audit ORDER BY seq")
        return cur.fetchall()

    def get_audit_rows(self, worker_id: str) -> List[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM audit WHERE worker_id = ? ORDER BY seq", (worker_id,)
        )
        return cur.fetchall()

    # ---- 擦除登记 ----

    def is_erased(self, worker_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM erasures WHERE worker_id = ?", (worker_id,)
        )
        return cur.fetchone() is not None

    def erased_worker_ids(self) -> List[str]:
        cur = self._conn.execute("SELECT worker_id FROM erasures")
        return [r["worker_id"] for r in cur.fetchall()]

    def record_erasure(self, worker_id: str, request_id: str) -> None:
        self._conn.execute(
            "INSERT INTO erasures (worker_id, request_id, erased_at) VALUES (?, ?, ?)",
            (worker_id, request_id, utcnow()),
        )

    # ---- 请求去重 ----

    def request_status(self, request_id: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT op FROM requests WHERE request_id = ?", (request_id,)
        )
        row = cur.fetchone()
        return row["op"] if row else None

    def record_request(self, request_id: str, op: str, worker_id: Optional[str]) -> None:
        self._conn.execute(
            "INSERT INTO requests (request_id, op, worker_id, created_at) VALUES (?, ?, ?, ?)",
            (request_id, op, worker_id, utcnow()),
        )

    # ---- 曾登记过的 worker ----

    def is_known(self, worker_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM known_workers WHERE worker_id = ?", (worker_id,)
        )
        return cur.fetchone() is not None

    def record_known(self, worker_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO known_workers (worker_id, registered_at) VALUES (?, ?)",
            (worker_id, utcnow()),
        )

    def commit(self) -> None:
        self._conn.commit()
