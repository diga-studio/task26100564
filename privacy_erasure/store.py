"""SQLite persistence for business state, audit ledger, erasures and requests.

Main DB tables:
  profiles      -- current business state (PII columns hold ciphertext)
  audit         -- append-only ledger; PII inside detail JSON is ciphertext
  erasures      -- erasure facts; never rolled back, never exported to backups
  requests      -- idempotency ledger for erase/restore request ids
  known_workers -- every worker_id ever registered (survives deletes/restores)

Backups contain ONLY: profiles, audit, requests. Erasure facts and the
key store live outside backups, so a restore can never resurrect erased PII.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    worker_id  TEXT PRIMARY KEY,
    name_enc   TEXT NOT NULL,
    ssn_enc    TEXT NOT NULL,
    company    TEXT NOT NULL,
    state      TEXT NOT NULL,
    version    INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    entry_id   TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    worker_id  TEXT,
    request_id TEXT,
    detail     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS erasures (
    worker_id  TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    ts         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    ts         TEXT NOT NULL,
    detail     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_workers (
    worker_id     TEXT PRIMARY KEY,
    registered_at TEXT NOT NULL
);
"""

_BACKUP_TABLES = ("profiles", "audit", "requests")

_BACKUP_SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    worker_id  TEXT PRIMARY KEY,
    name_enc   TEXT NOT NULL,
    ssn_enc    TEXT NOT NULL,
    company    TEXT NOT NULL,
    state      TEXT NOT NULL,
    version    INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    entry_id   TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    worker_id  TEXT,
    request_id TEXT,
    detail     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    ts         TEXT NOT NULL,
    detail     TEXT NOT NULL
);
"""



def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProfileRow:
    worker_id: str
    name_enc: str
    ssn_enc: str
    company: str
    state: str
    version: int
    updated_at: str


@dataclass
class AuditRow:
    entry_id: str
    seq: int
    ts: str
    kind: str
    worker_id: Optional[str]
    request_id: Optional[str]
    detail: dict


class Store:
    """Owns the main SQLite database (business state + audit ledger)."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- profiles ---------------------------------------------------------

    def get_profile(self, worker_id: str) -> Optional[ProfileRow]:
        row = self._conn.execute(
            "SELECT * FROM profiles WHERE worker_id = ?", (worker_id,)
        ).fetchone()
        return self._to_profile(row) if row else None

    def upsert_profile(self, p: ProfileRow) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO profiles"
            " (worker_id, name_enc, ssn_enc, company, state, version, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (p.worker_id, p.name_enc, p.ssn_enc, p.company, p.state, p.version, p.updated_at),
        )
        self._conn.commit()

    def delete_profile(self, worker_id: str) -> None:
        self._conn.execute("DELETE FROM profiles WHERE worker_id = ?", (worker_id,))
        self._conn.commit()

    def list_profiles(self) -> list:
        return [self._to_profile(r) for r in self._conn.execute("SELECT * FROM profiles")]

    def replace_profiles(self, rows: list) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM profiles")
            for p in rows:
                self._conn.execute(
                    "INSERT INTO profiles"
                    " (worker_id, name_enc, ssn_enc, company, state, version, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (p.worker_id, p.name_enc, p.ssn_enc, p.company, p.state, p.version, p.updated_at),
                )

    @staticmethod
    def _to_profile(row: sqlite3.Row) -> ProfileRow:
        return ProfileRow(
            worker_id=row["worker_id"], name_enc=row["name_enc"], ssn_enc=row["ssn_enc"],
            company=row["company"], state=row["state"], version=row["version"],
            updated_at=row["updated_at"],
        )

    # -- audit ------------------------------------------------------------

    def append_audit(self, kind: str, worker_id: Optional[str],
                     request_id: Optional[str], detail: dict) -> str:
        entry_id = uuid.uuid4().hex
        with self._conn:
            seq = self._conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit").fetchone()[0]
            self._conn.execute(
                "INSERT INTO audit (entry_id, seq, ts, kind, worker_id, request_id, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (entry_id, seq, _now(), kind, worker_id, request_id, json.dumps(detail)),
            )
        return entry_id

    def list_audit(self, worker_id: Optional[str] = None) -> list:
        if worker_id is None:
            cur = self._conn.execute("SELECT * FROM audit ORDER BY seq")
        else:
            cur = self._conn.execute(
                "SELECT * FROM audit WHERE worker_id = ? ORDER BY seq", (worker_id,))
        return [self._to_audit(r) for r in cur]

    def merge_audit(self, rows: list) -> None:
        with self._conn:
            max_seq = self._conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit").fetchone()[0]
            for r in rows:
                exists = self._conn.execute(
                    "SELECT 1 FROM audit WHERE entry_id = ?", (r["entry_id"],)).fetchone()
                if exists:
                    continue
                max_seq += 1
                self._conn.execute(
                    "INSERT INTO audit (entry_id, seq, ts, kind, worker_id, request_id, detail)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (r["entry_id"], max_seq, r["ts"], r["kind"], r["worker_id"],
                     r["request_id"], r["detail"]),
                )

    @staticmethod
    def _to_audit(row: sqlite3.Row) -> AuditRow:
        return AuditRow(
            entry_id=row["entry_id"], seq=row["seq"], ts=row["ts"], kind=row["kind"],
            worker_id=row["worker_id"], request_id=row["request_id"],
            detail=json.loads(row["detail"]),
        )

    # -- erasures (never exported, never rolled back) ----------------------

    def add_erasure(self, worker_id: str, request_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO erasures (worker_id, request_id, ts) VALUES (?, ?, ?)",
            (worker_id, request_id, _now()),
        )
        self._conn.commit()

    def is_erased(self, worker_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM erasures WHERE worker_id = ?", (worker_id,)).fetchone() is not None

    def erased_ids(self) -> set:
        return {r[0] for r in self._conn.execute("SELECT worker_id FROM erasures")}

    # -- idempotency ledger ------------------------------------------------

    def get_request(self, request_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
        if not row:
            return None
        return {"request_id": row["request_id"], "kind": row["kind"],
                "ts": row["ts"], "detail": json.loads(row["detail"])}

    def record_request(self, request_id: str, kind: str, detail: dict) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO requests (request_id, kind, ts, detail) VALUES (?, ?, ?, ?)",
            (request_id, kind, _now(), json.dumps(detail)),
        )
        self._conn.commit()

    def merge_requests(self, rows: list) -> None:
        with self._conn:
            for r in rows:
                self._conn.execute(
                    "INSERT OR IGNORE INTO requests (request_id, kind, ts, detail)"
                    " VALUES (?, ?, ?, ?)",
                    (r["request_id"], r["kind"], r["ts"], r["detail"]),
                )

    # -- ever-registered workers -------------------------------------------

    def add_known_worker(self, worker_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO known_workers (worker_id, registered_at) VALUES (?, ?)",
            (worker_id, _now()),
        )
        self._conn.commit()

    def is_known_worker(self, worker_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM known_workers WHERE worker_id = ?", (worker_id,)).fetchone() is not None

    # -- backup export / import --------------------------------------------

    def export_backup(self, dest_path: str) -> None:
        """Write a backup file containing ONLY profiles/audit/requests."""
        out = sqlite3.connect(dest_path)
        try:
            out.executescript(_BACKUP_SCHEMA)
            with out:
                for table in _BACKUP_TABLES:
                    cols = [r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")]
                    col_list = ", ".join(cols)
                    marks = ", ".join("?" for _ in cols)
                    for row in self._conn.execute(f"SELECT {col_list} FROM {table}"):
                        out.execute(f"INSERT INTO {table} ({col_list}) VALUES ({marks})",
                                    tuple(row))
        finally:
            out.close()

    @staticmethod
    def load_backup(path: str) -> dict:
        """Read a backup file; returns {'profiles': [...], 'audit': [...], 'requests': [...]}."""
        src = sqlite3.connect(path)
        src.row_factory = sqlite3.Row
        try:
            profiles = [dict(r) for r in src.execute("SELECT * FROM profiles")]
            audit = [dict(r) for r in src.execute("SELECT * FROM audit ORDER BY seq")]
            requests = [dict(r) for r in src.execute("SELECT * FROM requests")]
        finally:
            src.close()
        return {"profiles": profiles, "audit": audit, "requests": requests}
