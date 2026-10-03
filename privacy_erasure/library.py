"""Public API: employee profile privacy erasure library.

Layout inside the working directory:
  state.db     -- business state + audit ledger + erasure/request ledgers
  keystore.db  -- per-worker PII keys (NEVER backed up)
  backups/     -- backup files produced by backup()

Erasure is crypto-shredding: the worker's key is destroyed, so every copy
of that worker's PII (current DB, audit history, all historical backups)
becomes permanently undecryptable.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from . import crypto
from .keystore import KeyStore
from .store import ProfileRow, Store

_STATE_DB = "state.db"
_KEYS_DB = "keystore.db"
_BACKUP_DIR = "backups"

_PII_FIELDS = ("name", "ssn")
_NON_PII_FIELDS = ("company", "state")


class PrivacyErasureLibrary:
    def __init__(self, workdir: str) -> None:
        self._workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        os.makedirs(os.path.join(workdir, _BACKUP_DIR), exist_ok=True)
        self._store = Store(os.path.join(workdir, _STATE_DB))
        self._keys = KeyStore(os.path.join(workdir, _KEYS_DB))

    def close(self) -> None:
        self._store.close()
        self._keys.close()

    def __enter__(self) -> "PrivacyErasureLibrary":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- registration & updates -------------------------------------------

    def register(self, worker_id: str, name: str, ssn: str, company: str, state: str) -> None:
        if self._store.is_erased(worker_id):
            raise ValueError(f"worker {worker_id!r} was erased and can never be re-registered")
        if self._store.get_profile(worker_id) is not None:
            raise ValueError(f"worker {worker_id!r} is already registered")
        key = self._keys.get(worker_id) or crypto.generate_key()
        self._keys.put(worker_id, key)
        now = _now()
        self._store.upsert_profile(ProfileRow(
            worker_id=worker_id,
            name_enc=crypto.encrypt(key, name),
            ssn_enc=crypto.encrypt(key, ssn),
            company=company, state=state, version=1, updated_at=now,
        ))
        self._store.add_known_worker(worker_id)
        self._store.append_audit("change", worker_id, None, {
            "before": None,
            "after": self._enc_snapshot(key, name, ssn, company, state),
        })

    def update(self, worker_id: str, *, name: Optional[str] = None, ssn: Optional[str] = None,
               company: Optional[str] = None, state: Optional[str] = None) -> None:
        row = self._store.get_profile(worker_id)
        if row is None:
            raise ValueError(f"worker {worker_id!r} is not registered")
        key = self._keys.get(worker_id)
        if key is None:  # pragma: no cover - erased workers have no profile row
            raise ValueError(f"worker {worker_id!r} has been erased")
        before = self._enc_snapshot(key, crypto.decrypt(key, row.name_enc),
                                    crypto.decrypt(key, row.ssn_enc), row.company, row.state)
        new_name = name if name is not None else crypto.decrypt(key, row.name_enc)
        new_ssn = ssn if ssn is not None else crypto.decrypt(key, row.ssn_enc)
        new_company = company if company is not None else row.company
        new_state = state if state is not None else row.state
        self._store.upsert_profile(ProfileRow(
            worker_id=worker_id,
            name_enc=crypto.encrypt(key, new_name),
            ssn_enc=crypto.encrypt(key, new_ssn),
            company=new_company, state=new_state,
            version=row.version + 1, updated_at=_now(),
        ))
        self._store.append_audit("change", worker_id, None, {
            "before": before,
            "after": self._enc_snapshot(key, new_name, new_ssn, new_company, new_state),
        })

    # -- reads --------------------------------------------------------------

    def get_profile(self, worker_id: str) -> Optional[dict]:
        row = self._store.get_profile(worker_id)
        if row is None:
            return None
        key = self._keys.get(worker_id)
        if key is None:
            return None
        return {
            "worker_id": row.worker_id,
            "name": crypto.decrypt(key, row.name_enc),
            "ssn": crypto.decrypt(key, row.ssn_enc),
            "company": row.company,
            "state": row.state,
            "version": row.version,
            "updated_at": row.updated_at,
        }

    def get_history(self, worker_id: str) -> list:
        key = self._keys.get(worker_id)
        out = []
        for entry in self._store.list_audit(worker_id):
            out.append({
                "entry_id": entry.entry_id,
                "seq": entry.seq,
                "ts": entry.ts,
                "kind": entry.kind,
                "worker_id": entry.worker_id,
                "request_id": entry.request_id,
                "detail": self._decrypt_detail(entry.detail, key),
            })
        return out

    # -- erasure ------------------------------------------------------------

    def erase(self, worker_id: str, request_id: str) -> None:
        if self._store.get_request(request_id) is not None:
            return  # idempotent retry: already processed
        if not self._store.is_known_worker(worker_id):
            raise ValueError(f"worker {worker_id!r} was never registered")
        self._keys.delete(worker_id)            # crypto-shredding
        self._store.delete_profile(worker_id)   # current profile ceases to exist
        self._store.add_erasure(worker_id, request_id)
        self._store.append_audit("erase", worker_id, request_id, {
            "worker_id": worker_id,
            "fact": "pii_erased",
        })
        self._store.record_request(request_id, "erase", {"worker_id": worker_id})

    # -- backup & restore -----------------------------------------------------

    def backup(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"backup-{stamp}.db"
        self._store.export_backup(os.path.join(self._workdir, _BACKUP_DIR, name))
        return name

    def list_backups(self) -> list:
        path = os.path.join(self._workdir, _BACKUP_DIR)
        return sorted(f for f in os.listdir(path) if f.endswith(".db"))

    def restore(self, backup_name: str, request_id: str) -> None:
        if self._store.get_request(request_id) is not None:
            return  # idempotent retry: must not clobber later changes
        path = os.path.join(self._workdir, _BACKUP_DIR, backup_name)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"backup {backup_name!r} not found")
        data = Store.load_backup(path)
        erased = self._store.erased_ids()
        profiles = [
            ProfileRow(
                worker_id=p["worker_id"], name_enc=p["name_enc"], ssn_enc=p["ssn_enc"],
                company=p["company"], state=p["state"], version=p["version"],
                updated_at=p["updated_at"],
            )
            for p in data["profiles"] if p["worker_id"] not in erased
        ]
        self._store.replace_profiles(profiles)
        self._store.merge_audit(data["audit"])
        self._store.merge_requests(data["requests"])
        self._store.append_audit("restore", None, request_id, {"backup": backup_name})
        self._store.record_request(request_id, "restore", {"backup": backup_name})

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _enc_snapshot(key: str, name: str, ssn: str, company: str, state: str) -> dict:
        return {
            "name": crypto.encrypt(key, name),
            "ssn": crypto.encrypt(key, ssn),
            "company": company,
            "state": state,
        }

    @staticmethod
    def _decrypt_detail(detail: dict, key: Optional[str]) -> dict:
        out = {}
        for field, value in detail.items():
            if isinstance(value, dict):
                out[field] = PrivacyErasureLibrary._decrypt_detail(value, key)
            elif field in _PII_FIELDS and isinstance(value, str):
                out[field] = crypto.decrypt(key, value) if key else None
            else:
                out[field] = value
        return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
