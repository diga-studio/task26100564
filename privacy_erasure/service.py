"""员工档案隐私擦除服务：上层直接调用的入口。

核心机制：crypto-shredding。PII（姓名、SSN）以每 worker 独立密钥加密后
入账；密钥保存在 keys/ 目录，绝不进入备份。擦除即销毁密钥，此后任何
账本副本与历史备份都无法再还原该 worker 的 PII。
"""

import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import crypto
from .errors import (
    BackupNotFoundError,
    PrivacyErasureError,
    WorkerExistsError,
    WorkerNotFoundError,
)
from .storage import PII_FIELDS, KeyStore, Ledger

ALL_FIELDS = ("name", "ssn", "company", "state")


class PrivacyErasureService:
    def __init__(self, data_dir) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir = self.data_dir / "backups"
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(self.data_dir / "ledger.sqlite3")
        self.keystore = KeyStore(self.data_dir / "keys")

    def close(self) -> None:
        self.ledger.close()

    # ---- 档案登记与更新 ----

    def register(self, worker_id: str, name: str, ssn: str,
                 company: str, state: str) -> None:
        if self.ledger.is_erased(worker_id):
            raise WorkerExistsError(f"worker {worker_id!r} 已被擦除，永久禁止再登记")
        if self.ledger.get_profile_row(worker_id) is not None:
            raise WorkerExistsError(f"worker {worker_id!r} 已存在")
        key = self.keystore.create(worker_id)
        name_enc = crypto.encrypt(key, name)
        ssn_enc = crypto.encrypt(key, ssn)
        self.ledger.insert_profile(worker_id, name_enc, ssn_enc, company, state)
        for field, value in (("name", name), ("ssn", ssn)):
            self.ledger.append_audit(op="register", worker_id=worker_id, field=field,
                                     new_pii_enc=crypto.encrypt(key, value))
        for field, value in (("company", company), ("state", state)):
            self.ledger.append_audit(op="register", worker_id=worker_id, field=field,
                                     new_value=value)
        self.ledger.record_known(worker_id)
        self.ledger.commit()

    def update(self, worker_id: str, *, name: Optional[str] = None,
               ssn: Optional[str] = None, company: Optional[str] = None,
               state: Optional[str] = None) -> None:
        row = self.ledger.get_profile_row(worker_id)
        if row is None:
            raise WorkerNotFoundError(f"worker {worker_id!r} 不存在")
        key = self.keystore.load(worker_id)
        current = {
            "name": crypto.decrypt(key, row["name_enc"]),
            "ssn": crypto.decrypt(key, row["ssn_enc"]),
            "company": row["company"],
            "state": row["state"],
        }
        new = dict(current)
        for field, value in (("name", name), ("ssn", ssn),
                             ("company", company), ("state", state)):
            if value is not None:
                new[field] = value
        for field in ALL_FIELDS:
            if new[field] != current[field]:
                if field in PII_FIELDS:
                    self.ledger.append_audit(
                        op="update", worker_id=worker_id, field=field,
                        old_pii_enc=crypto.encrypt(key, current[field]),
                        new_pii_enc=crypto.encrypt(key, new[field]))
                else:
                    self.ledger.append_audit(
                        op="update", worker_id=worker_id, field=field,
                        old_value=current[field], new_value=new[field])
        self.ledger.update_profile(
            worker_id,
            crypto.encrypt(key, new["name"]), crypto.encrypt(key, new["ssn"]),
            new["company"], new["state"])
        self.ledger.commit()

    # ---- 读取 ----

    def get_profile(self, worker_id: str) -> Optional[dict]:
        row = self.ledger.get_profile_row(worker_id)
        if row is None:
            return None
        key = self.keystore.load(worker_id)
        return {
            "worker_id": worker_id,
            "name": crypto.decrypt(key, row["name_enc"]),
            "ssn": crypto.decrypt(key, row["ssn_enc"]),
            "company": row["company"],
            "state": row["state"],
            "updated_at": row["updated_at"],
        }

    def get_history(self, worker_id: str) -> List[dict]:
        return self._decode_audit(self.ledger.get_audit_rows(worker_id),
                                  self.keystore.load(worker_id))

    def get_audit_log(self) -> List[dict]:
        """全量审计账本（含恢复等全局事件）；已擦除 worker 的 PII 显示为不可读。"""
        return self._decode_audit(self.ledger.get_all_audit_rows(), None)

    def _decode_audit(self, rows, key) -> List[dict]:
        history = []
        for row in rows:
            row_key = key
            if row_key is None and row["worker_id"] is not None:
                row_key = self.keystore.load(row["worker_id"])
            entry = {
                "seq": row["seq"], "ts": row["ts"], "op": row["op"],
                "request_id": row["request_id"], "worker_id": row["worker_id"],
                "field": row["field"], "detail": row["detail"],
            }
            if row["field"] in PII_FIELDS:
                entry["pii"] = True
                if row_key is None:
                    entry.update(old=None, new=None, readable=False)
                else:
                    entry.update(
                        old=crypto.decrypt(row_key, row["old_pii_enc"]) if row["old_pii_enc"] else None,
                        new=crypto.decrypt(row_key, row["new_pii_enc"]) if row["new_pii_enc"] else None,
                        readable=True)
            else:
                entry.update(pii=False, old=row["old_value"], new=row["new_value"],
                             readable=True)
            history.append(entry)
        return history

    # ---- 擦除 ----

    def erase(self, request_id: str, worker_id: str) -> None:
        if self.ledger.request_status(request_id) is not None:
            return  # 相同请求标识重试：幂等，无新业务效果、无新审计项
        if not self.ledger.is_known(worker_id):
            raise WorkerNotFoundError(f"worker {worker_id!r} 从未登记")
        if self.ledger.is_erased(worker_id):
            self.ledger.record_request(request_id, "erase", worker_id)
            self.ledger.commit()
            return
        self.keystore.destroy(worker_id)          # 销毁密钥：全部历史 PII 不可恢复
        self.ledger.delete_profile(worker_id)     # 当前档案不再存在
        self.ledger.record_erasure(worker_id, request_id)  # 永久禁止再登记
        self.ledger.append_audit(op="erase", request_id=request_id, worker_id=worker_id,
                                 detail={"fact": "pii_erased", "worker_id": worker_id})
        self.ledger.record_request(request_id, "erase", worker_id)
        self.ledger.commit()

    # ---- 备份与恢复 ----

    def create_backup(self) -> Path:
        self.ledger.commit()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%f")
        dest = self.backups_dir / f"backup-{stamp}.sqlite3"
        src = sqlite3.connect(str(self.ledger.db_path))
        try:
            dst = sqlite3.connect(str(dest))
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        return dest

    def _validate_backup_path(self, backup_path) -> Path:
        path = Path(backup_path).resolve()
        root = self.backups_dir.resolve()
        if root not in path.parents or not path.is_file():
            raise BackupNotFoundError(f"备份 {backup_path!r} 不在受管备份目录内或不存在")
        return path

    def restore(self, request_id: str, backup_path) -> None:
        if self.ledger.request_status(request_id) is not None:
            return  # 已完成的恢复请求：幂等，不覆盖其后发生的新变更
        path = self._validate_backup_path(backup_path)
        try:
            src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            src.row_factory = sqlite3.Row
            rows = [dict(r) for r in
                    src.execute("SELECT * FROM profiles").fetchall()]
        except sqlite3.Error as exc:
            raise PrivacyErasureError(f"无效备份文件: {exc}") from exc
        finally:
            src.close()
        erased = set(self.ledger.erased_worker_ids())
        kept = [r for r in rows if r["worker_id"] not in erased]
        skipped = sorted(r["worker_id"] for r in rows if r["worker_id"] in erased)
        # 仅替换业务状态表；审计账本、擦除登记、请求记录均不回滚
        self.ledger.replace_profiles(kept)
        self.ledger.append_audit(op="restore", request_id=request_id,
                                 detail={"fact": "backup_restored",
                                         "backup": path.name,
                                         "restored_workers": len(kept),
                                         "skipped_erased": skipped})
        self.ledger.record_request(request_id, "restore", None)
        self.ledger.commit()
