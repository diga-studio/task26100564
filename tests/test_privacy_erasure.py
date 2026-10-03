import tempfile
import unittest
from pathlib import Path

from privacy_erasure import (
    BackupNotFoundError,
    PrivacyErasureService,
    WorkerExistsError,
    WorkerNotFoundError,
)


def all_files_bytes(root: Path) -> bytes:
    blob = bytearray()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            blob.extend(p.read_bytes())
    return bytes(blob)


class ErasureTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.svc = PrivacyErasureService(self.dir)

    def tearDown(self):
        self.svc.close()
        self._tmp.cleanup()

    def test_multi_rename_then_erase(self):
        svc = self.svc
        # 其他 worker：擦除后其当前及历史 PII 仍须完整可读
        svc.register("w-other", "Carol", "333-33-3333", "Globex", "TX")
        svc.update("w-other", ssn="333-33-3334")

        svc.register("w1", "Alice", "111-11-1111", "ACME", "CA")
        svc.update("w1", name="Alicia", ssn="111-11-1112")
        svc.update("w1", name="Ally", ssn="111-11-1113", company="Initech", state="NY")

        # 擦除前：历史变更中的 PII 完整可读
        history = svc.get_history("w1")
        names = [(e["old"], e["new"]) for e in history if e["field"] == "name"]
        self.assertIn((None, "Alice"), names)
        self.assertIn(("Alice", "Alicia"), names)
        self.assertIn(("Alicia", "Ally"), names)
        ssns = [(e["old"], e["new"]) for e in history if e["field"] == "ssn"]
        self.assertIn(("111-11-1112", "111-11-1113"), ssns)

        svc.erase("req-erase-1", "w1")

        # 当前档案不存在；workerID 永久不能再次登记
        self.assertIsNone(svc.get_profile("w1"))
        with self.assertRaises(WorkerExistsError):
            svc.register("w1", "X", "9", "Y", "ZZ")

        # 审计中 workerID 与非 PII 内容仍可读；PII 不可读
        history = svc.get_history("w1")
        self.assertTrue(any(e["op"] == "erase" and e["request_id"] == "req-erase-1"
                            for e in history))
        company_changes = [(e["old"], e["new"]) for e in history if e["field"] == "company"]
        self.assertIn(("ACME", "Initech"), company_changes)
        state_changes = [(e["old"], e["new"]) for e in history if e["field"] == "state"]
        self.assertIn(("CA", "NY"), state_changes)
        for e in history:
            if e["pii"]:
                self.assertFalse(e["readable"])
                self.assertIsNone(e["old"])
                self.assertIsNone(e["new"])
            self.assertEqual(e["worker_id"], "w1")

        # 即使持有全部受管文件与全部历史备份，也找不到任何历史 PII 明文
        svc.create_backup()
        blob = all_files_bytes(self.dir)
        for pii in ("Alice", "Alicia", "Ally",
                    "111-11-1111", "111-11-1112", "111-11-1113"):
            self.assertNotIn(pii.encode("utf-8"), blob)

        # 其他 worker 的当前及历史 PII 完整可读
        other = svc.get_profile("w-other")
        self.assertEqual(other["ssn"], "333-33-3334")
        other_history = svc.get_history("w-other")
        other_ssns = [(e["old"], e["new"]) for e in other_history if e["field"] == "ssn"]
        self.assertIn(("333-33-3333", "333-33-3334"), other_ssns)

    def test_interleaved_backup_modify_erase_restore(self):
        svc = self.svc
        svc.register("w1", "Alice", "111-11-1111", "ACME", "CA")
        backup1 = svc.create_backup()                      # 含 w1

        svc.register("w2", "Bob", "222-22-2222", "Globex", "TX")
        svc.update("w1", name="Alicia")
        backup2 = svc.create_backup()                      # 含 w1(Alicia), w2

        svc.erase("req-erase-w1", "w1")                    # 擦除 w1
        svc.update("w2", company="Hooli")
        backup3 = svc.create_backup()                      # 仅 w2(Hooli)

        # 恢复到 backup1：业务状态 = backup1 剔除已擦除的 w1 = 空
        svc.restore("req-restore-1", backup1)
        self.assertIsNone(svc.get_profile("w1"))
        self.assertIsNone(svc.get_profile("w2"))
        # 审计账本不回滚：w1 的擦除事实与 w2 的全部历史仍在
        self.assertTrue(any(e["op"] == "erase" for e in svc.get_history("w1")))
        log = svc.get_audit_log()
        self.assertTrue(any(e["op"] == "restore" and e["request_id"] == "req-restore-1"
                            for e in log))
        w2_company = [(e["old"], e["new"]) for e in svc.get_history("w2")
                      if e["field"] == "company"]
        self.assertIn(("Globex", "Hooli"), w2_company)

        # 当前档案已不存在、但历史中仍有 PII 的 worker（w2 被恢复剔除）仍可擦除
        svc.restore("req-restore-2", backup2)              # 恢复 w2(Bob, Globex)
        self.assertEqual(svc.get_profile("w2")["name"], "Bob")
        svc.restore("req-restore-3", backup1)              # w2 当前档案又消失
        self.assertIsNone(svc.get_profile("w2"))
        svc.erase("req-erase-w2", "w2")                    # 历史 PII 仍可擦除
        w2_history = svc.get_history("w2")
        self.assertTrue(all(not e["pii"] or not e["readable"] for e in w2_history))
        blob = all_files_bytes(self.dir)
        self.assertNotIn("Bob".encode(), blob)
        self.assertNotIn("222-22-2222".encode(), blob)

        # 重复提交已成功的恢复请求：不覆盖其后发生的新变更
        svc.register("w3", "Dave", "444-44-4444", "ACME", "WA")
        svc.restore("req-restore-4", backup3)              # w1/w2 已擦除 → 空
        self.assertIsNone(svc.get_profile("w3"))
        svc.register("w4", "Erin", "555-55-5555", "Initech", "OR")
        svc.restore("req-restore-4", backup3)              # 幂等：不得再次覆盖
        self.assertEqual(svc.get_profile("w4")["name"], "Erin")
        restores = [e for e in svc.get_history("w4") if e["op"] == "restore"]
        self.assertEqual(len(restores), 0)                 # restore 审计只记一次（在全局账本）
        svc.restore("req-restore-5", backup3)
        self.assertIsNone(svc.get_profile("w4"))           # 新请求标识才生效

    def test_erase_idempotent_and_validation(self):
        svc = self.svc
        svc.register("w1", "Alice", "111-11-1111", "ACME", "CA")
        svc.erase("req-e", "w1")
        svc.erase("req-e", "w1")                           # 同标识重试：幂等
        erases = [e for e in svc.get_history("w1") if e["op"] == "erase"]
        self.assertEqual(len(erases), 1)                   # 只产生一条审计项
        with self.assertRaises(WorkerNotFoundError):
            svc.erase("req-e2", "never-registered")
        with self.assertRaises(WorkerNotFoundError):
            svc.update("w1", name="X")
        with self.assertRaises(WorkerNotFoundError):
            svc.update("ghost", name="X")
        with self.assertRaises(BackupNotFoundError):
            svc.restore("req-r", self.dir / "backups" / "missing.sqlite3")
        with self.assertRaises(BackupNotFoundError):
            svc.restore("req-r", "/etc/hosts")             # 不在受管备份目录内

    def test_duplicate_register_rejected(self):
        self.svc.register("w1", "Alice", "111-11-1111", "ACME", "CA")
        with self.assertRaises(WorkerExistsError):
            self.svc.register("w1", "Alice", "111-11-1111", "ACME", "CA")


if __name__ == "__main__":
    unittest.main()
