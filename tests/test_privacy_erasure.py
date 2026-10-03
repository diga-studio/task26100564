import os
import sqlite3
import tempfile
import unittest

from privacy_erasure import PrivacyErasureLibrary


def read_all_files(root):
    """Concatenate bytes of every file under root (simulates an attacker
    holding all managed files and all historical backups)."""
    blob = b""
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            with open(os.path.join(dirpath, f), "rb") as fh:
                blob += fh.read()
    return blob


class ErasureTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = PrivacyErasureLibrary(self.dir)

    def tearDown(self):
        self.lib.close()

    def test_multiple_renames_then_erase(self):
        # w1: multiple name + SSN changes
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        self.lib.update("w1", name="Alicia", ssn="222-22-2222")
        self.lib.update("w1", name="Ally", ssn="333-33-3333", company="Beta", state="NY")
        # w2: another worker whose PII must survive
        self.lib.register("w2", "Bob", "999-88-7777", "Acme", "CA")
        self.lib.update("w2", name="Bobby")

        self.lib.erase("w1", "erase-req-1")

        # current profile gone
        self.assertIsNone(self.lib.get_profile("w1"))
        # workerID and non-PII still readable in audit history
        history = self.lib.get_history("w1")
        self.assertEqual(len(history), 4)  # register + 2 updates + erase
        self.assertEqual(history[0]["worker_id"], "w1")
        self.assertEqual(history[2]["detail"]["after"]["company"], "Beta")
        self.assertEqual(history[2]["detail"]["after"]["state"], "NY")
        # all historical PII of w1 unreadable
        for entry in history:
            for side in ("before", "after"):
                snap = entry["detail"].get(side)
                if snap:
                    self.assertIsNone(snap["name"])
                    self.assertIsNone(snap["ssn"])
        # erase fact recorded
        self.assertEqual(history[-1]["kind"], "erase")
        self.assertEqual(history[-1]["request_id"], "erase-req-1")
        # other worker fully intact, current + history
        self.assertEqual(self.lib.get_profile("w2")["name"], "Bobby")
        w2h = self.lib.get_history("w2")
        self.assertEqual(w2h[0]["detail"]["after"]["ssn"], "999-88-7777")
        self.assertEqual(w2h[1]["detail"]["before"]["name"], "Bob")
        # erased workerID can never be re-registered
        with self.assertRaises(ValueError):
            self.lib.register("w1", "X", "0", "C", "CA")
        # no file anywhere (state.db, keystore.db, backups) contains w1 PII
        blob = read_all_files(self.dir)
        for pii in (b"Alice", b"Alicia", b"Ally",
                    b"111-11-1111", b"222-22-2222", b"333-33-3333"):
            self.assertNotIn(pii, blob)
        # w2 PII is recoverable (sanity: blob check is meaningful)
        self.assertEqual(self.lib.get_history("w2")[0]["detail"]["after"]["name"], "Bob")

    def test_erase_idempotent_request_id(self):
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        self.lib.erase("w1", "req-42")
        self.lib.erase("w1", "req-42")  # retry with same id
        self.lib.erase("w1", "req-42")
        erases = [e for e in self.lib.get_history("w1") if e["kind"] == "erase"]
        self.assertEqual(len(erases), 1)

    def test_erase_unknown_worker_rejected(self):
        with self.assertRaises(ValueError):
            self.lib.erase("nobody", "req-x")


class BackupRestoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lib = PrivacyErasureLibrary(self.dir)

    def tearDown(self):
        self.lib.close()

    def test_interleaved_backup_modify_erase_restore(self):
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        self.lib.register("w2", "Bob", "999-88-7777", "Acme", "WA")
        b1 = self.lib.backup()

        self.lib.update("w1", name="Alicia")          # after b1
        self.lib.erase("w2", "erase-w2")              # w2 erased after b1
        b2 = self.lib.backup()

        self.lib.update("w1", ssn="222-22-2222")      # after b2
        self.lib.register("w3", "Carol", "555-55-5555", "Gamma", "NV")

        # restore b1: w1 back to backup state, w2 filtered out (erased),
        # w3 (not in backup) disappears; audit ledger keeps growing.
        audit_before = len(self.lib._store.list_audit())
        w1_entries_before = {e["entry_id"] for e in self.lib.get_history("w1")}
        self.lib.restore(b1, "restore-1")

        p1 = self.lib.get_profile("w1")
        self.assertEqual(p1["name"], "Alice")
        self.assertEqual(p1["ssn"], "111-11-1111")
        self.assertIsNone(self.lib.get_profile("w2"))   # erased, stays gone
        self.assertIsNone(self.lib.get_profile("w3"))   # not in backup
        # pre-restore audit entries preserved + restore entry appended
        self.assertGreater(len(self.lib._store.list_audit()), audit_before)
        w1_entries_after = {e["entry_id"] for e in self.lib.get_history("w1")}
        self.assertTrue(w1_entries_before <= w1_entries_after)
        # w2 was erased: even though b1 contained w2, its PII is gone everywhere
        blob = read_all_files(self.dir)
        self.assertNotIn(b"999-88-7777", blob)
        self.assertNotIn(b"Bobby", blob)
        # w2 history entries survive (non-PII), PII redacted
        w2h = self.lib.get_history("w2")
        self.assertTrue(any(e["kind"] == "erase" for e in w2h))
        self.assertIsNone(w2h[0]["detail"]["after"]["ssn"])

        # restore b2: w1 has the b2-era name, w2 still filtered
        self.lib.restore(b2, "restore-2")
        self.assertEqual(self.lib.get_profile("w1")["name"], "Alicia")
        self.assertIsNone(self.lib.get_profile("w2"))

    def test_erase_after_restore_when_profile_absent(self):
        # w1 registered, backed up, then erased is NOT the case here:
        # w1's profile disappears via restore of a pre-registration backup,
        # but history still holds PII -> erase must still work.
        b0 = self.lib.backup()                        # empty state
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        self.lib.update("w1", name="Alicia")
        self.lib.restore(b0, "restore-empty")         # profile now gone
        self.assertIsNone(self.lib.get_profile("w1"))
        # history (with PII) survived the restore
        self.assertEqual(self.lib.get_history("w1")[1]["detail"]["after"]["name"], "Alicia")
        # erase still possible because w1 was once registered
        self.lib.erase("w1", "erase-late")
        for entry in self.lib.get_history("w1"):
            for side in ("before", "after"):
                snap = entry["detail"].get(side)
                if snap:
                    self.assertIsNone(snap["name"])
        blob = read_all_files(self.dir)
        self.assertNotIn(b"Alice", blob)
        self.assertNotIn(b"111-11-1111", blob)

    def test_duplicate_restore_request_does_not_clobber(self):
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        b1 = self.lib.backup()
        self.lib.restore(b1, "restore-req-9")
        # later changes after the successful restore
        self.lib.update("w1", name="Alicia", company="Beta")
        # duplicate submission of the same restore request id: no-op
        self.lib.restore(b1, "restore-req-9")
        p = self.lib.get_profile("w1")
        self.assertEqual(p["name"], "Alicia")
        self.assertEqual(p["company"], "Beta")
        # exactly one restore audit entry exists in the global ledger
        global_restore_entries = [
            e for e in self.lib._store.list_audit()
            if e.kind == "restore" and e.request_id == "restore-req-9"
        ]
        self.assertEqual(len(global_restore_entries), 1)

    def test_restore_preserves_audit_and_erasure_facts(self):
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        b1 = self.lib.backup()
        self.lib.erase("w1", "erase-1")
        self.lib.restore(b1, "restore-1")
        # erasure fact not rolled back: profile stays absent, re-register banned
        self.assertIsNone(self.lib.get_profile("w1"))
        with self.assertRaises(ValueError):
            self.lib.register("w1", "X", "0", "C", "CA")
        # erase audit entry survived the restore
        kinds = [e["kind"] for e in self.lib.get_history("w1")]
        self.assertIn("erase", kinds)

    def test_backup_excludes_keys_and_erasures(self):
        self.lib.register("w1", "Alice", "111-11-1111", "Acme", "CA")
        name = self.lib.backup()
        path = os.path.join(self.dir, "backups", name)
        tables = {r[0] for r in sqlite3.connect(path).execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(tables, {"profiles", "audit", "requests"})
        with open(path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"Alice", blob)
        self.assertNotIn(b"111-11-1111", blob)


if __name__ == "__main__":
    unittest.main()
