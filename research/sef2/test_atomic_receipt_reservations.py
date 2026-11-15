"""Atomic reservation and receipt-chain fixture tests."""
import os
import sqlite3
import tempfile
import unittest
from atomic_receipt_reservations import AtomicReceiptReservations
from reservation_receipt_chain import verify_reservation_chain, GENESIS

class AtomicReceiptReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "receipts.db")
        self.store = AtomicReceiptReservations(self.path, "authority-a")

    def test_reservation_and_receipt_are_atomic_and_ordered(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.store.reserve("op-2", "b" * 64, 2))
        head, entries = self.store.evidence()
        self.assertEqual(head[0], 2)
        self.assertTrue(verify_reservation_chain(entries, head[1], head[0]))
        self.assertFalse(self.store.reserve("op-1", "a" * 64, 1))
        self.assertEqual(self.store.evidence(), (head, entries))

    def test_invalid_reservation_does_not_advance_head(self):
        self.assertFalse(self.store.reserve("bad\\n", "a" * 64, 1) if False else
                         self.store.reserve("bad" + chr(10), "a" * 64, 1))
        self.assertEqual(self.store.evidence(), ((0, GENESIS), []))

    def test_tampered_receipt_prevents_future_reservation(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE receipt_reservations SET digest=? WHERE sequence=1", ("b" * 64,))
        self.assertFalse(self.store.reserve("op-2", "c" * 64, 2))

    def test_deleted_receipt_prevents_future_reservation(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM receipt_reservations WHERE sequence=1")
        self.assertFalse(self.store.reserve("op-2", "c" * 64, 2))

    def test_corrupted_stored_hash_prevents_future_reservation(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE receipt_reservations SET chain_hash=? WHERE sequence=1", ("b" * 64,))
        self.assertFalse(self.store.reserve("op-2", "c" * 64, 2))

    def test_restart_preserves_chain(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        reopened = AtomicReceiptReservations(self.path, "authority-a", require_existing=True)
        self.assertFalse(reopened.reserve("op-1", "a" * 64, 1))
        head, entries = reopened.evidence()
        self.assertTrue(verify_reservation_chain(entries, head[1], head[0]))

    def test_evidence_uses_read_only_database_connection(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        # A read-only SQLite URI must reject writes even when the OS user
        # could otherwise write to the underlying file.
        with sqlite3.connect(self.store.read_uri, uri=True) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM receipt_reservations")
        head, entries = self.store.evidence()
        self.assertTrue(verify_reservation_chain(entries, head[1], head[0]))

    def test_symlink_bootstrap_rejected_without_target_modification(self):
        target = os.path.join(self.tmp.name, "target.sqlite")
        with open(target, "wb") as out:
            out.write(b"sentinel-not-a-database")
        link = os.path.join(self.tmp.name, "link.sqlite")
        os.symlink(target, link)
        with self.assertRaises(ValueError):
            AtomicReceiptReservations(link, "authority-a")
        with open(target, "rb") as source:
            self.assertEqual(source.read(), b"sentinel-not-a-database")

    def test_live_ledger_replacement_denies_reservations(self):
        os.unlink(self.path)
        fresh = AtomicReceiptReservations(self.path, "authority-a")
        self.assertFalse(self.store.reserve("op-old", "a" * 64, 1))
        with self.assertRaises((OSError, ValueError)):
            self.store.evidence()
        self.assertTrue(fresh.reserve("op-new", "b" * 64, 1))

    def test_missing_existing_ledger_denied(self):
        with self.assertRaises(ValueError):
            AtomicReceiptReservations(self.path + ".missing", "authority-a", require_existing=True)

    def test_truncated_local_history_fails_external_head(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 1))
        first_head, first_entries = self.store.evidence()
        self.assertTrue(self.store.reserve("op-2", "b" * 64, 2))
        latest_head, _ = self.store.evidence()
        self.assertFalse(verify_reservation_chain(first_entries, latest_head[1], latest_head[0]))

if __name__ == "__main__":
    unittest.main()
