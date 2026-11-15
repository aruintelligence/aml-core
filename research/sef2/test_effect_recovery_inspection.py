"""Recovery inspection tests: classification never permits a second effect."""
import os
import sqlite3
import tempfile
import unittest
from effect_authority import EffectAuthority
from effect_recovery_inspection import classify_recovery
from independent_effect_reservations import IndependentEffectReservations
# The SEF2 workflow explicitly runs this module; include the receipt-chain
# test class until the workflow invokes its own test module directly.
from test_reservation_receipt_chain import ReservationReceiptChainTests
from test_atomic_receipt_reservations import AtomicReceiptReservationTests
from test_witnessed_receipt_history import WitnessedReceiptHistoryTests

def effect(op="op-1"):
    return {"operation_id": op, "kind": "fixture:write",
            "target": "fixture:protected", "value": 4}

class RecoveryInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = os.path.join(self.temp.name, "effects.sqlite")
        self.reservations = IndependentEffectReservations(
            os.path.join(self.temp.name, "reservations.sqlite"), "authority-a")
        self.authority = EffectAuthority(
            self.db, lambda *args: True, reserve_operation=self.reservations.reserve)

    def test_invalid_operation_id_is_unknown_without_reading_stores(self):
        class ExplodingStore:
            def inspect(self, operation_id):
                raise AssertionError("invalid identifier reached storage")
        for invalid in ("", "x" * 129, "bad\nline", "nonascii-\u00e9", 42, None):
            self.assertEqual(classify_recovery(self.db, ExplodingStore(), invalid), "UNKNOWN")

    def test_absent_operation_is_not_authorized_by_classifier(self):
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "ABSENT")

    def test_recovery_path_with_spaces_and_query_characters(self):
        unusual = os.path.join(self.temp.name, "effect #1? backup.sqlite")
        authority = EffectAuthority(
            unusual, lambda *args: True, reserve_operation=self.reservations.reserve)
        self.assertEqual(authority.commit(effect(), 0), "APPLIED")
        self.assertEqual(classify_recovery(unusual, self.reservations, "op-1"), "COMMITTED")

    def test_committed_operation(self):
        self.assertEqual(self.authority.commit(effect(), 0), "APPLIED")
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "COMMITTED")

    def test_crash_after_reservation_is_stranded_and_cannot_replay(self):
        self.assertTrue(self.reservations.reserve("op-1", "a" * 64, 0))
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "STRANDED")
        self.assertEqual(self.authority.commit(effect(), 0), "DENIED")

    def test_missing_reservation_evidence_is_conflict(self):
        self.assertEqual(self.authority.commit(effect(), 0), "APPLIED")
        with sqlite3.connect(self.reservations.path) as db:
            db.execute("DELETE FROM reservations WHERE operation_id='op-1'")
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "CONFLICT")

    def test_changed_effect_digest_is_conflict(self):
        self.assertEqual(self.authority.commit(effect(), 0), "APPLIED")
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE effects SET digest=? WHERE operation_id='op-1'", ("b" * 64,))
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "CONFLICT")

    def test_missing_effect_database_is_unknown(self):
        os.unlink(self.db)
        self.assertEqual(classify_recovery(self.db, self.reservations, "op-1"), "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
