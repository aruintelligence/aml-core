"""Rollback attack regression for independently persisted effect reservations."""
import os
import shutil
import sqlite3
import tempfile
import unittest
from effect_authority import EffectAuthority
from independent_effect_reservations import IndependentEffectReservations

def effect(operation_id="op-1", value=7):
    return {"operation_id": operation_id, "kind": "fixture:write",
            "target": "fixture:protected", "value": value}

class IndependentReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.effects = os.path.join(self.tmp.name, "effects.sqlite")
        self.snapshot = os.path.join(self.tmp.name, "snapshot.sqlite")
        self.reservations = os.path.join(self.tmp.name, "independent.sqlite")
        self.store = IndependentEffectReservations(self.reservations, "authority-a")

    def authority(self):
        return EffectAuthority(self.effects, lambda *args: True,
                               reserve_operation=self.store.reserve)

    def test_snapshot_rollback_cannot_replay_reserved_effect(self):
        authority = self.authority()
        shutil.copyfile(self.effects, self.snapshot)
        self.assertEqual(authority.commit(effect(), 0), "APPLIED")
        shutil.copyfile(self.snapshot, self.effects)
        restarted = self.authority()
        self.assertEqual(restarted.commit(effect(), 0), "DENIED")
        with sqlite3.connect(self.effects) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 0)

    def test_reservation_survives_store_restart(self):
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 0))
        self.store = IndependentEffectReservations(
            self.reservations, "authority-a", require_existing=True)
        self.assertFalse(self.store.reserve("op-1", "a" * 64, 0))
        self.assertFalse(self.store.reserve("op-1", "b" * 64, 0))

    def test_missing_reservation_store_fails_strict_restart(self):
        with self.assertRaises(ValueError):
            IndependentEffectReservations(os.path.join(self.tmp.name, "absent"),
                                          "authority-a", require_existing=True)

    def test_authorizer_denial_never_reserves(self):
        authority = EffectAuthority(self.effects, lambda *args: False,
                                    reserve_operation=self.store.reserve)
        self.assertEqual(authority.commit(effect(), 0), "DENIED")
        self.assertTrue(self.store.reserve("op-1", "a" * 64, 0))

    def test_reservation_failure_prevents_effect(self):
        authority = EffectAuthority(self.effects, lambda *args: True,
                                    reserve_operation=lambda *args: False)
        self.assertEqual(authority.commit(effect(), 0), "DENIED")
        with sqlite3.connect(self.effects) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 0)

if __name__ == "__main__":
    unittest.main()
