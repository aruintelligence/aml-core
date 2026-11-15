"""Adversarial regression tests for the synthetic effect authority."""
import os
import sqlite3
import tempfile
import unittest
from effect_authority import EffectAuthority

def effect(operation="op-1", value=7):
    return {"operation_id":operation,"kind":"fixture:write","target":"fixture:protected","value":value}

class EffectAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "effects.sqlite")

    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT operation_id,value FROM effects ORDER BY operation_id").fetchall()

    def test_denied_before_effect(self):
        authority = EffectAuthority(self.path, lambda *args: False)
        self.assertEqual(authority.commit(effect(), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_commit_once_and_replay_after_restart(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertEqual(authority.commit(effect(), 1), "APPLIED")
        restarted = EffectAuthority(self.path, lambda *args: False)
        self.assertEqual(restarted.commit(effect(), 1), "ALREADY_APPLIED")
        self.assertEqual(restarted.commit(effect(value=8), 1), "DENIED")
        self.assertEqual(self.rows(), [("op-1",7)])

    def test_invalid_generation_and_boolean_confusion(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertEqual(authority.commit(effect(), True), "DENIED")
        self.assertEqual(authority.commit(effect(value=True), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_policy_generation_is_passed_to_trusted_authority(self):
        seen = []
        def authorize(op, digest, generation):
            seen.append((op,digest,generation))
            return generation == 3
        authority = EffectAuthority(self.path, authorize)
        self.assertEqual(authority.commit(effect(), 2), "DENIED")
        self.assertEqual(authority.commit(effect(), 3), "APPLIED")
        self.assertEqual([x[2] for x in seen], [2,3])

    def test_authority_must_return_exact_true(self):
        authority = EffectAuthority(self.path, lambda *args: 1)
        self.assertEqual(authority.commit(effect(), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_stale_generation_rejected_even_with_permissive_authorizer(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertTrue(authority.advance_policy_floor(4))
        self.assertEqual(authority.commit(effect(), 3), "DENIED")
        self.assertEqual(authority.commit(effect(), 4), "APPLIED")
        self.assertEqual(self.rows(), [("op-1", 7)])

    def test_floor_never_decreases_across_restart(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertTrue(authority.advance_policy_floor(9))
        self.assertTrue(authority.advance_policy_floor(2))
        restarted = EffectAuthority(self.path, lambda *args: True)
        self.assertEqual(restarted.commit(effect(), 8), "DENIED")
        self.assertEqual(restarted.commit(effect(), 9), "APPLIED")

    def test_floor_rejects_invalid_values(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertFalse(authority.advance_policy_floor(True))
        self.assertFalse(authority.advance_policy_floor(-1))
        self.assertEqual(authority.commit(effect(), 0), "APPLIED")

    def test_authorizer_exception_denies_without_effect(self):
        def broken(*args):
            raise RuntimeError("authority offline")
        authority = EffectAuthority(self.path, broken)
        self.assertEqual(authority.commit(effect(), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_invalid_effect_cannot_reach_authorizer(self):
        def unexpected(*args):
            raise AssertionError("called")
        authority = EffectAuthority(self.path, unexpected)
        self.assertEqual(authority.commit({"operation_id":"x"}, 1), "DENIED")

if __name__ == "__main__":
    unittest.main()
