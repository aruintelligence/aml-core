"""Adversarial regression tests for the synthetic effect authority."""
import os
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Event
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

    def test_strict_restart_refuses_absent_or_empty_database(self):
        with self.assertRaises(ValueError):
            EffectAuthority(self.path, lambda *args: True, require_existing=True)
        with open(self.path, "wb"):
            pass
        with self.assertRaises(ValueError):
            EffectAuthority(self.path, lambda *args: True, require_existing=True)
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertTrue(authority.advance_policy_floor(7))
        restarted = EffectAuthority(self.path, lambda *args: True, require_existing=True)
        self.assertEqual(restarted.commit(effect(), 6), "DENIED")

    def test_restart_refuses_deleted_policy_floor_row(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertTrue(authority.advance_policy_floor(11))
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM policy_floor WHERE singleton=1")
        with self.assertRaises(ValueError):
            EffectAuthority(self.path, lambda *args: True)

    def test_restart_refuses_deleted_policy_table(self):
        EffectAuthority(self.path, lambda *args: True)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE policy_floor")
        with self.assertRaises(ValueError):
            EffectAuthority(self.path, lambda *args: True)

    def test_restart_refuses_deleted_effects_table(self):
        EffectAuthority(self.path, lambda *args: True)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE effects")
        with self.assertRaises(ValueError):
            EffectAuthority(self.path, lambda *args: True)

    def test_restart_preserves_existing_policy_floor(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        self.assertTrue(authority.advance_policy_floor(11))
        restarted = EffectAuthority(self.path, lambda *args: True)
        self.assertEqual(restarted.commit(effect(), 10), "DENIED")
        self.assertEqual(restarted.commit(effect(), 11), "APPLIED")

    def test_missing_policy_floor_row_never_acknowledges_revocation(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM policy_floor WHERE singleton=1")
        self.assertFalse(authority.advance_policy_floor(7))
        self.assertEqual(authority.commit(effect(), 7), "DENIED")
        self.assertEqual(self.rows(), [])

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

    def test_concurrent_identical_requests_apply_once(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: authority.commit(effect(), 1), range(32)))
        self.assertEqual(results.count("APPLIED"), 1)
        self.assertEqual(results.count("ALREADY_APPLIED"), 31)
        self.assertEqual(self.rows(), [("op-1", 7)])

    def test_concurrent_conflicting_requests_cannot_overwrite(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda i: authority.commit(effect(value=i % 2 + 1), 1), range(24)))
        self.assertEqual(results.count("APPLIED"), 1)
        self.assertEqual(results.count("DENIED"), 12)
        self.assertEqual(results.count("ALREADY_APPLIED"), 11)
        self.assertEqual(len(self.rows()), 1)

    def test_revocation_serializes_with_inflight_execution(self):
        entered = Event()
        release = Event()
        def authorize(*args):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("authorization timed out")
            return True
        authority = EffectAuthority(self.path, authorize)
        with ThreadPoolExecutor(max_workers=2) as pool:
            committing = pool.submit(authority.commit, effect(), 1)
            self.assertTrue(entered.wait(timeout=5))
            revoking = pool.submit(authority.advance_policy_floor, 2)
            release.set()
            self.assertEqual(committing.result(timeout=10), "APPLIED")
            self.assertTrue(revoking.result(timeout=10))
        self.assertEqual(authority.commit(effect("op-2"), 1), "DENIED")
        self.assertEqual(self.rows(), [("op-1", 7)])

    def test_external_checkpoint_detects_rolled_back_local_floor(self):
        external = [0]
        authority = EffectAuthority(self.path, lambda *args: True, lambda: external[0])
        self.assertTrue(authority.advance_policy_floor(3))
        external[0] = 5
        self.assertEqual(authority.commit(effect(), 5), "DENIED")
        self.assertEqual(self.rows(), [])
        self.assertTrue(authority.advance_policy_floor(5))
        self.assertEqual(authority.commit(effect(), 5), "APPLIED")

    def test_unavailable_external_checkpoint_fails_closed(self):
        def unavailable():
            raise ConnectionError("checkpoint offline")
        authority = EffectAuthority(self.path, lambda *args: True, unavailable)
        self.assertEqual(authority.commit(effect(), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_malformed_external_checkpoint_fails_closed(self):
        for value in (True, -1, None, "5"):
            authority = EffectAuthority(self.path, lambda *args: True, lambda value=value: value)
            self.assertEqual(authority.commit(effect(), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_external_checkpoint_cannot_be_a_static_untrusted_value(self):
        with self.assertRaises(TypeError):
            EffectAuthority(self.path, lambda *args: True, external_floor=7)

    def test_operation_identifier_is_bounded_and_printable(self):
        authority = EffectAuthority(self.path, lambda *args: True)
        for identifier in ("x" * 129, "op\\nattack", "op\\x00attack", "op-☃"):
            self.assertEqual(authority.commit(effect(identifier), 1), "DENIED")
        self.assertEqual(self.rows(), [])

    def test_invalid_effect_cannot_reach_authorizer(self):
        def unexpected(*args):
            raise AssertionError("called")
        authority = EffectAuthority(self.path, unexpected)
        self.assertEqual(authority.commit({"operation_id":"x"}, 1), "DENIED")

if __name__ == "__main__":
    unittest.main()
