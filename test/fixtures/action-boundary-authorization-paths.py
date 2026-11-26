#!/usr/bin/env python3
"""Mission 1: bounded authorization-path regressions, not universal coverage.

Reuse synthetic setup/signing helpers, not the review class's inherited tests.
No production credentials, network effects or arbitrary provider execution.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
MODULES = ROOT / "pilots/action-boundary"
sys.path.insert(0, str(MODULES))
spec = importlib.util.spec_from_file_location("pilot003_review_helpers", Path(__file__).with_name("action-contract-pilot-003-review.py"))
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)
auth, atomic = review.auth, review.atomic


class AuthorizationPaths(unittest.TestCase):
    setUp = review.Review.setUp
    envelope = review.Review.envelope
    send = review.Review.send
    snapshot = review.Review.snapshot
    empty = review.Review.empty
    pair = review.Review.pair

    def call(self, e=None):
        return atomic.request_effect(self.db, self.pub, e or self.envelope())

    def expected(self, e):
        return {k: e["authorization"][k] for k in ("operation_id", "request_sha256", "destination")}

    def test_01_authorization_shape_and_type_guards(self):
        changes = [{"version": "wrong"}]
        for field in ("issuer", "principal", "policy_id", "operation_id", "destination", "effect"):
            changes.extend({field: value} for value in ("", "non-ASCII-雪", None, 1, []))
        changes.extend({"request_sha256": value} for value in ("a" * 63, "A" * 64, "g" * 64, 1, None))
        for field in ("policy_epoch", "expires_at_ms"):
            changes.extend({field: value} for value in (True, False, 1.5, "1", None))
        for change in changes:
            with self.subTest(change=change):
                p = self.send(self.envelope(**change))
                self.assertEqual(p.returncode, 2, p.stderr)
                self.empty()
        e = self.envelope()
        for value in (None, [], {}, {**e["authorization"], "extra": "field"}, {k:v for k,v in e["authorization"].items() if k != "issuer"}):
            with self.subTest(shape=value):
                with self.assertRaises((ValueError, TypeError)):
                    self.call({**e, "authorization": value})
                self.empty()
        self.call(e); self.pair(e)

    def test_02_signature_decode_length_and_verification_guards(self):
        e = self.envelope()
        invalid = [None, True, 7, {}, [], "", "雪", "?" * 88,
                   base64.b64encode(b"x" * 63).decode(), base64.b64encode(b"\0" * 64).decode(), e["signature"] + "!"]
        for signature in invalid:
            with self.subTest(signature_type=type(signature).__name__):
                with self.assertRaisesRegex(ValueError, "invalid_authorization_signature"):
                    self.call({**e, "signature": signature})
                self.empty()
        self.call(e); self.pair(e)

    def test_03_cli_parser_envelope_and_operator_argument_guards(self):
        valid = self.envelope()
        bad_inputs = [b"[]", b"null", b"true", b"{}", b"\xff", b"NaN", b"[", b" " * 65537,
                      json.dumps({**valid, "extra": True}).encode(), json.dumps({**valid, "request_bytes": []}).encode(),
                      json.dumps(valid).replace('"authorization":', '"authorization":{},"authorization":', 1).encode()]
        command = ["python3", str(MODULES / "atomic-authorized-provider-fixture.py"), self.db, "request", self.pub]
        for raw in bad_inputs:
            p = review.run(command, raw); self.assertEqual(p.returncode, 2, p.stderr); self.empty()
        for arguments in ([self.db, "unknown"], [self.db, "initialize"],
                          [self.db, "status", self.pub], [self.db, "request", self.pub, "--fault=unknown"],
                          [self.db, "request", self.pub, "--arbitrary=after_commit"]):
            p = review.run(["python3", str(MODULES / "atomic-authorized-provider-fixture.py"), *arguments], json.dumps(valid).encode())
            self.assertEqual(p.returncode, 2, p.stderr); self.empty()
        self.call(valid); self.pair(valid)

    def test_04_corrupt_pin_configuration_rejects_without_repair(self):
        e = self.envelope()
        with closing(sqlite3.connect(self.db)) as c:
            original = c.execute("SELECT * FROM config").fetchall()
        for rows in ([], original + original, [("0" * 64, 1)]):
            with closing(sqlite3.connect(self.db)) as c:
                c.execute("DELETE FROM config"); c.executemany("INSERT INTO config VALUES (?,?)", rows); c.commit()
            with self.assertRaisesRegex(ValueError, "untrusted_issuer_key"): self.call(e)
            with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute("SELECT * FROM config").fetchall(), rows)
            self.empty()
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("DELETE FROM config"); c.executemany("INSERT INTO config VALUES (?,?)", original); c.commit()
        self.call(e); self.pair(e)

    def test_05_invalid_initial_epoch_never_creates_authority(self):
        for value in (0, -1, True, False, 1.5, "1", None):
            selected = str(self.dir / "invalid-initialize.sqlite")
            before = set(self.dir.iterdir())
            with self.assertRaisesRegex(ValueError, "invalid_epoch"): auth.initialize(selected, self.pub, value)
            self.assertEqual(set(self.dir.iterdir()), before)
        self.empty()

    def test_06_initialization_cannot_reset_advanced_epoch(self):
        auth.set_epoch(self.db, 2)
        with self.assertRaisesRegex(ValueError, "trust_configuration_conflict"): atomic.initialize_provider(self.db, self.pub)
        with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute("SELECT policy_epoch FROM config").fetchall(), [(2,)])
        self.empty()
        e = self.envelope(policy_epoch=2); self.call(e); self.pair(e)

    def test_07_epoch_rejection_rolls_back_and_preserves_monotonic_state(self):
        auth.set_epoch(self.db, 2)
        for value in (2, 1, 0, -1, True, False, 2.5, "3", None):
            with self.assertRaisesRegex(ValueError, "epoch_must_increase"): auth.set_epoch(self.db, value)
            with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute("SELECT policy_epoch FROM config").fetchall(), [(2,)])
            self.empty()
        auth.set_epoch(self.db, 3)
        e = self.envelope(policy_epoch=3); self.call(e); self.pair(e)

    def test_08_repeated_revocation_is_idempotent_and_not_a_dispatch(self):
        e = self.envelope()
        auth.revoke(self.db, self.request["operation_id"]); auth.revoke(self.db, self.request["operation_id"])
        with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute("SELECT * FROM revoked").fetchall(), [(self.request["operation_id"],)])
        with self.assertRaisesRegex(ValueError, "authorization_revoked"): self.call(e)
        self.empty(); self.assertEqual(atomic.status(self.db, self.expected(e))["result"], "INCOMPLETE")

    def test_09_failed_helper_does_not_rollback_callers_prior_work(self):
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            c.execute("CREATE TABLE caller_work (value TEXT)"); c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO caller_work VALUES ('synthetic')"); e = self.envelope()
            with self.assertRaisesRegex(ValueError, "invalid_authorization_signature"):
                auth.consume_in_transaction(c, self.pub, e["authorization"], "AAAA", e["request_bytes"].encode())
            self.assertTrue(c.in_transaction); self.assertEqual(c.execute("SELECT * FROM caller_work").fetchall(), [("synthetic",)])
            self.empty()
            with closing(sqlite3.connect(self.db)) as observer: self.assertEqual(observer.execute("SELECT * FROM caller_work").fetchall(), [])
            c.rollback()
        self.empty()

    def test_10_second_provisional_consume_rejects_then_outer_rollback_restores(self):
        e = self.envelope()
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            c.execute("BEGIN IMMEDIATE")
            auth.consume_in_transaction(c, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
            with self.assertRaisesRegex(ValueError, "authorization_spent"):
                auth.consume_in_transaction(c, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
            self.assertTrue(c.in_transaction); self.assertEqual(c.execute("SELECT count(*) FROM claims").fetchone(), (1,)); self.empty()
            c.rollback()
        self.empty(); self.call(e); self.pair(e)

    def test_11_readonly_connection_cannot_upgrade_to_claim_writer(self):
        from sqlite_path import sqlite_file_uri
        e = self.envelope()
        with closing(sqlite3.connect(sqlite_file_uri(self.db, "ro"), uri=True, isolation_level=None)) as c:
            c.execute("BEGIN")
            with self.assertRaises(sqlite3.OperationalError):
                auth.consume_in_transaction(c, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
            self.assertTrue(c.in_transaction); c.rollback()
        self.empty(); self.call(e); self.pair(e)

    def test_12_autocommit_guard_precedes_key_access(self):
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            with self.assertRaisesRegex(ValueError, "authorization_transaction_required"):
                auth.consume_in_transaction(c, str(self.dir / "absent-key.pem"), None, None, None)
            self.assertFalse(c.in_transaction)
        self.empty()

    def test_13_sqlite_implicit_rollback_preserves_original_failure_and_pair_invariant(self):
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("CREATE TRIGGER fail_effect BEFORE INSERT ON effects BEGIN SELECT RAISE(ROLLBACK,'synthetic_effect_failure'); END"); c.commit()
        e = self.envelope()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "synthetic_effect_failure"): self.call(e)
        self.empty()
        with closing(sqlite3.connect(self.db)) as c: c.execute("DROP TRIGGER fail_effect"); c.commit()
        self.call(e); self.pair(e)

    def test_14_real_sql_trace_orders_full_sync_claim_effect_and_commit(self):
        statements = []; original_connect = sqlite3.connect
        def connect(*args, **kwargs):
            c = original_connect(*args, **kwargs); c.set_trace_callback(statements.append); return c
        e = self.envelope()
        with patch.object(atomic.sqlite3, "connect", side_effect=connect): self.call(e)
        positions = [next(i for i,s in enumerate(statements) if s.startswith(prefix)) for prefix in
                     ("PRAGMA synchronous=FULL", "BEGIN IMMEDIATE", "INSERT INTO claims", "INSERT INTO effects", "COMMIT")]
        self.assertEqual(positions, sorted(positions)); self.assertEqual(statements.count("COMMIT"), 1)
        self.pair(e)

    def test_15_exact_expiry_boundary_is_checked_without_weakening_crypto(self):
        expiry = time.time_ns() // 1000000 + 60000; e = self.envelope(expires_at_ms=expiry)
        with patch.object(auth.time, "time_ns", return_value=expiry * 1000000):
            with self.assertRaisesRegex(ValueError, "authorization_expired"): self.call(e)
        self.empty()
        with patch.object(auth.time, "time_ns", return_value=(expiry - 1) * 1000000): self.call(e)
        self.pair(e)

    def test_16_waiting_writer_observes_committed_epoch_change(self):
        e = self.envelope()
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            c.execute("BEGIN IMMEDIATE"); c.execute("UPDATE config SET policy_epoch=2")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.send, e); time.sleep(.15); c.commit(); result = future.result()
        self.assertEqual(result.returncode, 2, result.stderr); self.assertIn(b"stale_policy_epoch", result.stderr); self.empty()
        current = self.envelope(policy_epoch=2); self.call(current); self.pair(current)

    def test_17_one_immutable_public_key_snapshot_for_verification_and_pin(self):
        original = auth._verify_signature; key_bytes = Path(self.pub).read_bytes(); e = self.envelope()
        def verified_then_swap(snapshot, statement, signature):
            self.assertEqual(snapshot, key_bytes); original(snapshot, statement, signature)
            Path(self.pub).write_bytes(b"not the pinned key anymore")
        try:
            with patch.object(auth, "_verify_signature", side_effect=verified_then_swap): self.call(e)
        finally: Path(self.pub).write_bytes(key_bytes)
        self.pair(e)

    def test_18_verified_statement_is_a_flat_snapshot_not_callers_live_dict(self):
        e = self.envelope()
        verified = auth._verify_authorization_binding(self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
        e["authorization"]["policy_epoch"] = 999
        self.assertEqual(verified[0]["policy_epoch"], 1); self.assertIsNot(verified[0], e["authorization"])
        self.assertEqual(verified[2], hashlib.sha256(Path(self.pub).read_bytes()).hexdigest()); self.empty()

    def test_19_status_binding_guards_never_modify_history(self):
        e = self.envelope(); expected = self.expected(e)
        cases = [{}, {**expected, "extra": True}]
        for field, values in (("operation_id", [None, True, 7, "not-uuid", "AAAAAAAA-0000-4000-8000-000000000000"]),
                              ("request_sha256", [None, 7, "a" * 63, "A" * 64]), ("destination", [None, "fixture:other"])):
            cases.extend({**expected, field: value} for value in values)
        for value in cases:
            with self.assertRaises(ValueError): atomic.status(self.db, value)
            self.empty()
        self.assertEqual(atomic.status(self.db, expected)["result"], "INCOMPLETE")

    def test_20_corrupt_effect_identity_destination_and_joint_digest_are_not_repaired(self):
        e = self.envelope(); self.call(e); original = self.snapshot()
        changes = [("UPDATE effects SET effect_id='invalid'",), ("UPDATE effects SET destination='fixture:other'",),
                   ("UPDATE claims SET request_sha256='" + "0" * 64 + "'", "UPDATE effects SET request_sha256='" + "0" * 64 + "'")]
        for statements in changes:
            with closing(sqlite3.connect(self.db)) as c:
                for statement in statements: c.execute(statement)
                c.commit()
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, "request_history_conflict"): atomic.status(self.db, self.expected(e))
            with self.assertRaisesRegex(ValueError, "authorization_spent"): self.call(e)
            self.assertEqual(self.snapshot(), before)
            with closing(sqlite3.connect(self.db)) as c:
                c.execute("DELETE FROM claims"); c.execute("DELETE FROM effects")
                c.executemany("INSERT INTO claims VALUES (?,?)", original[0]); c.executemany("INSERT INTO effects VALUES (?,?,?,?)", original[1]); c.commit()
        self.assertEqual(atomic.status(self.db, self.expected(e))["record"]["effect_id"], original[1][0][3])

    def test_21_KNOWN_LIMIT_trusted_helper_caller_can_commit_claim_without_effect(self):
        e = self.envelope()
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            c.execute("BEGIN IMMEDIATE")
            auth.consume_in_transaction(c, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode()); c.commit()
        claims, effects = self.snapshot(); self.assertEqual(len(claims), 1); self.assertEqual(effects, [])
        with self.assertRaisesRegex(ValueError, "atomic_history_inconsistent"): atomic.status(self.db, self.expected(e))
        with self.assertRaisesRegex(ValueError, "authorization_spent"): self.call(e)
        self.assertEqual(self.snapshot(), (claims, effects))

    def test_22_KNOWN_LIMIT_legacy_helper_is_not_the_fixed_effect_policy(self):
        request = {**self.request, "effect": "unmodeled:effect", "body": []}; e = self.envelope(request)
        parsed = auth.consume(self.db, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
        self.assertEqual(parsed, request); before = self.snapshot(); self.assertEqual(len(before[0]), 1); self.assertEqual(before[1], [])
        rejected = self.envelope({**request, "operation_id": str(uuid.uuid4())})
        with self.assertRaisesRegex(ValueError, "unsupported_fixture_effect"): self.call(rejected)
        self.assertEqual(self.snapshot(), before)

    def test_23_private_verified_helper_requires_callers_active_transaction(self):
        e = self.envelope(); verified = auth._verify_authorization_binding(self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            with self.assertRaisesRegex(ValueError, "authorization_transaction_required"): auth._consume_verified_in_transaction(c, verified)
        self.empty()

    def test_24_invalid_or_missing_key_never_reserves_claim_and_keeps_owner_transaction(self):
        e = self.envelope(); original = Path(self.pub).read_bytes()
        try:
            for raw in (b"", b"not a public key"):
                Path(self.pub).write_bytes(raw)
                with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
                    c.execute("BEGIN IMMEDIATE")
                    with self.assertRaisesRegex(ValueError, "invalid_authorization_signature"):
                        auth.consume_in_transaction(c, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
                    self.assertTrue(c.in_transaction); c.rollback()
                self.empty()
            with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
                c.execute("BEGIN IMMEDIATE")
                with self.assertRaises(OSError): auth.consume_in_transaction(c, str(self.dir / "missing-public.pem"), e["authorization"], e["signature"], e["request_bytes"].encode())
                self.assertTrue(c.in_transaction); c.rollback()
        finally: Path(self.pub).write_bytes(original)
        self.call(e); self.pair(e)

    def test_25_verifier_backend_errors_do_not_reserve_authority_or_fallback(self):
        import subprocess
        e = self.envelope(); selected = str(self.dir / "missing-authority.sqlite")
        for failure in (OSError("synthetic_missing_verifier"), subprocess.TimeoutExpired("synthetic_verifier", 10)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(auth.subprocess, "run", side_effect=failure):
                    with self.assertRaises(type(failure)): self.call(e)
                    with self.assertRaises(type(failure)):
                        auth.consume(selected, self.pub, e["authorization"], e["signature"], e["request_bytes"].encode())
                self.assertFalse(Path(selected).exists()); self.empty()
        self.call(e); self.pair(e)

    def test_26_witness_append_shape_key_and_canonical_guards_preserve_state(self):
        selected = str(self.dir / "witness.sqlite")
        command = ["python3", str(MODULES / "sqlite-status-witness.py"), selected]
        initialized = review.run([*command, "initialize", self.pub]); self.assertEqual(initialized.returncode, 0, initialized.stderr)
        baseline = Path(selected).read_bytes()
        canonical = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        value = dict(protocol="aml-fixture-provider-status/2", issuer="fixture-provider", operation_id=self.request["operation_id"],
                     challenge="a" * 64, record=None, signature="A" * 86 + "==")
        values = [{}, {**value, "extra": True}, {**value, "protocol": "wrong"}, {**value, "issuer": "wrong"},
                  {**value, "operation_id": "invalid"}, {**value, "challenge": "bad"}, {**value, "signature": "bad"},
                  {**value, "record": {"extra": True}}]
        payloads = [canonical(v) for v in values] + [b" " * 8193, json.dumps(value).encode(), canonical(value)]
        for payload in payloads:
            result = review.run([*command, "append", self.pub], payload)
            self.assertEqual(result.returncode, 2, result.stderr); self.assertEqual(Path(selected).read_bytes(), baseline)
        for args in (["unknown", self.pub], ["append"], ["append", str(self.dir / "absent-public.pem")]):
            result = review.run([*command, *args], canonical(value)); self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(Path(selected).read_bytes(), baseline)
        with closing(sqlite3.connect(selected)) as c: self.assertEqual(c.execute("SELECT count(*) FROM snapshots").fetchone(), (0,))
        self.empty()

    def test_27_KNOWN_LIMIT_legacy_coordinator_missing_store_creates_empty_file_but_no_authority(self):
        source = MODULES / "sqlite-epoch-coordinator.py"
        spec = importlib.util.spec_from_file_location("legacy_epoch_coordinator", source)
        coordinator = importlib.util.module_from_spec(spec); spec.loader.exec_module(coordinator)
        selected = str(self.dir / "absent-coordinator.sqlite")
        request = dict(protocol="aml-sqlite-epoch-test/1", action="claim", issuer_sha256="a" * 64, epoch=0,
                       claim_protocol="aml-file-authority-external-claim/2", claim_key_sha256="b" * 64, binding_sha256="c" * 64)
        with self.assertRaises(sqlite3.OperationalError): coordinator.run(selected, request)
        self.assertTrue(Path(selected).is_file())
        with closing(sqlite3.connect(selected)) as c: self.assertEqual(c.execute("SELECT name FROM sqlite_master").fetchall(), [])
        self.empty()  # This legacy route is NOT the atomic provider's no-create contract.


if __name__ == "__main__":
    unittest.main(verbosity=2)
