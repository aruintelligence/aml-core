#!/usr/bin/env python3
"""Executable falsification lab. Synthetic effects only; no production payment."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from service import DESTINATION, EFFECT, initialize_provider, strict_json

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pilots/action-boundary"))
from authorized_execution import DOMAIN, canonical, initialize, revoke, set_epoch
from client import exchange

RESULTS = []
PORTABLE = False


def observe(case, expected, actual, property_name):
    RESULTS.append({"case": case, "property": property_name, "expected": expected, "observed": actual,
                    "pass": expected == actual})
    assert expected == actual, case


class Lab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="aml-sef-011-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.trusted = self.base / "trusted"
        self.trusted.mkdir(mode=0o700)
        self.empty = self.base / "empty"
        self.empty.mkdir()
        self.agent = self.base / "agent"
        self.agent.mkdir()
        self.public = self.trusted / "public.pem"
        self.private = self.trusted / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
                       check=True, capture_output=True)
        self.authority = self.trusted / "authority.db"
        self.provider = self.trusted / "provider.db"
        initialize(self.authority, self.public)
        initialize_provider(self.provider)
        self.inbox = self.base / "inbox"
        self.inbox.mkdir()
        self.outbox = self.base / "outbox"
        self.outbox.mkdir()
        self.process = None
        self.addCleanup(self.stop)

    def start(self, fault=None):
        if self.process is not None:
            self.stop()
        cmd = [sys.executable, str(ROOT / "research/sef1/service.py"),
               "--inbox", str(self.inbox), "--outbox", str(self.outbox), "--authority", str(self.authority),
               "--provider", str(self.provider), "--public-key", str(self.public)]
        if fault:
            cmd += ["--fault", fault]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if self.process.poll() is not None:
                break
            time.sleep(0.01)
        if self.process.poll() is not None:
            raise RuntimeError(self.process.stderr.read().decode())

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
            self.process = None

    def sign(self, statement):
        with tempfile.TemporaryDirectory(dir=self.trusted) as directory:
            message = Path(directory) / "message"
            message.write_bytes(DOMAIN + canonical(statement))
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                                                 str(self.private), "-in", str(message)])
        return base64.b64encode(signature).decode("ascii")

    def request(self, op=None, amount=900, epoch=1, expiry=None):
        op = op or str(uuid.uuid4())
        raw = json.dumps({"operation_id": op, "destination": DESTINATION, "effect": EFFECT,
                          "body": {"amount_minor": amount, "currency": "USD"}},
                         sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        statement = {"version": "aml-authorized-execution/1", "issuer": "issuer:lab", "principal": "agent:lab",
                     "policy_id": "payables:lab", "policy_epoch": epoch, "operation_id": op,
                     "request_sha256": digest, "destination": DESTINATION, "effect": EFFECT,
                     "expires_at_ms": expiry if expiry is not None else int(time.time() * 1000) + 60000}
        return {"protocol": "aml-sef-lab-request/1", "command": "submit", "challenge": os.urandom(16).hex(),
                "envelope": {"authorization": statement, "signature": self.sign(statement), "request_bytes": raw}}

    def send(self, request, sandbox=True):
        data = json.dumps(request, separators=(",", ":")).encode()
        if not sandbox or PORTABLE:
            return exchange(self.inbox, self.outbox, data)
        cmd = ["bwrap", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid",
               "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(self.empty), str(self.trusted),
               "--bind", str(self.inbox), str(self.inbox), "--ro-bind", str(self.outbox), str(self.outbox),
               "--bind", str(self.agent), str(self.agent), "--chdir", str(self.agent), "--clearenv",
               "--setenv", "PATH", "/usr/bin:/bin", "--die-with-parent", "--new-session",
               sys.executable, str(ROOT / "research/sef1/client.py"), str(self.inbox), str(self.outbox)]
        child = subprocess.run(cmd, input=data, capture_output=True, timeout=10)
        if child.returncode != 0:
            raise RuntimeError(child.stderr.decode())
        return json.loads(child.stdout)

    def count(self):
        con = sqlite3.connect(self.provider)
        try:
            return con.execute("SELECT count(*) FROM effects").fetchone()[0]
        finally:
            con.close()

    def binding(self, request):
        statement = request["envelope"]["authorization"]
        return {"operation_id": statement["operation_id"], "request_sha256": statement["request_sha256"],
                "destination": DESTINATION}

    def status(self, request):
        return self.send({"protocol": "aml-sef-lab-request/1", "command": "status",
                          "challenge": os.urandom(16).hex(), "binding": self.binding(request)})

    def test_authorized_replay_and_destination_mutation(self):
        self.start()
        request = self.request()
        observe("authorized_payment", "PROVIDER_REPORTED", self.send(request)["state"], "provider acceptance report")
        observe("same_signed_capability_replay", "DENIED", self.send(request)["state"], "one-use safety")
        mutated = self.request()
        mutated["envelope"]["request_bytes"] = mutated["envelope"]["request_bytes"].replace(
            DESTINATION, "fixture:merchant-b")
        observe("changed_destination_after_approval", "DENIED", self.send(mutated)["state"], "request binding")
        self.assertEqual(self.count(), 1)

    def test_no_authority_wrong_key_expiry_revocation_epoch(self):
        self.start()
        unauthorized = self.request()
        unauthorized["envelope"]["signature"] = "AA=="
        observe("forged_signature", "DENIED", self.send(unauthorized)["state"], "authenticity")
        expired = self.request(expiry=1)
        observe("expired", "DENIED", self.send(expired)["state"], "freshness")
        revoked = self.request()
        revoke(self.authority, self.binding(revoked)["operation_id"])
        observe("revoked", "DENIED", self.send(revoked)["state"], "revocation")
        stale = self.request()
        set_epoch(self.authority, 2)
        observe("stale_policy_epoch", "DENIED", self.send(stale)["state"], "epoch consistency")
        observe("fresh_policy_epoch", "PROVIDER_REPORTED", self.send(self.request(epoch=2))["state"], "liveness")

    def test_parallel_same_authorization(self):
        self.start()
        request = self.request()
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: self.send(request)["state"], range(8)))
        observe("eight_concurrent_requests", (1, 7),
                (outcomes.count("PROVIDER_REPORTED"), outcomes.count("DENIED")), "one-use concurrency")
        self.assertEqual(self.count(), 1)

    def test_provider_rollback_retains_independent_claim(self):
        self.start()
        request = self.request()
        first = self.send(request)
        self.assertEqual(first["state"], "PROVIDER_REPORTED")
        self.stop()
        con = sqlite3.connect(self.provider)
        con.execute("DELETE FROM effects")
        con.commit()
        con.close()
        self.start()
        observe("provider_rollback_authority_retained", "DENIED", self.send(request)["state"], "replay after provider loss")
        observe("claim_without_provider_history", "UNCERTAIN", self.status(request)["state"], "evidence uncertainty")
        self.assertEqual(self.count(), 0)

    def test_lost_ack_and_crash_after_claim(self):
        for fault, expected_status in [("after_claim", "UNCERTAIN"), ("after_effect", "PROVIDER_REPORTED"),
                                       ("before_response_publish", "PROVIDER_REPORTED")]:
            self.start(fault)
            request = self.request()
            observe(fault + "_reply", "UNCERTAIN", self.send(request)["state"], "acknowledgment failure")
            self.stop()
            self.start()
            observe(fault + "_replay", "DENIED", self.send(request)["state"], "fail-closed replay")
            observe(fault + "_status", expected_status, self.status(request)["state"], "read-only reconciliation")

    def test_sandbox_denies_direct_provider_route_and_admin_access(self):
        if PORTABLE:
            self.skipTest("requires bubblewrap isolation; run default lab on Linux")
        self.start()
        script = ("from pathlib import Path\nimport sqlite3\n"
                  f"p=Path({str(self.provider)!r})\n"
                  "sqlite3.connect(p).execute('CREATE TABLE attack(x)')\n")
        cmd = ["bwrap", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--proc", "/proc",
               "--dev", "/dev", "--ro-bind", str(self.empty), str(self.trusted), "--clearenv",
               "--setenv", "PATH", "/usr/bin:/bin", sys.executable, "-c", script]
        attack = subprocess.run(cmd, capture_output=True, timeout=10)
        observe("sandbox_direct_db_write", True, attack.returncode != 0 and self.count() == 0, "route isolation")
        self.assertNotIn(b"private.pem", attack.stdout)
        # The same OS identity *outside* the sandbox can write directly. This
        # is retained as a counterexample to whole-host compromise.
        con = sqlite3.connect(self.provider)
        con.execute("INSERT INTO effects VALUES (?,?,?,?)", (str(uuid.uuid4()), "0" * 64, DESTINATION,
                     str(uuid.uuid4())))
        con.commit()
        con.close()
        observe("same_uid_outside_sandbox_bypass", 1, self.count(), "known administration boundary")

    def test_strict_ingress_and_dishonest_issuer_limit(self):
        self.start()
        for label, data in [("duplicate_json_key", b'{"a":1,"a":2}'),
                            ("nonfinite_number", b'{"a":NaN}'),
                            ("float_number", b'{"a":1.0}'),
                            ("oversize", b' ' * 65537),
                            ("deep_nesting", b'[' * 17 + b'0' + b']' * 17)]:
            try:
                strict_json(data)
                actual = "accepted"
            except ValueError:
                actual = "denied"
            observe(label, "denied", actual, "parser safety")
        # A trusted key can sign a new allowed operation: an issuer compromise
        # is outside this slice's guarantee.
        observe("dishonest_trusted_issuer", "PROVIDER_REPORTED", self.send(self.request())["state"],
                "key-custody boundary")

    def test_parser_and_approval_binding_variants(self):
        self.start()
        for label, change in [
            ("unicode_escaped_currency", lambda raw: raw.replace('"USD"', '"\\u0055SD"')),
            ("numeric_representation", lambda raw: raw.replace('900', '9e2')),
            ("request_amount_mutation", lambda raw: raw.replace('900', '901')),
            ("duplicate_nested_key", lambda raw: raw.replace('"currency":"USD"',
                                                       '"currency":"USD","currency":"USD"')),
        ]:
            request = self.request()
            request["envelope"]["request_bytes"] = change(request["envelope"]["request_bytes"])
            observe(label, "DENIED", self.send(request)["state"], "exact byte binding")
        altered_identity = self.request()
        altered_identity["envelope"]["authorization"]["principal"] = "agent:other"
        observe("untrusted_approval_identity", "DENIED", self.send(altered_identity)["state"], "issuer binding")
        self.assertEqual(self.count(), 0)

    def test_agent_fabricated_completion_report(self):
        self.start()
        request = self.request()
        fake = {"state": "CONFIRMED", "independent_confirmation": True,
                "operation_id": self.binding(request)["operation_id"]}
        observe("agent_can_forge_own_receipt", "CONFIRMED", fake["state"], "untrusted claim counterexample")
        observe("trusted_read_only_status", "INCOMPLETE", self.status(request)["state"], "independent query")
        self.assertEqual(self.count(), 0)

    def test_joint_authority_provider_rollback_counterexample(self):
        self.start()
        request = self.request()
        self.stop()
        authority_copy = self.base / "old_authority.db"
        provider_copy = self.base / "old_provider.db"
        shutil.copy2(self.authority, authority_copy)
        shutil.copy2(self.provider, provider_copy)
        self.start()
        first = self.send(request)
        self.assertEqual(first["state"], "PROVIDER_REPORTED")
        first_id = first["effect_id"]
        self.stop()
        shutil.copy2(authority_copy, self.authority)
        shutil.copy2(provider_copy, self.provider)
        self.start()
        second = self.send(request)
        observe("joint_trusted_store_rollback", "PROVIDER_REPORTED", second["state"],
                "preserved negative control")
        observe("duplicate_external_histories", True, second["effect_id"] != first_id,
                "counterexample: coordinated rollback")


if __name__ == "__main__":
    if "--portable" in sys.argv:
        PORTABLE = True
        sys.argv.remove("--portable")
    report = None
    if "--report" in sys.argv:
        index = sys.argv.index("--report")
        report = Path(sys.argv[index + 1])
        del sys.argv[index:index + 2]
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(Lab))
    if report:
        report.write_text(json.dumps({"schema": "aml-sef-lab-results/1", "source": "project-authored",
            "case_count": len(RESULTS), "assertions": RESULTS, "tests_run": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors),
            "sandbox": "not exercised; sandbox test skipped" if PORTABLE else
                       "bubblewrap read-only root; hidden trusted directory; agent process only",
            "limitations": ["same-UID unsandboxed administrator can bypass", "joint trusted-store rollback duplicates",
                            "no external payment provider", "no independent completion"]}, indent=2) + "\n")
    sys.exit(0 if result.wasSuccessful() else 1)
