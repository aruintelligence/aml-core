"""Synthetic SEF/2 adversarial regression suite; no external effects."""
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time
import tempfile
import unittest
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from sef2 import approve, db, digest, initialize, post, start

class Adversarial(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = self.tmp.name + "/authority.db"
        self.p = self.tmp.name + "/provider.db"
        initialize(self.a, self.p)
        self.secret = os.urandom(32)
        self.auth, self.auth_url = start("authority", self.a, secret=self.secret)
        self.prov, self.url = start("provider", self.p, self.auth_url, self.secret)
        self.addCleanup(self.auth.server_close)
        self.addCleanup(self.auth.shutdown)
        self.addCleanup(lambda: self.prov.server_close())
        self.addCleanup(lambda: self.prov.shutdown())

    def request(self):
        return {"operation_id": str(uuid.uuid4()), "destination": "fixture:merchant-a",
            "effect": "payment:simulate", "body": {"amount_minor": 500, "currency": "USD"}}

    def count(self):
        with db(self.p) as con:
            return con.execute("SELECT count(*) FROM effects").fetchone()[0]

    def test_no_approval_and_direct_authority_denied(self):
        r = self.request()
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(post(self.auth_url + "/consume",
            {"operation_id": r["operation_id"], "request_sha256": digest(r)})["state"], "DENIED")
        self.assertEqual(self.count(), 0)

    def test_approved_replay_and_mutation(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        changed = json.loads(json.dumps(r))
        changed["destination"] = "fixture:merchant-b"
        self.assertEqual(post(self.url + "/execute", changed)["state"], "DENIED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "PROVIDER_REPORTED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 1)

    def test_concurrent_claim(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            states = list(pool.map(lambda _: post(self.url + "/execute", r)["state"], range(12)))
        self.assertEqual(states.count("PROVIDER_REPORTED"), 1)
        self.assertEqual(states.count("DENIED"), 11)
        self.assertEqual(self.count(), 1)

    def test_provider_rollback_retains_authority(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "PROVIDER_REPORTED")
        with db(self.p) as con:
            con.execute("DELETE FROM effects")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 0)

    def restart_provider(self, fault=None):
        self.prov.shutdown()
        self.prov.server_close()
        self.prov, self.url = start("provider", self.p, self.auth_url, self.secret, fault=fault)

    def test_after_claim_uncertain_and_reconciles_without_retry(self):
        self.restart_provider(fault="after_claim")
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "UNCERTAIN")
        self.assertEqual(self.count(), 0)
        self.restart_provider()
        self.assertEqual(post(self.url + "/status", r)["state"], "UNCERTAIN")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 0)

    def test_after_effect_uncertain_then_reconciles(self):
        self.restart_provider(fault="after_effect")
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "UNCERTAIN")
        self.assertEqual(self.count(), 1)
        self.restart_provider()
        self.assertEqual(post(self.url + "/status", r)["state"], "PROVIDER_REPORTED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 1)

    def test_provider_restart_retains_one_use_claim(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "PROVIDER_REPORTED")
        self.restart_provider()
        self.assertEqual(post(self.url + "/status", r)["state"], "PROVIDER_REPORTED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")

    def child_provider(self, fault):
        # Child is a distinct OS process; os._exit cannot terminate the test runner.
        port_file = pathlib.Path(self.tmp.name) / ("port-" + str(uuid.uuid4()))
        proc = subprocess.Popen([sys.executable, "provider_child.py",
            "--provider-db", self.p, "--authority-url", self.auth_url,
            "--secret-hex", self.secret.hex(), "--fault", fault,
            "--port-file", str(port_file)], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: proc.kill() if proc.poll() is None else None)
        deadline = time.monotonic() + 5
        while not port_file.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError("provider child exited before readiness")
            time.sleep(0.01)
        self.assertTrue(port_file.exists(), "provider child never became ready")
        return proc, port_file.read_text()

    def test_hard_kill_after_claim_no_duplicate(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        proc, url = self.child_provider("kill_after_claim")
        with self.assertRaises((URLError, ConnectionError, TimeoutError, OSError)):
            post(url + "/execute", r)
        self.assertEqual(proc.wait(timeout=5), 71)
        self.assertEqual(self.count(), 0)
        self.assertEqual(post(self.url + "/status", r)["state"], "UNCERTAIN")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 0)

    def test_hard_kill_after_effect_recovers_report(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        proc, url = self.child_provider("kill_after_effect")
        with self.assertRaises((URLError, ConnectionError, TimeoutError, OSError)):
            post(url + "/execute", r)
        self.assertEqual(proc.wait(timeout=5), 72)
        self.assertEqual(self.count(), 1)
        self.assertEqual(post(self.url + "/status", r)["state"], "PROVIDER_REPORTED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 1)

    def test_authority_restart_retains_consumed_claim(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "PROVIDER_REPORTED")
        self.auth.shutdown()
        self.auth.server_close()
        self.auth, self.auth_url = start("authority", self.a, secret=self.secret)
        self.restart_provider()
        self.assertEqual(post(self.url + "/status", r)["state"], "PROVIDER_REPORTED")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 1)

    def test_authority_unavailable_must_not_execute(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.auth.shutdown()
        self.auth.server_close()
        self.assertEqual(post(self.url + "/execute", r)["state"], "UNCERTAIN")
        self.assertEqual(self.count(), 0)

    def test_forged_provider_evidence_conflict_is_uncertain(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/execute", r)["state"], "PROVIDER_REPORTED")
        with db(self.p) as con:
            con.execute("UPDATE effects SET digest=? WHERE op=?",
                ("0" * 64, r["operation_id"]))
        result = post(self.url + "/status", r)
        self.assertEqual(result["state"], "UNCERTAIN")
        self.assertEqual(result["reason"], "evidence_conflict")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")
        self.assertEqual(self.count(), 1)

    def test_forged_effect_without_authority_is_uncertain(self):
        r = self.request()
        with db(self.p) as con:
            con.execute("INSERT INTO effects VALUES (?,?,?)",
                (r["operation_id"], digest(r), str(uuid.uuid4())))
        result = post(self.url + "/status", r)
        self.assertEqual(result["state"], "UNCERTAIN")
        self.assertEqual(result["reason"], "authority_conflict")
        self.assertEqual(post(self.url + "/execute", r)["state"], "DENIED")

    def test_reconciliation_does_not_authorize_unconsumed_approval(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        self.assertEqual(post(self.url + "/status", r)["state"], "INCOMPLETE")
        self.assertEqual(self.count(), 0)

    def test_duplicate_keys_rejected(self):
        r = self.request()
        approve(self.a, r["operation_id"], digest(r))
        raw = json.dumps(r)[:-1] + ',"destination":"fixture:merchant-a"}'
        req = Request(self.url + "/execute", raw.encode(),
            {"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(req) as res:
                result = json.load(res)
        except HTTPError as error:
            result = json.load(error)
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(self.count(), 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
