"""Synthetic SEF/2 adversarial regression suite; no external effects."""
import concurrent.futures
import json
import os
import tempfile
import unittest
import uuid
from urllib.error import HTTPError
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
        self.addCleanup(self.prov.server_close)
        self.addCleanup(self.prov.shutdown)

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
