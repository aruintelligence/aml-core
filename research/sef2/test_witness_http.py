import json
import pathlib
import sys
import tempfile
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from witness_http_service import serve
from witness_live_verifier import collect_latest
from witness_freshness import challenge,verify_fresh

def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class WitnessHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.keys={n:Ed25519PrivateKey.generate() for n in ("north","south")}
        self.stores={}
        self.servers=[]
        self.threads=[]
        for n,k in self.keys.items():
            store=DurableWitness(str(pathlib.Path(self.tmp.name)/(n+".sqlite")),n,k)
            store.publish(cp())
            self.stores[n]=store
            server=serve(store)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            self.servers.append(server)
            self.threads.append(thread)
        self.urls=["http://127.0.0.1:%d/latest"%s.server_address[1] for s in self.servers]
        self.addCleanup(self.cleanup_servers)

    def cleanup_servers(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        for t in self.threads:
            t.join(timeout=2)

    def check(self,nonce=None,expected=None):
        n=challenge() if nonce is None else nonce
        responses=collect_latest(self.urls,n)
        return verify_fresh(responses,n,{k:v.public_key() for k,v in self.keys.items()},2,cp() if expected is None else expected)

    def test_two_http_witnesses_accepted(self):
        self.assertEqual(self.check(),"FRESH_QUORUM_CONSISTENT")

    def test_http_replay_challenge_rejected(self):
        old=challenge()
        responses=collect_latest(self.urls,old)
        self.assertEqual(verify_fresh(responses,challenge(),
            {k:v.public_key() for k,v in self.keys.items()},2,cp()),"INVALID")

    def test_cross_witness_fork_rejected(self):
        self.stores["south"].publish(cp(2,"b"*64))
        self.assertEqual(self.check(),"FORK_OR_ADVANCED_HISTORY")

    def test_stale_history_rejected(self):
        self.assertEqual(self.check(expected=cp(2)),"STALE_HISTORY")

    def test_loopback_only_enforced(self):
        with self.assertRaises(ValueError):
            serve(self.stores["north"],host="0.0.0.0")

    def test_nonloopback_client_rejected(self):
        with self.assertRaises(ValueError):
            collect_latest(["http://example.com/latest"],challenge())

    def test_missing_service_fails_closed(self):
        self.servers[0].shutdown()
        self.servers[0].server_close()
        with self.assertRaises(Exception):
            collect_latest(self.urls,challenge(),timeout=0.1)

    def test_duplicate_endpoint_rejected_by_signature_quorum(self):
        n=challenge()
        responses=collect_latest([self.urls[0],self.urls[0]],n)
        self.assertEqual(verify_fresh(responses,n,{k:v.public_key() for k,v in self.keys.items()},2,cp()),"UNTRUSTED_OR_DUPLICATE")
