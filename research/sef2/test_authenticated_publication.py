import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_publication import sign_checkpoint
from durable_checkpoint_witness import DurableWitness
from witness_http_service import serve
from witness_live_verifier import collect_latest
from witness_freshness import challenge,verify_fresh

def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class AuthenticatedPublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.approver=Ed25519PrivateKey.generate()
        self.witness_key=Ed25519PrivateKey.generate()
        self.store=DurableWitness(str(pathlib.Path(self.tmp.name)/"store.sqlite"),"north",self.witness_key)
        self.server=serve(self.store,approver_public=self.approver.public_key())
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup)
        self.url="http://127.0.0.1:%d"%self.server.server_address[1]

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def post(self,envelope):
        request=urllib.request.Request(self.url+"/publish",data=json.dumps(envelope).encode(),method="POST")
        with urllib.request.urlopen(request,timeout=2) as r:
            return json.loads(r.read())

    def test_authorized_publish_and_fresh_read(self):
        self.assertEqual(self.post(sign_checkpoint(self.approver,cp()))["status"],"PUBLISHED")
        nonce=challenge()
        response=collect_latest([self.url+"/latest"],nonce)
        self.assertEqual(verify_fresh(response,nonce,{"north":self.witness_key.public_key(),"south":Ed25519PrivateKey.generate().public_key()},2,cp()),"INSUFFICIENT_WITNESSES")

    def test_unauthorized_approver_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(sign_checkpoint(Ed25519PrivateKey.generate(),cp()))
        self.assertEqual(ctx.exception.code,403)

    def test_tampered_publication_rejected(self):
        envelope=sign_checkpoint(self.approver,cp())
        envelope["checkpoint"]["head_hash"]="b"*64
        with self.assertRaises(urllib.error.HTTPError):
            self.post(envelope)

    def test_authenticated_replay_idempotent(self):
        envelope=sign_checkpoint(self.approver,cp())
        self.assertEqual(self.post(envelope)["status"],"PUBLISHED")
        self.assertEqual(self.post(envelope)["status"],"REPLAY")

    def test_older_epoch_rejected(self):
        self.post(sign_checkpoint(self.approver,cp(2,"b"*64)))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(sign_checkpoint(self.approver,cp()))
        self.assertEqual(ctx.exception.code,409)

    def test_same_epoch_fork_rejected(self):
        self.post(sign_checkpoint(self.approver,cp()))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(sign_checkpoint(self.approver,cp(1,"b"*64)))
        self.assertEqual(ctx.exception.code,409)

    def test_unsigned_publication_rejected(self):
        with self.assertRaises(urllib.error.HTTPError):
            self.post({"checkpoint":cp()})
