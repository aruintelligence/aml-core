"""Actual child-process witness integration: distinct interpreters, keys and stores."""
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from witness_freshness import challenge,verify_fresh
from witness_live_verifier import collect_latest

ROOT=pathlib.Path(__file__).resolve().parent
def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class ProcessWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.keys={}
        self.children=[]
        self.urls=[]
        for name in ("north","south"):
            key=Ed25519PrivateKey.generate()
            self.keys[name]=key.public_key()
            db=str(pathlib.Path(self.tmp.name)/(name+".sqlite"))
            self.assertEqual(DurableWitness(db,name,key).publish(cp())[0],"PUBLISHED")
            secret=pathlib.Path(self.tmp.name)/(name+".key")
            secret.write_text(key.private_bytes_raw().hex())
            secret.chmod(0o600)
            with socket.socket() as s:
                s.bind(("127.0.0.1",0))
                port=s.getsockname()[1]
            child=subprocess.Popen([sys.executable,"-u",str(ROOT/"witness_http_service.py"),
                "--db",db,"--witness-id",name,"--private-key-file",str(secret),
                "--port",str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.children.append(child)
            ready,_,_=select.select([child.stdout],[],[],5)
            if not ready or "WITNESS_READY" not in child.stdout.readline():
                raise AssertionError("child witness did not start")
            self.urls.append("http://127.0.0.1:%d/latest"%port)
        self.addCleanup(self.stop)

    def stop(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        for child in self.children:
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=3)

    def check(self,expected=None):
        n=challenge()
        responses=collect_latest(self.urls,n,timeout=1)
        return verify_fresh(responses,n,self.keys,2,cp() if expected is None else expected)

    def test_separate_process_quorum(self):
        self.assertEqual(self.check(),"FRESH_QUORUM_CONSISTENT")

    def test_process_kill_fails_closed(self):
        self.children[0].kill()
        self.children[0].wait(timeout=3)
        with self.assertRaises(Exception):
            self.check()

    def test_cross_process_fork_rejected(self):
        # Separate south store advances while north still reports old head.
        keyfile=pathlib.Path(self.tmp.name)/"south.key"
        key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keyfile.read_text()))
        db=str(pathlib.Path(self.tmp.name)/"south.sqlite")
        self.assertEqual(DurableWitness(db,"south",key).publish(cp(2,"b"*64))[0],"PUBLISHED")
        self.assertEqual(self.check(),"FORK_OR_ADVANCED_HISTORY")

    def test_process_reports_stale_history(self):
        self.assertEqual(self.check(expected=cp(2)),"STALE_HISTORY")

    def test_replayed_response_rejected(self):
        old=challenge()
        responses=collect_latest(self.urls,old)
        self.assertEqual(verify_fresh(responses,challenge(),self.keys,2,cp()),"INVALID")

    def test_network_endpoint_redirect_bypass_rejected(self):
        with self.assertRaises(ValueError):
            collect_latest(["http://127.0.0.1:9@evil.example/latest"],challenge())
