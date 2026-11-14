"""Real child-process enforcement of an independently pinned checkpoint."""
import json
import pathlib
import select
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from external_witness_anchor import issue_anchor,anchor_pin
from witness_live_verifier import collect_latest
from witness_freshness import challenge,verify_fresh

ROOT=pathlib.Path(__file__).resolve().parent
def cp(epoch,head):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class PinnedServiceProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
        self.key=Ed25519PrivateKey.generate()
        self.db=self.root/"witness.sqlite"
        self.snapshot=self.root/"snapshot.sqlite"
        self.store=DurableWitness(self.db,"north",self.key)
        self.assertEqual(self.store.publish(cp(1,"a"*64))[0],"PUBLISHED")
        with sqlite3.connect(self.db) as source:
            with sqlite3.connect(self.snapshot) as target:
                source.backup(target)
        self.assertEqual(self.store.publish(cp(2,"b"*64))[0],"PUBLISHED")
        anchor=issue_anchor(self.store)
        self.anchor=self.root/"anchor.json"
        self.anchor.write_text(json.dumps(anchor))
        self.pin=anchor_pin(anchor)
        self.secret=self.root/"secret"
        self.secret.write_text(self.key.private_bytes_raw().hex())
        self.public=self.root/"public"
        self.public.write_text(self.key.public_key().public_bytes_raw().hex())
        self.children=[]
        self.addCleanup(self.stop)
    def stop(self):
        for p in self.children:
            if p.poll() is None:
                p.terminate()
        for p in self.children:
            try:
                p.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate(timeout=3)
    def launch(self,pin=None):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        args=[sys.executable,"-u",str(ROOT/"witness_http_service.py"),
            "--db",str(self.db),"--witness-id","north",
            "--private-key-file",str(self.secret),"--port",str(port),
            "--anchor-file",str(self.anchor),"--anchor-pin",self.pin if pin is None else pin,
            "--witness-public-file",str(self.public)]
        p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.children.append(p)
        ready,_,_=select.select([p.stdout],[],[],5)
        if not ready:
            p.wait(timeout=3)
            return None
        line=p.stdout.readline()
        return ("http://127.0.0.1:%d/latest"%port) if "WITNESS_READY" in line else None
    def test_valid_pinned_start_and_live_response(self):
        url=self.launch()
        self.assertIsNotNone(url)
        nonce=challenge()
        responses=collect_latest([url],nonce)
        self.assertEqual(verify_fresh(responses,nonce,{"north":self.key.public_key(),
            "south":Ed25519PrivateKey.generate().public_key()},2,cp(2,"b"*64)),
            "INSUFFICIENT_WITNESSES")
    def test_restored_snapshot_blocks_service_restart(self):
        url=self.launch()
        self.assertIsNotNone(url)
        self.children[-1].terminate()
        self.children[-1].wait(timeout=3)
        with sqlite3.connect(self.snapshot) as source:
            with sqlite3.connect(self.db) as target:
                source.backup(target)
        self.assertIsNone(self.launch())
    def test_wrong_pin_blocks_service_startup(self):
        self.assertIsNone(self.launch("0"*64))
    def test_corrupt_anchor_blocks_service_startup(self):
        self.anchor.write_text("{}")
        self.assertIsNone(self.launch())
    def test_live_request_rejected_after_anchor_tamper(self):
        url=self.launch()
        self.assertIsNotNone(url)
        self.anchor.write_text("{}")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            collect_latest([url],challenge())
        self.assertEqual(ctx.exception.code,503)
