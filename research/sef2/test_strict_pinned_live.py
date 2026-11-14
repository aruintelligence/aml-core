"""Full strict pinned enterprise gate: history, quorum, live challenge, anchor pins."""
import json
import pathlib
import tempfile
import threading
import unittest
from durable_checkpoint_witness import DurableWitness
from external_witness_anchor import issue_anchor,anchor_pin,verify_anchor
from witness_http_service import serve
from witness_live_verifier import verify_pinned_live
from test_durable_quorum import DurableQuorumTests,public_hex
from signed_history import digest

class StrictPinnedLiveTests(unittest.TestCase):
    def setUp(self):
        self.fixture=DurableQuorumTests("test_durable_quorum_accepts")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        self.anchors={}
        self.pins={}
        self.servers=[]
        self.threads=[]
        self.urls=[]
        self.addCleanup(self.stop)
        for name in ("north","south"):
            anchor=issue_anchor(f.witnesses[name])
            path=f.root/(name+"-external-anchor.json")
            path.write_text(json.dumps(anchor,sort_keys=True))
            self.anchors[name]=path
            self.pins[name]=anchor_pin(anchor)
            guard=lambda name=name,path=path,pin=self.pins[name]: verify_anchor(
                f.root/(name+".sqlite"),name,public_hex(f.privates[name]),path,pin)
            server=serve(f.witnesses[name],anchor_guard=guard)
            self.servers.append(server)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            self.threads.append(thread)
            self.urls.append("http://127.0.0.1:%d/latest"%server.server_address[1])
    def stop(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
    def check(self,pins=None,anchors=None):
        f=self.fixture
        return verify_pinned_live(f.root,f.manifest_path,f.manifest_pin,f.history_db,
            public_hex(f.approver),f.checkpoint_path,f.pin,1,f.keys_path,
            f.attestations,2,self.urls,self.anchors if anchors is None else anchors,
            self.pins if pins is None else pins)
    def test_full_pinned_enterprise_verification_passes(self):
        self.assertTrue(self.check())
    def test_substituted_external_anchor_pin_fails(self):
        pins=dict(self.pins)
        pins["north"]="0"*64
        self.assertFalse(self.check(pins=pins))
        self.assertTrue(self.check())
    def test_missing_external_anchor_fails(self):
        anchors=dict(self.anchors)
        del anchors["north"]
        self.assertFalse(self.check(anchors=anchors))
    def test_tampered_anchor_fails_live(self):
        self.anchors["north"].write_text("{}")
        self.assertFalse(self.check())
    def test_wrong_history_checkpoint_fails(self):
        f=self.fixture
        original=f.pin
        f.pin="0"*64
        self.assertFalse(self.check())
        f.pin=original
        self.assertTrue(self.check())
