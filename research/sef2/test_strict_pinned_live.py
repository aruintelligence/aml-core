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
import test_durable_quorum as durable_fixture
from test_durable_quorum import public_hex
from signed_history import digest

class StrictPinnedLiveTests(unittest.TestCase):
    def setUp(self):
        self.fixture=durable_fixture.DurableQuorumTests("test_durable_quorum_accepts")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        self.anchors={}
        self.pins={}
        self.servers=[]
        self.threads=[]
        self.urls={}
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
            self.urls[name]="http://127.0.0.1:%d/latest"%server.server_address[1]
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

    def test_duplicate_witness_endpoint_rejected(self):
        original=dict(self.urls)
        self.urls["south"]=self.urls["north"]
        self.assertFalse(self.check())
        self.urls=original
        self.assertTrue(self.check())
    def test_swapped_anchor_identity_rejected(self):
        anchors={"north":self.anchors["south"],"south":self.anchors["north"]}
        self.assertFalse(self.check(anchors=anchors))
    def test_untrusted_anchor_key_rejected(self):
        anchor=json.loads(self.anchors["north"].read_text())
        anchor["witness_public_hex"]="0"*64
        self.anchors["north"].write_text(json.dumps(anchor))
        self.assertFalse(self.check())
    def test_older_checkpoint_anchor_rejected(self):
        anchor=json.loads(self.anchors["north"].read_text())
        anchor["checkpoint"]["epoch"]=0
        self.anchors["north"].write_text(json.dumps(anchor))
        self.assertFalse(self.check())

    def test_endpoint_identity_substitution_rejected(self):
        original=dict(self.urls)
        self.urls={"north":original["south"],"south":original["north"]}
        self.assertFalse(self.check())
        self.urls=original
        self.assertTrue(self.check())
    def test_unbound_endpoint_list_rejected(self):
        original=self.urls
        self.urls=list(original.values())
        self.assertFalse(self.check())
        self.urls=original
    def test_endpoint_missing_binding_rejected(self):
        original=self.urls
        self.urls={"north":original["north"]}
        self.assertFalse(self.check())
        self.urls=original
    def test_endpoint_extra_unpinned_identity_rejected(self):
        original=self.urls
        self.urls=dict(original,unknown="http://127.0.0.1:1/latest")
        self.assertFalse(self.check())
        self.urls=original

    def test_signed_attestation_participant_mismatch_rejected(self):
        f=self.fixture
        original=list(f.receipts)
        f.receipts=f.receipts[:1]
        f.save()
        self.assertFalse(self.check())
        f.receipts=original
        f.save()
        self.assertTrue(self.check())

    def test_duplicate_enrolled_public_key_rejected(self):
        f=self.fixture
        keys=json.loads(f.keys_path.read_text())
        keys["east"]=keys["north"]
        f.keys_path.write_text(json.dumps(keys))
        self.assertFalse(self.check())

    def test_extra_live_endpoint_rejected_even_if_key_enrolled(self):
        original=dict(self.urls)
        self.urls["east"]="http://127.0.0.1:65534/latest"
        self.assertFalse(self.check())
        self.urls=original

    def test_non_string_endpoint_fails_closed(self):
        original=dict(self.urls)
        self.urls["north"]=None
        self.assertFalse(self.check())
        self.urls=original

    def test_unhashable_attested_identity_fails_closed(self):
        f=self.fixture
        original=f.attestations.read_text()
        receipts=json.loads(original)
        receipts[0]["payload"]["witness_id"]=["north"]
        f.attestations.write_text(json.dumps(receipts))
        self.assertFalse(self.check())
        f.attestations.write_text(original)

    def test_null_attested_identity_fails_closed(self):
        f=self.fixture
        original=f.attestations.read_text()
        receipts=json.loads(original)
        receipts[0]["payload"]["witness_id"]=None
        f.attestations.write_text(json.dumps(receipts))
        self.assertFalse(self.check())
        f.attestations.write_text(original)

    def test_conflicting_pinned_anchor_fails_closed(self):
        original=self.anchors["north"].read_text()
        anchor=json.loads(original)
        anchor["checkpoint"]["head_hash"]="f"*64
        self.anchors["north"].write_text(json.dumps(anchor))
        self.assertFalse(self.check())
        self.anchors["north"].write_text(original)
        self.assertTrue(self.check())
