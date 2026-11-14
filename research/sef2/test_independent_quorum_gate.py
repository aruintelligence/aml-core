import json
import pathlib
import tempfile
import unittest
from verify_independent_quorum import verify_independent_quorum
from witness_independence import DIMENSIONS,independence_digest
from test_durable_quorum import DurableQuorumTests,public_hex

class IndependentQuorumGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture=DurableQuorumTests("test_durable_quorum_accepts")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        self.domains_path=f.root/"witness-domains.json"
        keys=json.loads(f.keys_path.read_text())
        self.domains={"witnesses":{name:{
            **{dimension:name+"-"+dimension for dimension in DIMENSIONS},
            "public_key_sha256":__import__("hashlib").sha256(bytes.fromhex(raw)).hexdigest()}
            for name,raw in keys.items()}}
        self.domains_path.write_text(json.dumps(self.domains))
        self.pin=independence_digest(self.domains)

    def check(self,pin=None):
        f=self.fixture
        return verify_independent_quorum(f.root,f.manifest_path,f.manifest_pin,
            f.history_db,public_hex(f.approver),f.checkpoint_path,f.pin,1,
            f.keys_path,self.domains_path,self.pin if pin is None else pin,
            f.attestations,3,1)

    def test_independent_quorum_gate_accepts(self):
        self.assertTrue(self.check())

    def test_shared_operator_rejected_before_quorum(self):
        self.domains["witnesses"]["south"]["operator"]=self.domains["witnesses"]["north"]["operator"]
        self.domains_path.write_text(json.dumps(self.domains))
        self.assertFalse(self.check())

    def test_changed_domains_with_old_pin_rejected(self):
        self.domains["witnesses"]["north"]["operator"]="substituted"
        self.domains_path.write_text(json.dumps(self.domains))
        self.assertFalse(self.check())

    def test_witness_key_substitution_rejected_by_pinned_manifest(self):
        keys=json.loads(self.fixture.keys_path.read_text())
        keys["north"]="f"*64
        self.fixture.keys_path.write_text(json.dumps(keys))
        self.assertFalse(self.check())
