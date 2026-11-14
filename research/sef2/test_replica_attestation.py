"""Offline authenticated replica identities and adversarial substitution tests."""
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest,verify_attestations

class ReplicaAttestationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=pathlib.Path(temp.name)
        self.registry=PinRegistry(root/"registry.sqlite")
        self.registry.enroll("north","a"*64)
        self.replicas=[PinReplica(root/("replica-%d.sqlite"%i)) for i in range(3)]
        self.keys=[Ed25519PrivateKey.generate() for _ in range(3)]
        self.enrolled={"r%d"%i:key.public_key().public_bytes_raw().hex() for i,key in enumerate(self.keys)}
        for r in self.replicas:
            r.record("north",0,"a"*64)
    def receipts(self):
        return [attest(r,"r%d"%i,"north",self.keys[i]) for i,r in enumerate(self.replicas)]
    def test_authenticated_replica_set_passes(self):
        self.assertTrue(verify_attestations(self.registry,"north",self.receipts(),self.enrolled))
    def test_identity_substitution_rejected(self):
        receipts=self.receipts()
        receipts[0]["payload"]["replica_id"]="r1"
        self.assertFalse(verify_attestations(self.registry,"north",receipts,self.enrolled))
    def test_signature_substitution_rejected(self):
        receipts=self.receipts()
        receipts[0]["signature"]="00"*64
        self.assertFalse(verify_attestations(self.registry,"north",receipts,self.enrolled))
    def test_duplicate_identity_rejected(self):
        receipts=self.receipts()
        receipts[1]=receipts[0]
        self.assertFalse(verify_attestations(self.registry,"north",receipts,self.enrolled))
    def test_old_signed_state_rejected_after_registry_advance(self):
        receipts=self.receipts()
        self.registry.prepare("north","a"*64,"b"*64)
        self.registry.commit("north","a"*64,"b"*64)
        self.assertFalse(verify_attestations(self.registry,"north",receipts,self.enrolled))
    def test_duplicate_enrolled_public_key_rejected(self):
        enrolled=dict(self.enrolled)
        enrolled["r1"]=enrolled["r0"]
        self.assertFalse(verify_attestations(self.registry,"north",self.receipts(),enrolled))
