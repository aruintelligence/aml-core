import copy
import json
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from evaluation_kit.verify_recovery_authority import verify_recovery_authority_evidence

def make_policy(keys):
    return {"schema":POLICY_SCHEMA,"policy_id":"recovery-council-a","threshold":3,
        "max_faults":1,
        "authorities":{name:key.public_key().public_bytes_raw().hex() for name,key in keys.items()},
        "administrative_domains":{name:"domain-"+name for name in keys}}

class RecoveryAuthorityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
        self.policy=make_policy(self.keys)
        self.signer=RecoveryAuthoritySigner("authority-0",self.keys["authority-0"],
            pathlib.Path(self.tmp.name)/"authority.sqlite")
        self.payload={"witness_id":"north","generation":1,
            "previous_state_sha256":"a"*64}
        self.signer.approve(self.payload,self.policy)
        self.bundle=self.signer.export_approval_ledger()
        self.public_hex=self.keys["authority-0"].public_key().public_bytes_raw().hex()

    def check(self,bundle=None,head=None,policy=None,public_hex=None):
        return verify_recovery_authority_evidence(
            self.bundle if bundle is None else bundle,
            self.public_hex if public_hex is None else public_hex,
            self.bundle["head_sha256"] if head is None else head,
            self.policy if policy is None else policy)

    def test_independent_verifier_accepts_signed_hash_chain_and_pinned_head(self):
        self.assertTrue(self.check())

    def test_wrong_expected_head_rejected(self):
        self.assertFalse(self.check(head="f"*64))

    def test_wrong_authority_public_key_rejected(self):
        self.assertFalse(self.check(public_hex=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()))

    def test_policy_key_substitution_rejected(self):
        policy=copy.deepcopy(self.policy)
        policy["authorities"]["authority-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        self.assertFalse(self.check(policy=policy))

    def test_event_payload_tampering_rejected(self):
        bundle=copy.deepcopy(self.bundle)
        bundle["events"][0]["payload_sha256"]="f"*64
        self.assertFalse(self.check(bundle=bundle))

    def test_event_signature_tampering_rejected(self):
        bundle=copy.deepcopy(self.bundle)
        bundle["events"][0]["signature"]="00"*64
        self.assertFalse(self.check(bundle=bundle))

    def test_event_chain_predecessor_tampering_rejected(self):
        bundle=copy.deepcopy(self.bundle)
        bundle["events"][0]["previous_event_sha256"]="f"*64
        self.assertFalse(self.check(bundle=bundle))

    def test_truncated_history_rejected_under_pinned_head(self):
        second={**self.payload,"generation":2,"previous_state_sha256":"b"*64}
        self.signer.approve(second,self.policy)
        full=self.signer.export_approval_ledger()
        truncated=copy.deepcopy(full); truncated["events"]=truncated["events"][:1]
        truncated["head_sha256"]=truncated["events"][0]["event_sha256"]
        self.assertFalse(verify_recovery_authority_evidence(
            truncated,self.public_hex,full["head_sha256"],self.policy))

    def test_unknown_authority_id_rejected_by_policy(self):
        bundle=copy.deepcopy(self.bundle); bundle["authority_id"]="outsider"
        self.assertFalse(self.check(bundle=bundle))

    def test_invalid_policy_rejected(self):
        self.assertFalse(self.check(policy={"schema":"wrong"}))
