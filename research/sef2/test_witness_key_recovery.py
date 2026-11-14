import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_key_recovery import (make_transition,verify_transition,advance_state,
    key_fingerprint)

def cp(epoch=4,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1",
        "epoch":epoch,"head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class WitnessKeyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.authority=Ed25519PrivateKey.generate()
        self.old=Ed25519PrivateKey.generate()
        self.new=Ed25519PrivateKey.generate()
        self.state={"witness_id":"north","generation":0,
            "public_key_sha256":key_fingerprint(self.old.public_key().public_bytes_raw().hex()),
            "checkpoint":cp(),"transition_sha256":"0"*64}
        self.envelope=make_transition(self.authority,self.new,"north",self.state,cp(5,"b"*64),"offline-recovery-1")

    def test_compromised_old_key_not_required_for_recovery(self):
        self.assertTrue(verify_transition(self.envelope,self.state,self.authority.public_key(),"offline-recovery-1"))
        advanced=advance_state(self.envelope,self.state,self.authority.public_key(),"offline-recovery-1")
        self.assertEqual(advanced["generation"],1)
        self.assertEqual(advanced["public_key_sha256"],key_fingerprint(self.new.public_key().public_bytes_raw().hex()))
        self.assertEqual(advanced["checkpoint"],cp(5,"b"*64))

    def test_old_key_signature_is_not_a_requirement(self):
        self.assertNotIn("old_witness_signature",self.envelope)
        self.assertTrue(verify_transition(self.envelope,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_wrong_recovery_authority_rejected(self):
        self.assertFalse(verify_transition(self.envelope,self.state,Ed25519PrivateKey.generate().public_key(),"offline-recovery-1"))

    def test_wrong_recovery_authority_identity_rejected(self):
        self.assertFalse(verify_transition(self.envelope,self.state,self.authority.public_key(),"other-authority"))

    def test_tampered_successor_key_rejected(self):
        changed=copy.deepcopy(self.envelope)
        changed["payload"]["new_public_key_hex"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_missing_proof_of_possession_rejected(self):
        changed=copy.deepcopy(self.envelope)
        changed["proof_of_possession"]="00"*64
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_tampered_authority_signature_rejected(self):
        changed=copy.deepcopy(self.envelope)
        changed["recovery_signature"]="00"*64
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_wrong_witness_identity_rejected(self):
        changed=copy.deepcopy(self.envelope)
        changed["payload"]["witness_id"]="south"
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_generation_skip_and_replay_rejected(self):
        changed=copy.deepcopy(self.envelope)
        changed["payload"]["generation"]=3
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))
        advanced=advance_state(self.envelope,self.state,self.authority.public_key(),"offline-recovery-1")
        self.assertFalse(verify_transition(self.envelope,advanced,self.authority.public_key(),"offline-recovery-1"))

    def test_old_state_substitution_rejected(self):
        changed=dict(self.state,generation=1)
        self.assertFalse(verify_transition(self.envelope,changed,self.authority.public_key(),"offline-recovery-1"))

    def test_checkpoint_rollback_rejected(self):
        changed=make_transition(self.authority,self.new,"north",self.state,cp(3),"offline-recovery-1")
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_same_epoch_fork_rejected(self):
        changed=make_transition(self.authority,self.new,"north",self.state,cp(4,"f"*64),"offline-recovery-1")
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_duplicate_key_replacement_rejected(self):
        changed=make_transition(self.authority,self.old,"north",self.state,cp(5,"b"*64),"offline-recovery-1")
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

    def test_malformed_current_state_fails_closed(self):
        self.assertFalse(verify_transition(self.envelope,{"witness_id":"north"},self.authority.public_key(),"offline-recovery-1"))

    def test_malformed_current_key_fingerprint_rejected(self):
        changed=dict(self.state,public_key_sha256="not-a-digest")
        self.assertFalse(verify_transition(self.envelope,changed,self.authority.public_key(),"offline-recovery-1"))

    def test_malformed_current_transition_digest_rejected(self):
        changed=dict(self.state,transition_sha256="not-a-digest")
        self.assertFalse(verify_transition(self.envelope,changed,self.authority.public_key(),"offline-recovery-1"))

    def test_transition_cannot_be_mutated_after_approval(self):
        changed=copy.deepcopy(self.envelope)
        changed["payload"]["checkpoint"]["head_hash"]="f"*64
        self.assertFalse(verify_transition(changed,self.state,self.authority.public_key(),"offline-recovery-1"))

