import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose
from threshold_recovery import (POLICY_SCHEMA,RecoveryAuthoritySigner,
    ThresholdRecoveryPublicKey,make_threshold_transition)
from witness_recovery_enrollment import WitnessRecoveryEnrollment
from evaluation_kit.verify_recovery_transaction import verify_recovery_transaction

def pub(k): return k.public_key().public_bytes_raw().hex()
def checkpoint(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
  "head_hash":head,"count":epoch,"approver_key_id":"c"*64}
def policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"recovery-council-e2e","threshold":3,
  "max_faults":1,"authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryTransactionEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.trust_path=str(pathlib.Path(self.tmp.name)/"trust.sqlite")
  self.recovery_path=str(pathlib.Path(self.tmp.name)/"recovery.sqlite")
  self.approver=Ed25519PrivateKey.generate()
  self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  self.base_keys={"authority":pub(Ed25519PrivateKey.generate()),
   "provider":pub(Ed25519PrivateKey.generate()),"witness":pub(self.old)}
  self.enrollment=Enrollment(self.trust_path,self.approver.public_key())
  self.assertEqual(self.enrollment.accept(propose(self.approver,1,self.base_keys)),"ENROLLED")
  self.before=copy.deepcopy(self.enrollment.manifest())
  self.authorities={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.authorities)
  self.signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite"))
    for n,k in self.authorities.items()}
  verifier=ThresholdRecoveryPublicKey(self.policy)
  self.coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,verifier,self.policy["policy_id"])
  self.current=self.coordinator.initialize("north",checkpoint())
  chosen={n:self.signers[n] for n in ("r0","r1","r2")}
  self.transition=make_threshold_transition(self.new,"north",self.current,checkpoint(2,"b"*64),
    self.policy,chosen)
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  self.after=copy.deepcopy(self.enrollment.manifest())
  self.next_state=self.coordinator.state("north")
  self.verifier=verifier
 def check(self,before=None,after=None,current=None,next_state=None,transition=None):
  return verify_recovery_transaction(
   self.before if before is None else before,self.after if after is None else after,
   self.current if current is None else current,self.next_state if next_state is None else next_state,
   self.transition if transition is None else transition,self.verifier,self.policy["policy_id"])
 def test_complete_recovery_transaction_verifies_without_live_database(self):
  self.assertTrue(self.check())
 def test_missing_old_key_revocation_rejected(self):
  after=copy.deepcopy(self.after); after["revoked_key_hex"]=[]
  self.assertFalse(self.check(after=after))
 def test_extra_unexplained_revocation_rejected(self):
  after=copy.deepcopy(self.after); after["revoked_key_hex"]=sorted(after["revoked_key_hex"]+["f"*64])
  self.assertFalse(self.check(after=after))
 def test_provider_key_change_rejected(self):
  after=copy.deepcopy(self.after); after["public_keys"]["provider"]=pub(Ed25519PrivateKey.generate())
  self.assertFalse(self.check(after=after))
 def test_authority_key_change_rejected(self):
  after=copy.deepcopy(self.after); after["public_keys"]["authority"]=pub(Ed25519PrivateKey.generate())
  self.assertFalse(self.check(after=after))
 def test_epoch_skip_rejected(self):
  after=copy.deepcopy(self.after); after["epoch"]+=1
  self.assertFalse(self.check(after=after))
 def test_new_witness_key_substitution_rejected(self):
  after=copy.deepcopy(self.after); after["public_keys"]["witness"]=pub(Ed25519PrivateKey.generate())
  self.assertFalse(self.check(after=after))
 def test_current_state_not_bound_to_old_witness_rejected(self):
  current=copy.deepcopy(self.current); current["public_key_sha256"]="f"*64
  self.assertFalse(self.check(current=current))
 def test_next_state_substitution_rejected(self):
  nxt=copy.deepcopy(self.next_state); nxt["generation"]+=1
  self.assertFalse(self.check(next_state=nxt))
 def test_transition_tampering_rejected(self):
  transition=copy.deepcopy(self.transition); transition["proof_of_possession"]="00"*64
  self.assertFalse(self.check(transition=transition))
