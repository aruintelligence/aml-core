import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose
from threshold_recovery import (POLICY_SCHEMA,RecoveryAuthoritySigner,ThresholdRecoveryPublicKey,
 make_threshold_transition,policy_digest)
from witness_recovery_enrollment import WitnessRecoveryEnrollment
from evaluation_kit.verify_recovery_bundle import BUNDLE_SCHEMA,verify_recovery_bundle

def pub(k): return k.public_key().public_bytes_raw().hex()
def cp(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
  "head_hash":head,"count":epoch,"approver_key_id":"c"*64}
def policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"bundle-council","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class FullRecoveryEvidenceBundleTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  trust=str(pathlib.Path(self.tmp.name)/"trust.sqlite"); recovery=str(pathlib.Path(self.tmp.name)/"recovery.sqlite")
  approver=Ed25519PrivateKey.generate(); old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  base={"authority":pub(Ed25519PrivateKey.generate()),"provider":pub(Ed25519PrivateKey.generate()),"witness":pub(old)}
  enrollment=Enrollment(trust,approver.public_key()); enrollment.accept(propose(approver,1,base))
  before=copy.deepcopy(enrollment.manifest())
  authorities={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(authorities)
  signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite")) for n,k in authorities.items()}
  chosen={n:signers[n] for n in ("r0","r1","r2")}
  verifier=ThresholdRecoveryPublicKey(self.policy)
  coordinator=WitnessRecoveryEnrollment(trust,recovery,verifier,self.policy["policy_id"])
  current=coordinator.initialize("north",cp())
  transition=make_threshold_transition(self.new,"north",current,cp(2,"b"*64),self.policy,chosen)
  self.assertEqual(coordinator.recover("north",transition),"RECOVERED")
  after=copy.deepcopy(enrollment.manifest()); next_state=coordinator.state("north")
  ledgers={n:signers[n].export_approval_ledger() for n in chosen}
  heads={n:ledgers[n]["head_sha256"] for n in chosen}
  self.registry_head="d"*64
  self.bundle={"schema":BUNDLE_SCHEMA,
   "policy_registry_state":{"generation":7,"policy":self.policy,
      "policy_sha256":policy_digest(self.policy),"head_sha256":self.registry_head},
   "policy":self.policy,"before_manifest":before,"after_manifest":after,
   "current_state":current,"next_state":next_state,"transition":transition,
   "authority_ledgers":ledgers,"authority_heads":heads}
 def check(self,bundle=None,head=None):
  return verify_recovery_bundle(self.bundle if bundle is None else bundle,
   self.registry_head if head is None else head)
 def test_complete_bundle_verifies(self): self.assertTrue(self.check())
 def test_wrong_pinned_policy_registry_head_rejected(self): self.assertFalse(self.check(head="f"*64))
 def test_policy_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["policy"]["threshold"]=2
  self.assertFalse(self.check(b))
 def test_registry_policy_digest_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["policy_registry_state"]["policy_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_missing_authority_ledger_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_ledgers"].pop("r2")
  self.assertFalse(self.check(b))
 def test_stale_authority_head_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_heads"]["r1"]="0"*64
  self.assertFalse(self.check(b))
 def test_transition_approval_bundle_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["transition"]["recovery_signature"]="00"
  self.assertFalse(self.check(b))
 def test_old_key_revocation_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["after_manifest"]["revoked_key_hex"]=[]
  self.assertFalse(self.check(b))
 def test_final_witness_key_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["after_manifest"]["public_keys"]["witness"]=pub(Ed25519PrivateKey.generate())
  self.assertFalse(self.check(b))
 def test_extra_bundle_field_rejected(self):
  b=copy.deepcopy(self.bundle); b["success"]=True
  self.assertFalse(self.check(b))
