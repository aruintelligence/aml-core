import copy,json,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import canonical
from trust_enrollment import Enrollment,propose
from witness_recovery_enrollment import WitnessRecoveryEnrollment
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_POLICY_SCHEMA,RecoveryAnchorWitness
from anchored_threshold_recovery import (AnchoredThresholdRecoveryPublicKey,
    make_anchored_threshold_transition)

def make_policy(keys,policy_id,schema=POLICY_SCHEMA):
 result={"schema":schema,"policy_id":policy_id,"threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
 if schema==ANCHOR_POLICY_SCHEMA:
  result["administrative_domains"]={k:"operator-domain-"+k for k in keys}
 return result
def checkpoint(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
   "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class AnchoredThresholdRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.trust_path=str(pathlib.Path(self.temp.name)/"trust.sqlite")
  self.recovery_path=str(pathlib.Path(self.temp.name)/"recovery.sqlite")
  self.approver=Ed25519PrivateKey.generate(); self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  self.trust_keys={"authority":self.approver.public_key().public_bytes_raw().hex(),
   "provider":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
   "witness":self.old.public_key().public_bytes_raw().hex()}
  self.enrollment=Enrollment(self.trust_path,self.approver.public_key())
  self.assertEqual(self.enrollment.accept(propose(self.approver,1,self.trust_keys)),"ENROLLED")
  self.recovery_keys={f"recovery-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.recovery_policy=make_policy(self.recovery_keys,"recovery-council-v1")
  self.recovery_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.recovery_keys.items()}
  self.anchor_keys={f"anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.anchor_policy=make_policy(self.anchor_keys,"anchor-council-v1",ANCHOR_POLICY_SCHEMA)
  self.anchor_witnesses={k:RecoveryAnchorWitness(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.anchor_keys.items()}
  self.initial_pin="0"*64
  self.coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,
   AnchoredThresholdRecoveryPublicKey(self.recovery_policy,self.anchor_policy,self.initial_pin),
   self.recovery_policy["policy_id"])
  self.state=self.coordinator.initialize("north",checkpoint())
  self.transition,self.next_pin=make_anchored_threshold_transition(self.new,"north",self.state,
   checkpoint(2,"b"*64),self.recovery_policy,
   {k:self.recovery_signers[k] for k in ("recovery-0","recovery-1","recovery-2")},
   self.anchor_policy,{k:self.anchor_witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")},
   self.initial_pin)
 def test_two_independent_quorums_authorize_and_anchor_real_recovery(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  manifest=self.enrollment.manifest()
  self.assertEqual(manifest["public_keys"]["witness"],self.new.public_key().public_bytes_raw().hex())
  self.assertIn(self.old.public_key().public_bytes_raw().hex(),manifest["revoked_key_hex"])
 def test_below_threshold_recovery_bundle_rejected(self):
  bad=copy.deepcopy(self.transition)
  composite=json.loads(bytes.fromhex(bad["recovery_signature"]))
  composite["threshold_bundle"]["approvals"]=composite["threshold_bundle"]["approvals"][:2]
  bad["recovery_signature"]=canonical(composite).hex()
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
 def test_anchor_certificate_tampering_rejected(self):
  bad=copy.deepcopy(self.transition)
  composite=json.loads(bytes.fromhex(bad["recovery_signature"]))
  composite["anchor_certificate"]["approvals"][0]["signature"]="00"*64
  bad["recovery_signature"]=canonical(composite).hex()
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
 def test_wrong_external_previous_pin_rejected(self):
  coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,
   AnchoredThresholdRecoveryPublicKey(self.recovery_policy,self.anchor_policy,"f"*64),
   self.recovery_policy["policy_id"])
  self.assertEqual(coordinator.recover("north",self.transition),"INVALID_RECOVERY")
 def test_anchor_head_must_bind_exact_threshold_payload(self):
  bad=copy.deepcopy(self.transition)
  composite=json.loads(bytes.fromhex(bad["recovery_signature"]))
  composite["anchor_payload"]["checkpoint"]["head_hash"]="d"*64
  bad["recovery_signature"]=canonical(composite).hex()
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
 def test_wrong_anchor_council_rejected(self):
  other_keys={f"other-anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  other_policy=make_policy(other_keys,"other-anchor-council",ANCHOR_POLICY_SCHEMA)
  coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,
   AnchoredThresholdRecoveryPublicKey(self.recovery_policy,other_policy,self.initial_pin),
   self.recovery_policy["policy_id"])
  self.assertEqual(coordinator.recover("north",self.transition),"INVALID_RECOVERY")
 def test_replay_rejected_after_success(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  self.assertEqual(self.coordinator.recover("north",self.transition),"INVALID_RECOVERY")
 def test_anchor_pin_is_returned_for_independent_verifier_state(self):
  self.assertEqual(len(self.next_pin),64)
  self.assertNotEqual(self.next_pin,self.initial_pin)

 def test_two_successive_anchored_recoveries_advance_both_quorums(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  second_key=Ed25519PrivateKey.generate()
  current=self.coordinator.state("north")
  second,second_pin=make_anchored_threshold_transition(second_key,"north",current,
   checkpoint(3,"c"*64),self.recovery_policy,
   {k:self.recovery_signers[k] for k in ("recovery-0","recovery-1","recovery-2")},
   self.anchor_policy,{k:self.anchor_witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")},
   self.next_pin)
  next_coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,
   AnchoredThresholdRecoveryPublicKey(self.recovery_policy,self.anchor_policy,self.next_pin),
   self.recovery_policy["policy_id"])
  self.assertEqual(next_coordinator.recover("north",second),"RECOVERED")
  self.assertEqual(next_coordinator.state("north")["generation"],2)
  self.assertNotEqual(second_pin,self.next_pin)
  manifest=self.enrollment.manifest()
  self.assertEqual(manifest["public_keys"]["witness"],second_key.public_key().public_bytes_raw().hex())
  self.assertIn(self.old.public_key().public_bytes_raw().hex(),manifest["revoked_key_hex"])

 def test_anchor_certificate_is_independently_verified(self):
  from recovery_anchor_reference_verifier import verify_anchor_certificate
  composite=json.loads(bytes.fromhex(self.transition["recovery_signature"]))
  self.assertTrue(verify_anchor_certificate(composite["anchor_payload"],
   composite["anchor_certificate"],self.anchor_policy,1,self.initial_pin,
   self.recovery_policy["policy_id"],
   __import__("anchored_threshold_recovery").authority_set_fingerprint(self.recovery_policy)))
