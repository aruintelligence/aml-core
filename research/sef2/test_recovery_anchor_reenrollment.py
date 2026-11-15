import copy,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
from recovery_anchor_quorum import POLICY_SCHEMA,RecoveryAnchorWitness,make_anchor_payload
from recovery_anchor_policy_rotation import make_anchor_policy_rotation
from recovery_anchor_reenrollment import make_anchor_reenrollment,verify_anchor_reenrollment,install_anchor_reenrollment
def policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:name+"-"+k for k in keys}}
class AnchorReenrollmentTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.old_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.old=policy(self.old_keys,"anchor-v1"); self.new=policy(self.new_keys,"anchor-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".approval.sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".approval.sqlite"))) for k,v in self.new_keys.items()}
  self.rotation=make_anchor_policy_rotation(self.old,self.new,2,"a"*64,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
  self.proof=make_anchor_reenrollment(self.old,self.new,self.rotation,2,"a"*64,"authority-x",5,"b"*64,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
  self.witness=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],str(root/"new-0.anchor.sqlite"))
 def check(self,p=None,seq=5,pin="b"*64):
  return verify_anchor_reenrollment(self.old,self.new,self.rotation,p or self.proof,2,"a"*64,"authority-x",seq,pin)
 def test_dual_consent_state_transfer_accepts(self): self.assertTrue(self.check())
 def test_fresh_successor_witness_installs_exact_state_and_continues(self):
  self.assertEqual(install_anchor_reenrollment(self.witness,self.old,self.new,self.rotation,self.proof,2,"a"*64,"authority-x",5,"b"*64),"INSTALLED")
  checkpoint={"schema":"AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1","authority_id":"authority-x","authority_key_sha256":"c"*64,"sequence":6,"head_hash":"d"*64}
  payload=make_anchor_payload(checkpoint,6,"b"*64,self.new)
  self.assertEqual(len(self.witness.approve(payload,self.new)),128)
 def test_reenrollment_is_idempotent(self):
  self.assertEqual(install_anchor_reenrollment(self.witness,self.old,self.new,self.rotation,self.proof,2,"a"*64,"authority-x",5,"b"*64),"INSTALLED")
  self.assertEqual(install_anchor_reenrollment(self.witness,self.old,self.new,self.rotation,self.proof,2,"a"*64,"authority-x",5,"b"*64),"ALREADY_INSTALLED")
 def test_wrong_current_pin_rejected(self): self.assertFalse(self.check(pin="f"*64))
 def test_wrong_current_sequence_rejected(self): self.assertFalse(self.check(seq=4))
 def test_tampered_incoming_acceptance_rejected(self):
  p=copy.deepcopy(self.proof); p["incoming_state_acceptance"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(p))
 def test_old_witness_cannot_be_installed_as_successor(self):
  old_witness=RecoveryAnchorWitness("old-0",self.old_keys["old-0"],str(Path(self.temp.name)/"old.anchor.sqlite"))
  self.assertEqual(install_anchor_reenrollment(old_witness,self.old,self.new,self.rotation,self.proof,2,"a"*64,"authority-x",5,"b"*64),"WITNESS_NOT_IN_SUCCESSOR_POLICY")
 def test_conflicting_preexisting_state_rejected(self):
  checkpoint={"schema":"AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1","authority_id":"authority-x","authority_key_sha256":"c"*64,"sequence":1,"head_hash":"d"*64}
  self.witness.approve(make_anchor_payload(checkpoint,1,"0"*64,self.new),self.new)
  self.assertEqual(install_anchor_reenrollment(self.witness,self.old,self.new,self.rotation,self.proof,2,"a"*64,"authority-x",5,"b"*64),"STATE_CONFLICT")

 def test_three_successor_witnesses_resume_quorum_at_next_sequence(self):
  from recovery_anchor_quorum import make_anchor_certificate,verify_anchor_certificate
  witnesses={}
  for name in ("new-0","new-1","new-2"):
   witness=RecoveryAnchorWitness(name,self.new_keys[name],str(Path(self.temp.name)/(name+".resume.sqlite")))
   self.assertEqual(install_anchor_reenrollment(witness,self.old,self.new,self.rotation,self.proof,
    2,"a"*64,"authority-x",5,"b"*64),"INSTALLED")
   witnesses[name]=witness
  checkpoint={"schema":"AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1",
   "authority_id":"authority-x","authority_key_sha256":"c"*64,"sequence":6,"head_hash":"e"*64}
  payload=make_anchor_payload(checkpoint,6,"b"*64,self.new)
  cert=make_anchor_certificate(payload,self.new,witnesses)
  self.assertTrue(verify_anchor_certificate(payload,cert,self.new,6,"b"*64,"authority-x","c"*64))

 def test_two_successor_witnesses_cannot_form_new_quorum(self):
  from recovery_anchor_quorum import make_anchor_certificate
  witnesses={}
  for name in ("new-0","new-1"):
   witness=RecoveryAnchorWitness(name,self.new_keys[name],str(Path(self.temp.name)/(name+".short.sqlite")))
   self.assertEqual(install_anchor_reenrollment(witness,self.old,self.new,self.rotation,self.proof,
    2,"a"*64,"authority-x",5,"b"*64),"INSTALLED")
   witnesses[name]=witness
  checkpoint={"schema":"AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1",
   "authority_id":"authority-x","authority_key_sha256":"c"*64,"sequence":6,"head_hash":"e"*64}
  payload=make_anchor_payload(checkpoint,6,"b"*64,self.new)
  with self.assertRaises(ValueError):
   make_anchor_certificate(payload,self.new,witnesses)
