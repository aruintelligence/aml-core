import copy,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
from recovery_anchor_quorum import POLICY_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate
from recovery_anchor_policy_rotation import make_anchor_policy_rotation
from recovery_anchor_reenrollment import make_anchor_reenrollment
from recovery_anchor_reenrollment_verified import verify_and_install_anchor_reenrollment
from recovery_ledger_anchor import CHECKPOINT_SCHEMA,checkpoint_pin

def policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:name+"-"+k for k in keys}}
class VerifiedAnchorReenrollmentTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.old_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.old=policy(self.old_keys,"anchor-v1"); self.new=policy(self.new_keys,"anchor-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".approval.sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".approval.sqlite"))) for k,v in self.new_keys.items()}
  self.old_witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".anchor.sqlite"))) for k,v in self.old_keys.items()}
  self.rotation=make_anchor_policy_rotation(self.old,self.new,2,"a"*64,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
  self.target="authority-x"; self.authority_key="c"*64
  self.checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":self.target,
   "authority_key_sha256":self.authority_key,"sequence":1,"head_hash":"d"*64}
  self.anchor_payload=make_anchor_payload(self.checkpoint,1,"0"*64,self.old)
  self.anchor_cert=make_anchor_certificate(self.anchor_payload,self.old,
   {k:self.old_witnesses[k] for k in ("old-0","old-1","old-2")})
  self.current_pin=checkpoint_pin(self.checkpoint)
  self.proof=make_anchor_reenrollment(self.old,self.new,self.rotation,2,"a"*64,
   self.target,1,self.current_pin,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
  self.successor=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],str(root/"successor.sqlite"))
 def install(self,payload=None,cert=None,prev="0"*64,key=None):
  return verify_and_install_anchor_reenrollment(self.successor,self.old,self.new,self.rotation,self.proof,
   2,"a"*64,payload or self.anchor_payload,cert or self.anchor_cert,prev,self.target,key or self.authority_key)
 def test_historically_verified_state_transfer_installs(self):
  self.assertEqual(self.install(),"INSTALLED")
 def test_forged_old_anchor_certificate_rejected(self):
  cert=copy.deepcopy(self.anchor_cert); cert["approvals"][0]["signature"]="00"*64
  self.assertEqual(self.install(cert=cert),"INVALID_CURRENT_ANCHOR")
 def test_wrong_old_anchor_predecessor_pin_rejected(self):
  self.assertEqual(self.install(prev="f"*64),"INVALID_CURRENT_ANCHOR")
 def test_wrong_authority_key_pin_rejected(self):
  self.assertEqual(self.install(key="f"*64),"INVALID_CURRENT_ANCHOR")
 def test_substituted_current_checkpoint_rejected(self):
  payload=copy.deepcopy(self.anchor_payload); payload["checkpoint"]["head_hash"]="e"*64
  self.assertEqual(self.install(payload=payload),"INVALID_CURRENT_ANCHOR")
 def test_reenrollment_proof_for_different_pin_rejected(self):
  bad=copy.deepcopy(self.proof); bad["payload"]["current_pin"]="f"*64
  from signed_receipt import canonical
  self.assertEqual(verify_and_install_anchor_reenrollment(self.successor,self.old,self.new,self.rotation,bad,
   2,"a"*64,self.anchor_payload,self.anchor_cert,"0"*64,self.target,self.authority_key),"INVALID_REENROLLMENT")
