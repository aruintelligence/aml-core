import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import (POLICY_SCHEMA,RecoveryAuthoritySigner,
    make_threshold_transition,policy_digest)
from witness_key_recovery import key_fingerprint
from recovery_transparency import (build_recovery_transparency_bundle,
    verify_recovery_transparency_bundle)

def cp(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
  "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class RecoveryTransparencyTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy={"schema":POLICY_SCHEMA,"policy_id":"council-1","threshold":3,"max_faults":1,
   "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in self.keys.items()}}
  self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  self.state={"witness_id":"north","generation":0,
   "public_key_sha256":key_fingerprint(self.old.public_key().public_bytes_raw().hex()),
   "checkpoint":cp(),"transition_sha256":"0"*64}
  self.signers={}
  for i in range(3):
   name=f"authority-{i}"
   self.signers[name]=RecoveryAuthoritySigner(name,self.keys[name],
    pathlib.Path(self.temp.name)/(name+".sqlite"))
  self.transition=make_threshold_transition(self.new,"north",self.state,cp(2,"b"*64),
   self.policy,self.signers)
  self.ledgers={name:signer.export_approval_ledger() for name,signer in self.signers.items()}
  self.heads={name:ledger["head_sha256"] for name,ledger in self.ledgers.items()}
  self.bundle=build_recovery_transparency_bundle(self.state,self.transition,self.policy,self.ledgers)
  self.pin=policy_digest(self.policy)
 def check(self,bundle=None,state=None,policy=None,heads=None,pin=None):
  return verify_recovery_transparency_bundle(bundle or self.bundle,state or self.state,
   policy or self.policy,self.pin if pin is None else pin,self.heads if heads is None else heads)
 def test_external_auditor_accepts_complete_recovery_evidence(self):
  self.assertTrue(self.check())
 def test_policy_pin_substitution_rejected(self):
  self.assertFalse(self.check(pin="f"*64))
 def test_predecessor_state_substitution_rejected(self):
  changed=dict(self.state,generation=1)
  self.assertFalse(self.check(state=changed))
 def test_transition_payload_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["transition"]["payload"]["generation"]+=1
  self.assertFalse(self.check(bundle=b))
 def test_missing_approver_ledger_rejected(self):
  b=copy.deepcopy(self.bundle); del b["authority_ledgers"]["authority-2"]
  self.assertFalse(self.check(bundle=b))
 def test_extra_unapproved_ledger_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_ledgers"]["authority-3"]=self.ledgers["authority-0"]
  self.assertFalse(self.check(bundle=b))
 def test_stale_authority_head_pin_rejected(self):
  heads=dict(self.heads); heads["authority-0"]="0"*64
  self.assertFalse(self.check(heads=heads))
 def test_ledger_event_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_ledgers"]["authority-0"]["events"][0]["payload_sha256"]="f"*64
  self.assertFalse(self.check(bundle=b))
 def test_approval_signature_not_present_in_ledger_rejected(self):
  b=copy.deepcopy(self.bundle)
  b["authority_ledgers"]["authority-0"]["events"][0]["signature"]="00"*64
  self.assertFalse(self.check(bundle=b))
 def test_wrong_policy_key_rejected(self):
  p=copy.deepcopy(self.policy)
  p["authorities"]["authority-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(self.check(policy=p))
 def test_builder_requires_exact_approver_ledgers(self):
  with self.assertRaises(ValueError):
   build_recovery_transparency_bundle(self.state,self.transition,self.policy,
    {"authority-0":self.ledgers["authority-0"]})
