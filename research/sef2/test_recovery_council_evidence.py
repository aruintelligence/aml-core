import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA,make_approval_bundle
from recovery_council_evidence import verify_recovery_council_evidence

def make_policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"council-transparency","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryCouncilEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.keys)
  self.payload={"witness_id":"north","generation":9,"previous_state_sha256":"a"*64}
  self.signers={name:RecoveryAuthoritySigner(name,self.keys[name],
      pathlib.Path(self.tmp.name)/(name+".sqlite")) for name in self.keys}
  chosen={name:self.signers[name] for name in ("authority-0","authority-1","authority-2")}
  self.bundle=make_approval_bundle(self.payload,self.policy,chosen)
  self.ledgers={name:self.signers[name].export_approval_ledger() for name in chosen}
  self.heads={name:self.ledgers[name]["head_sha256"] for name in chosen}
 def check(self,bundle=None,ledgers=None,heads=None,policy=None,payload=None):
  return verify_recovery_council_evidence(self.payload if payload is None else payload,
   self.bundle if bundle is None else bundle,self.policy if policy is None else policy,
   self.ledgers if ledgers is None else ledgers,self.heads if heads is None else heads)
 def test_threshold_bundle_is_backed_by_each_independent_authority_ledger(self):
  self.assertTrue(self.check())
 def test_missing_authority_ledger_rejected(self):
  ledgers=dict(self.ledgers); ledgers.pop("authority-2")
  self.assertFalse(self.check(ledgers=ledgers))
 def test_missing_expected_head_rejected(self):
  heads=dict(self.heads); heads.pop("authority-2")
  self.assertFalse(self.check(heads=heads))
 def test_stale_authority_head_rejected(self):
  heads=dict(self.heads); heads["authority-1"]="0"*64
  self.assertFalse(self.check(heads=heads))
 def test_bundle_signature_not_present_in_ledger_rejected(self):
  bundle=copy.deepcopy(self.bundle); bundle["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(bundle=bundle))
 def test_ledger_event_payload_substitution_rejected(self):
  ledgers=copy.deepcopy(self.ledgers)
  ledgers["authority-0"]["events"][0]["payload_sha256"]="f"*64
  self.assertFalse(self.check(ledgers=ledgers))
 def test_policy_key_substitution_rejected(self):
  policy=copy.deepcopy(self.policy)
  policy["authorities"]["authority-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(self.check(policy=policy))
 def test_payload_substitution_rejected(self):
  self.assertFalse(self.check(payload={**self.payload,"generation":10}))
 def test_extra_unapproved_authority_ledger_rejected(self):
  ledgers=dict(self.ledgers); heads=dict(self.heads)
  ledgers["authority-3"]=self.signers["authority-3"].export_approval_ledger()
  heads["authority-3"]=ledgers["authority-3"]["head_sha256"]
  self.assertFalse(self.check(ledgers=ledgers,heads=heads))
