import copy,json,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
from recovery_ledger_reference_verifier import verify_ledger,canonical

class IndependentRecoveryLedgerVerifierTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.key=Ed25519PrivateKey.generate()
  self.public=self.key.public_key().public_bytes_raw().hex()
  self.signer=RecoveryAuthoritySigner("authority-x",self.key,str(Path(self.temp.name)/"authority.sqlite"))
  self.policy={"schema":"AML-SEF2-RECOVERY-QUORUM-POLICY-V1","policy_id":"council-x",
   "threshold":3,"max_faults":1,"authorities":{f"authority-{i}":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex() for i in range(3)}}
  self.policy["authorities"]["authority-x"]=self.public
  self.payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64,"new_key":"b"*64}
  self.signer.approve(self.payload,self.policy)
  self.bundle=self.signer.export_approval_ledger()
 def test_independent_verifier_accepts_exported_ledger(self):
  self.assertTrue(verify_ledger(self.bundle,self.public,self.bundle["head_sha256"]))
 def test_wrong_public_key_rejected(self):
  other=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(verify_ledger(self.bundle,other))
 def test_modified_event_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["payload_sha256"]="f"*64
  self.assertFalse(verify_ledger(b,self.public))
 def test_reordered_events_rejected(self):
  self.signer.approve({**self.payload,"generation":2,"previous_state_sha256":"c"*64},self.policy)
  b=self.signer.export_approval_ledger(); b["events"].reverse()
  self.assertFalse(verify_ledger(b,self.public))
 def test_truncated_ledger_rejected_against_external_head(self):
  self.signer.approve({**self.payload,"generation":2,"previous_state_sha256":"c"*64},self.policy)
  full=self.signer.export_approval_ledger()
  truncated=copy.deepcopy(full); truncated["events"]=truncated["events"][:1]
  truncated["head_sha256"]=truncated["events"][-1]["event_sha256"]
  self.assertTrue(verify_ledger(truncated,self.public))
  self.assertFalse(verify_ledger(truncated,self.public,full["head_sha256"]))
 def test_duplicate_scope_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"].append(copy.deepcopy(b["events"][0]))
  self.assertFalse(verify_ledger(b,self.public))
 def test_duplicate_json_keys_rejected(self):
  raw=canonical(self.bundle).decode().replace('"schema":','"schema":"shadow","schema":',1)
  self.assertFalse(verify_ledger(raw,self.public))
 def test_wrong_external_pin_rejected(self):
  self.assertFalse(verify_ledger(self.bundle,self.public,"f"*64))
 def test_bundle_from_different_authority_id_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_id"]="other"
  self.assertFalse(verify_ledger(b,self.public))
 def test_missing_external_pin_is_explicitly_integrity_only(self):
  self.assertTrue(verify_ledger(self.bundle,self.public))
