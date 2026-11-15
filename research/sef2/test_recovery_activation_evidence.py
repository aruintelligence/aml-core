import copy,unittest
from test_recovery_activation_registry import RecoveryActivationRegistryTests
from recovery_activation_evidence import verify_activation_evidence

class RecoveryActivationEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.fixture=RecoveryActivationRegistryTests("test_valid_cutover_advances_active_policy")
  self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
  self.assertEqual(self.fixture.activate(),"ACTIVATED")
  self.bundle=self.fixture.registry.export_evidence()
 def check(self,bundle=None,head=None):
  return verify_activation_evidence(bundle or self.bundle,self.fixture.old,1,
   self.fixture.pins,3,1,self.fixture.manifest,self.fixture.manifest_pin,
   self.bundle["state"]["head_sha256"] if head is None else head)
 def test_external_auditor_accepts_complete_activation_history(self):
  self.assertTrue(self.check())
 def test_tampered_cutover_certificate_rejected(self):
  b=copy.deepcopy(self.bundle)
  b["events"][0]["certificate"]["acks"][0]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_event_hash_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["event_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_old_policy_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["previous_policy_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_final_state_rollback_rejected(self):
  b=copy.deepcopy(self.bundle); b["state"]["generation"]=1
  self.assertFalse(self.check(b))
 def test_external_head_pin_mismatch_rejected(self):
  self.assertFalse(self.check(head="f"*64))
 def test_missing_event_rejected_when_state_is_advanced(self):
  b=copy.deepcopy(self.bundle); b["events"]=[]
  self.assertFalse(self.check(b))
