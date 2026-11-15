import json,pathlib,tempfile,unittest
from test_recovery_policy_rotation import RecoveryPolicyRotationTests
from evaluation_kit.verify_recovery_policy_rotation import main
from threshold_recovery import policy_digest

class RecoveryPolicyRotationCliTests(unittest.TestCase):
 def setUp(self):
  self.fixture=RecoveryPolicyRotationTests("test_rotation_requires_and_accepts_both_quorums")
  self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.current=root/"current.json"; self.next=root/"next.json"; self.rotation=root/"rotation.json"
  self.current.write_text(json.dumps(self.fixture.current))
  self.next.write_text(json.dumps(self.fixture.next))
  self.rotation.write_text(json.dumps(self.fixture.bundle))
  self.pin=policy_digest(self.fixture.current)
 def args(self):
  return ["--current-policy",str(self.current),"--next-policy",str(self.next),
   "--rotation",str(self.rotation),"--pinned-current-policy-sha256",self.pin,
   "--expected-generation","2"]
 def test_cli_accepts_valid_dual_quorum_rotation(self):
  self.assertEqual(main(self.args()),0)
 def test_cli_rejects_wrong_current_policy_pin(self):
  args=self.args(); args[args.index("--pinned-current-policy-sha256")+1]="f"*64
  self.assertEqual(main(args),2)
 def test_cli_rejects_generation_mismatch(self):
  args=self.args(); args[args.index("--expected-generation")+1]="3"
  self.assertEqual(main(args),2)
 def test_cli_rejects_tampered_incoming_signature(self):
  data=json.loads(self.rotation.read_text())
  data["incoming_acceptance"]["approvals"][0]["signature"]="00"*64
  self.rotation.write_text(json.dumps(data))
  self.assertEqual(main(self.args()),2)
 def test_cli_rejects_duplicate_json_keys(self):
  self.next.write_text('{"schema":"x","schema":"y"}')
  self.assertEqual(main(self.args()),2)
