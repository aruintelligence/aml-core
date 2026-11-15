import json,pathlib,tempfile,unittest
from test_recovery_transparency import RecoveryTransparencyTests
from evaluation_kit.verify_recovery_transparency import main

class RecoveryTransparencyCliTests(unittest.TestCase):
 def setUp(self):
  self.fixture=RecoveryTransparencyTests("test_external_auditor_accepts_complete_recovery_evidence")
  self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.bundle=root/"bundle.json"; self.state=root/"state.json"; self.policy=root/"policy.json"; self.heads=root/"heads.json"
  self.bundle.write_text(json.dumps(self.fixture.bundle)); self.state.write_text(json.dumps(self.fixture.state))
  self.policy.write_text(json.dumps(self.fixture.policy)); self.heads.write_text(json.dumps(self.fixture.heads))
 def args(self):
  return ["--bundle",str(self.bundle),"--current-state",str(self.state),"--policy",str(self.policy),
    "--pinned-policy-sha256",self.fixture.pin,"--authority-heads",str(self.heads)]
 def test_cli_accepts_complete_external_evidence(self):
  self.assertEqual(main(self.args()),0)
 def test_cli_rejects_wrong_policy_pin(self):
  args=self.args(); args[args.index("--pinned-policy-sha256")+1]="f"*64
  self.assertEqual(main(args),2)
 def test_cli_rejects_duplicate_json_keys(self):
  self.heads.write_text('{"authority-0":"a","authority-0":"b"}')
  self.assertEqual(main(self.args()),2)
 def test_cli_rejects_tampered_bundle(self):
  data=json.loads(self.bundle.read_text()); data["transition"]["payload"]["generation"]+=1
  self.bundle.write_text(json.dumps(data))
  self.assertEqual(main(self.args()),2)
