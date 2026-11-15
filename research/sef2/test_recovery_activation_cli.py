import json,pathlib,tempfile,unittest
from test_recovery_activation_registry import RecoveryActivationRegistryTests
from evaluation_kit.verify_recovery_activation import main

class RecoveryActivationCliTests(unittest.TestCase):
 def setUp(self):
  self.fixture=RecoveryActivationRegistryTests("test_valid_cutover_advances_active_policy")
  self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
  self.assertEqual(self.fixture.activate(),"ACTIVATED")
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.bundle=root/"bundle.json"; self.keys=root/"keys.json"; self.domains=root/"domains.json"
  self.bundle.write_text(json.dumps(self.fixture.registry.export_evidence()))
  self.keys.write_text(json.dumps(self.fixture.pins))
  self.domains.write_text(json.dumps(self.fixture.manifest))
  self.head=self.fixture.registry.state()["head_sha256"]
 def args(self):
  return ["--bundle",str(self.bundle),"--initial-policy-sha256",self.fixture.old,
   "--initial-generation","1","--verifier-keys",str(self.keys),
   "--threshold","3","--max-faults","1","--verifier-domains",str(self.domains),
   "--pinned-verifier-domains-sha256",self.fixture.manifest_pin,
   "--expected-head-sha256",self.head]
 def test_cli_accepts_complete_activation_history(self):
  self.assertEqual(main(self.args()),0)
 def test_cli_rejects_wrong_external_head(self):
  args=self.args(); args[args.index("--expected-head-sha256")+1]="f"*64
  self.assertEqual(main(args),2)
 def test_cli_rejects_tampered_bundle(self):
  data=json.loads(self.bundle.read_text()); data["state"]["generation"]=1
  self.bundle.write_text(json.dumps(data))
  self.assertEqual(main(self.args()),2)
 def test_cli_rejects_duplicate_json_keys(self):
  self.keys.write_text('{"verifier-0":"a","verifier-0":"b"}')
  self.assertEqual(main(self.args()),2)
