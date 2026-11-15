import json,pathlib,tempfile,unittest
from test_recovery_cutover import RecoveryCutoverTests
from evaluation_kit.verify_recovery_cutover import main

class RecoveryCutoverCliTests(unittest.TestCase):
 def setUp(self):
  self.fixture=RecoveryCutoverTests("test_three_of_four_activation_certificate_accepts")
  self.fixture.setUp()
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.cert=root/"cert.json"; self.rotation=root/"rotation.json"; self.keys=root/"keys.json"; self.domains=root/"domains.json"
  self.cert.write_text(json.dumps(self.fixture.cert))
  self.rotation.write_text(json.dumps(self.fixture.rotation))
  self.keys.write_text(json.dumps(self.fixture.pins))
  import hashlib
  from witness_independence import DIMENSIONS,independence_digest
  self.manifest={"witnesses":{name:{**{d:name+"-"+d for d in DIMENSIONS},
   "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()} for name,raw in self.fixture.pins.items()}}
  self.domains.write_text(json.dumps(self.manifest)); self.domains_pin=independence_digest(self.manifest)
 def args(self):
  return ["--certificate",str(self.cert),"--rotation",str(self.rotation),
   "--next-policy-sha256",self.fixture.policy_sha,"--generation",str(self.fixture.generation),
   "--verifier-keys",str(self.keys),"--verifier-domains",str(self.domains),
   "--pinned-verifier-domains-sha256",self.domains_pin,
   "--threshold","3","--max-faults","1"]
 def test_cli_accepts_valid_cutover(self):
  self.assertEqual(main(self.args()),0)
 def test_cli_rejects_partial_cutover(self):
  data=json.loads(self.cert.read_text()); data["acks"]=data["acks"][:2]
  self.cert.write_text(json.dumps(data))
  self.assertEqual(main(self.args()),2)
 def test_cli_rejects_bad_generation(self):
  args=self.args(); args[args.index("--generation")+1]="3"
  self.assertEqual(main(args),2)
 def test_cli_rejects_duplicate_json_keys(self):
  self.keys.write_text('{"verifier-0":"a","verifier-0":"b"}')
  self.assertEqual(main(self.args()),2)

 def test_cli_rejects_shared_verifier_operator(self):
  data=json.loads(self.domains.read_text())
  data["witnesses"]["verifier-1"]["operator"]=data["witnesses"]["verifier-0"]["operator"]
  self.domains.write_text(json.dumps(data))
  self.assertEqual(main(self.args()),2)
 def test_cli_rejects_wrong_independence_manifest_pin(self):
  args=self.args(); args[args.index("--pinned-verifier-domains-sha256")+1]="f"*64
  self.assertEqual(main(args),2)
