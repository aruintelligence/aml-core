import copy,hashlib,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_activation_registry import RecoveryActivationRegistry
from recovery_activation_attestation import RecoveryActivationAttestor,verify_activation_commit_quorum
from recovery_cutover import build_cutover_certificate,make_cutover_ack
from witness_independence import DIMENSIONS,independence_digest

class RecoveryActivationAttestationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.old="a"*64; self.new="b"*64; self.generation=2
  self.rotation={"schema":"rotation","payload":{"generation":2,
   "previous_policy_sha256":self.old,"next_policy_sha256":self.new}}
  self.keys={f"verifier-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.pins={n:k.public_key().public_bytes_raw().hex() for n,k in self.keys.items()}
  prep=[make_cutover_ack(self.keys[n],n,self.rotation,self.new,2)
   for n in ("verifier-0","verifier-1","verifier-2")]
  self.cert=build_cutover_certificate(self.rotation,self.new,2,prep)
  self.manifest={"witnesses":{name:{**{d:name+"-"+d for d in DIMENSIONS},
   "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
   for name,raw in self.pins.items()}}
  self.manifest_pin=independence_digest(self.manifest)
  self.registries={}
  self.attestors={}
  for name in self.keys:
   registry=RecoveryActivationRegistry(pathlib.Path(self.tmp.name)/(name+".sqlite"))
   registry.initialize(self.old,1)
   self.registries[name]=registry
   self.attestors[name]=RecoveryActivationAttestor(name,self.keys[name],registry)
 def activate(self,name):
  return self.registries[name].activate(self.cert,self.rotation,self.new,2,
   self.pins,3,1,self.manifest,self.manifest_pin)
 def test_attestor_refuses_to_sign_before_local_commit(self):
  with self.assertRaises(PermissionError):
   self.attestors["verifier-0"].attest(2,self.new,"f"*64)
 def test_three_committed_verifiers_form_post_commit_quorum(self):
  for name in ("verifier-0","verifier-1","verifier-2"): self.assertEqual(self.activate(name),"ACTIVATED")
  head=self.registries["verifier-0"].state()["head_sha256"]
  self.assertEqual({self.registries[n].state()["head_sha256"] for n in ("verifier-0","verifier-1","verifier-2")},{head})
  attestations=[self.attestors[n].attest(2,self.new,head) for n in ("verifier-0","verifier-1","verifier-2")]
  self.assertTrue(verify_activation_commit_quorum(attestations,2,self.new,head,
   self.pins,3,1,self.manifest,self.manifest_pin))
 def test_one_stale_verifier_cannot_fake_commit_but_three_current_still_suffice(self):
  for name in ("verifier-0","verifier-1","verifier-2"): self.activate(name)
  head=self.registries["verifier-0"].state()["head_sha256"]
  with self.assertRaises(PermissionError):
   self.attestors["verifier-3"].attest(2,self.new,head)
  attestations=[self.attestors[n].attest(2,self.new,head) for n in ("verifier-0","verifier-1","verifier-2")]
  self.assertTrue(verify_activation_commit_quorum(attestations,2,self.new,head,
   self.pins,3,1,self.manifest,self.manifest_pin))
 def test_two_committed_verifiers_cannot_form_quorum(self):
  for name in ("verifier-0","verifier-1"): self.activate(name)
  head=self.registries["verifier-0"].state()["head_sha256"]
  attestations=[self.attestors[n].attest(2,self.new,head) for n in ("verifier-0","verifier-1")]
  self.assertFalse(verify_activation_commit_quorum(attestations,2,self.new,head,
   self.pins,3,1,self.manifest,self.manifest_pin))
 def test_duplicate_attestation_rejected(self):
  for name in ("verifier-0","verifier-1","verifier-2"): self.activate(name)
  head=self.registries["verifier-0"].state()["head_sha256"]
  a=self.attestors["verifier-0"].attest(2,self.new,head)
  attestations=[a,copy.deepcopy(a),self.attestors["verifier-1"].attest(2,self.new,head)]
  self.assertFalse(verify_activation_commit_quorum(attestations,2,self.new,head,
   self.pins,3,1,self.manifest,self.manifest_pin))
 def test_tampered_signature_rejected(self):
  for name in ("verifier-0","verifier-1","verifier-2"): self.activate(name)
  head=self.registries["verifier-0"].state()["head_sha256"]
  attestations=[self.attestors[n].attest(2,self.new,head) for n in ("verifier-0","verifier-1","verifier-2")]
  attestations[0]["signature"]="00"*64
  self.assertFalse(verify_activation_commit_quorum(attestations,2,self.new,head,
   self.pins,3,1,self.manifest,self.manifest_pin))
