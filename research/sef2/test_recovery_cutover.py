import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_cutover import (build_cutover_certificate,make_cutover_ack,
 verify_cutover_certificate)

class RecoveryCutoverTests(unittest.TestCase):
 def setUp(self):
  self.rotation={"schema":"rotation","payload":{"generation":2}}
  self.policy_sha="a"*64
  self.generation=2
  self.keys={f"verifier-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.pins={n:k.public_key().public_bytes_raw().hex() for n,k in self.keys.items()}
  self.acks=[make_cutover_ack(self.keys[n],n,self.rotation,self.policy_sha,self.generation)
   for n in ("verifier-0","verifier-1","verifier-2")]
  self.cert=build_cutover_certificate(self.rotation,self.policy_sha,self.generation,self.acks)
 def check(self,cert=None,rotation=None,pins=None,threshold=3,faults=1):
  return verify_cutover_certificate(cert or self.cert,rotation or self.rotation,
   self.policy_sha,self.generation,pins or self.pins,threshold,faults)
 def test_three_of_four_activation_certificate_accepts(self):
  self.assertTrue(self.check())
 def test_two_of_four_cannot_activate(self):
  c=copy.deepcopy(self.cert); c["acks"]=c["acks"][:2]
  self.assertFalse(self.check(c))
 def test_duplicate_verifier_cannot_inflate_quorum(self):
  c=copy.deepcopy(self.cert); c["acks"].append(copy.deepcopy(c["acks"][0]))
  self.assertFalse(self.check(c))
 def test_unknown_verifier_rejected(self):
  c=copy.deepcopy(self.cert); c["acks"][0]["payload"]["verifier_id"]="outsider"
  self.assertFalse(self.check(c))
 def test_rotation_substitution_rejected(self):
  self.assertFalse(self.check(rotation={"schema":"rotation","payload":{"generation":3}}))
 def test_target_policy_substitution_rejected(self):
  self.assertFalse(verify_cutover_certificate(self.cert,self.rotation,"b"*64,
   self.generation,self.pins,3,1))
 def test_generation_substitution_rejected(self):
  self.assertFalse(verify_cutover_certificate(self.cert,self.rotation,self.policy_sha,
   3,self.pins,3,1))
 def test_signature_tampering_rejected(self):
  c=copy.deepcopy(self.cert); c["acks"][0]["signature"]="00"*64
  self.assertFalse(self.check(c))
 def test_pinned_verifier_key_substitution_rejected(self):
  pins=dict(self.pins); pins["verifier-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(self.check(pins=pins))
 def test_unsafe_two_of_three_one_fault_configuration_rejected(self):
  pins={k:self.pins[k] for k in ("verifier-0","verifier-1","verifier-2")}
  acks=self.acks[:2]
  cert=build_cutover_certificate(self.rotation,self.policy_sha,self.generation,acks)
  self.assertFalse(verify_cutover_certificate(cert,self.rotation,self.policy_sha,
   self.generation,pins,2,1))
 def test_four_of_four_rejected_for_one_fault_liveness(self):
  acks=[make_cutover_ack(self.keys[n],n,self.rotation,self.policy_sha,self.generation)
   for n in self.keys]
  cert=build_cutover_certificate(self.rotation,self.policy_sha,self.generation,acks)
  self.assertFalse(verify_cutover_certificate(cert,self.rotation,self.policy_sha,
   self.generation,self.pins,4,1))

class IndependentRecoveryCutoverTests(unittest.TestCase):
 def setUp(self):
  import hashlib
  from witness_independence import DIMENSIONS,independence_digest
  self.base=RecoveryCutoverTests("test_three_of_four_activation_certificate_accepts")
  self.base.setUp()
  self.manifest={"witnesses":{name:{
    **{d:name+"-"+d for d in DIMENSIONS},
    "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
    for name,raw in self.base.pins.items()}}
  self.pin=independence_digest(self.manifest)
 def check(self,manifest=None,pin=None):
  from recovery_cutover import verify_independent_cutover_certificate
  return verify_independent_cutover_certificate(self.base.cert,self.base.rotation,
   self.base.policy_sha,self.base.generation,self.base.pins,3,1,
   self.manifest if manifest is None else manifest,self.pin if pin is None else pin)
 def test_independent_verifier_manifest_accepts(self):
  self.assertTrue(self.check())
 def test_shared_verifier_operator_rejected(self):
  import copy
  m=copy.deepcopy(self.manifest)
  m["witnesses"]["verifier-1"]["operator"]=m["witnesses"]["verifier-0"]["operator"]
  self.assertFalse(self.check(m))
 def test_shared_key_custody_rejected(self):
  import copy
  m=copy.deepcopy(self.manifest)
  m["witnesses"]["verifier-1"]["key_custody"]=m["witnesses"]["verifier-0"]["key_custody"]
  self.assertFalse(self.check(m))
 def test_manifest_pin_substitution_rejected(self):
  self.assertFalse(self.check(pin="f"*64))
 def test_verifier_key_substitution_rejected_by_manifest(self):
  pins=dict(self.base.pins)
  pins["verifier-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  from recovery_cutover import verify_independent_cutover_certificate
  self.assertFalse(verify_independent_cutover_certificate(self.base.cert,self.base.rotation,
   self.base.policy_sha,self.base.generation,pins,3,1,self.manifest,self.pin))
