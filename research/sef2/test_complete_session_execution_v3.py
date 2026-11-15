import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from authenticated_execution_challenge import make_execution_challenge
from execution_gate_receipt import evaluate_and_issue,DOMAIN as EVAL_DOMAIN
from signed_receipt import canonical
from authorized_execution_consumption import (AuthorizedExecutionConsumptionWitness,
 make_authorized_consumption_receipt)
from evaluation_kit.verify_complete_session_execution_v3 import (SCHEMA,verify_complete_v3)
from evaluation_kit.verify_session_authorization import SCHEMA as AUTH_SCHEMA

class CompleteSessionExecutionV3Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  registry=PinRegistry(root/"registry.sqlite"); registry.enroll("north","a"*64)
  replicas=[PinReplica(root/(f"r{i}.sqlite")) for i in range(3)]
  replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(replica_keys)}
  for r in replicas: r.record("north",0,"a"*64)
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate(); self.evaluator=Ed25519PrivateKey.generate()
  self.receipt_key=Ed25519PrivateKey.generate()
  self.request={"operation_id":"audit-v3-op","action":"payment:simulate",
    "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
    self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-v3","broker-a",
    self.request,self.cap,0,"c"*64)
  self.proof=make_holder_proof(self.holder,self.cap,self.request,"c"*64)
  attestations=[attest(r,f"r{i}","north",replica_keys[i]) for i,r in enumerate(replicas)]
  self.eval=evaluate_and_issue(registry,"north",replicas,2,attestations,enrolled,
    self.evaluator,"evaluator-v3","broker-a",self.request,self.cap,self.challenge,0)
  witness=AuthorizedExecutionConsumptionWitness(root/"consumption.sqlite")
  entry=witness.consume_record(self.request,self.cap,"c"*64,self.proof,self.eval)
  self.receipt=make_authorized_consumption_receipt(self.receipt_key,"consumption-v3",entry)
  auth={"schema":AUTH_SCHEMA,"request":self.request,"capability":self.cap,
    "broker_challenge":self.challenge,"holder_proof":self.proof}
  self.bundle={"schema":SCHEMA,"authorization":auth,
    "evaluator_authorization":self.eval,"consumption_receipt":self.receipt}
 def check(self,bundle=None):
  return verify_complete_v3(self.bundle if bundle is None else bundle,
    self.authority.public_key().public_bytes_raw().hex(),
    self.broker.public_key().public_bytes_raw().hex(),
    self.evaluator.public_key().public_bytes_raw().hex(),
    self.receipt_key.public_key().public_bytes_raw().hex(),
    "authority","broker-a","broker-instance-v3","evaluator-v3","north",
    "consumption-v3",0)
 def test_exact_full_authorization_chain_verifies(self): self.assertTrue(self.check())
 def test_forged_evaluator_authorization_rejected(self):
  b=copy.deepcopy(self.bundle); b["evaluator_authorization"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_validly_signed_alternate_evaluator_evidence_cannot_be_spliced(self):
  b=copy.deepcopy(self.bundle)
  alternate=copy.deepcopy(self.eval)
  alternate["payload"]["registry_state_sha256"]="f"*64
  alternate["signature"]=self.evaluator.sign(EVAL_DOMAIN+canonical(alternate["payload"])).hex()
  b["evaluator_authorization"]=alternate
  self.assertFalse(self.check(b))
 def test_holder_proof_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["authorization"]["holder_proof"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_consumption_receipt_signature_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["consumption_receipt"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_consumption_receipt_evaluator_digest_tampering_rejected(self):
  b=copy.deepcopy(self.bundle)
  b["consumption_receipt"]["payload"]["evaluator_authorization_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_consumption_receipt_holder_digest_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["consumption_receipt"]["payload"]["holder_proof_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_wrong_consumption_witness_key_rejected(self):
  self.assertFalse(verify_complete_v3(self.bundle,
    self.authority.public_key().public_bytes_raw().hex(),
    self.broker.public_key().public_bytes_raw().hex(),
    self.evaluator.public_key().public_bytes_raw().hex(),
    Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
    "authority","broker-a","broker-instance-v3","evaluator-v3","north","consumption-v3",0))
