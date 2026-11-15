import copy,hashlib,pathlib,shutil,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_cutover import build_cutover_certificate,make_cutover_ack
from recovery_activation_registry import RecoveryActivationRegistry
from witness_independence import DIMENSIONS,independence_digest

class RecoveryActivationRegistryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.path=str(pathlib.Path(self.tmp.name)/"activation.sqlite")
  self.old="a"*64; self.new="b"*64; self.generation=2
  self.rotation={"schema":"rotation","payload":{"generation":2,
    "previous_policy_sha256":self.old,"next_policy_sha256":self.new}}
  self.keys={f"verifier-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.pins={n:k.public_key().public_bytes_raw().hex() for n,k in self.keys.items()}
  self.acks=[make_cutover_ack(self.keys[n],n,self.rotation,self.new,2)
    for n in ("verifier-0","verifier-1","verifier-2")]
  self.cert=build_cutover_certificate(self.rotation,self.new,2,self.acks)
  self.manifest={"witnesses":{name:{**{d:name+"-"+d for d in DIMENSIONS},
    "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
    for name,raw in self.pins.items()}}
  self.manifest_pin=independence_digest(self.manifest)
  self.registry=RecoveryActivationRegistry(self.path); self.registry.initialize(self.old,1)
 def activate(self,registry=None,cert=None,rotation=None,generation=2):
  return (registry or self.registry).activate(cert or self.cert,rotation or self.rotation,
    self.new,generation,self.pins,3,1,self.manifest,self.manifest_pin)
 def test_valid_cutover_advances_active_policy(self):
  self.assertEqual(self.activate(),"ACTIVATED")
  self.assertEqual(self.registry.state()["policy_sha256"],self.new)
  self.assertEqual(self.registry.state()["generation"],2)
 def test_replay_rejected_by_generation(self):
  self.assertEqual(self.activate(),"ACTIVATED")
  self.assertEqual(self.activate(),"GENERATION_MISMATCH")
 def test_partial_cutover_never_mutates_state(self):
  cert=copy.deepcopy(self.cert); cert["acks"]=cert["acks"][:2]
  before=self.registry.state()
  self.assertEqual(self.activate(cert=cert),"INVALID_CUTOVER")
  self.assertEqual(self.registry.state(),before)
 def test_rotation_previous_policy_must_match_active_policy(self):
  rotation=copy.deepcopy(self.rotation); rotation["payload"]["previous_policy_sha256"]="f"*64
  acks=[make_cutover_ack(self.keys[n],n,rotation,self.new,2) for n in ("verifier-0","verifier-1","verifier-2")]
  cert=build_cutover_certificate(rotation,self.new,2,acks)
  self.assertEqual(self.activate(cert=cert,rotation=rotation),"ROTATION_STATE_MISMATCH")
 def test_database_rollback_detected_against_independent_anchor(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor
  anchor=MemoryRecoveryHeadAnchor("activation-anchor")
  path=str(pathlib.Path(self.tmp.name)/"anchored.sqlite")
  registry=RecoveryActivationRegistry(path,anchor); registry.initialize(self.old,1)
  snapshot=str(pathlib.Path(self.tmp.name)/"before.sqlite"); shutil.copy2(path,snapshot)
  self.assertEqual(self.activate(registry=registry),"ACTIVATED")
  shutil.copy2(snapshot,path)
  with self.assertRaisesRegex(ValueError,"rolled-back"):
   registry.state()
 def test_anchor_mismatch_blocks_activation_before_mutation(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor
  anchor=MemoryRecoveryHeadAnchor("mismatch")
  path=str(pathlib.Path(self.tmp.name)/"mismatch.sqlite")
  registry=RecoveryActivationRegistry(path,anchor); registry.initialize(self.old,1)
  anchor.compare_and_set("0"*64,"f"*64)
  self.assertEqual(self.activate(registry=registry),"ANCHOR_MISMATCH")
 def test_tampered_local_history_detected(self):
  import sqlite3
  self.assertEqual(self.activate(),"ACTIVATED")
  with sqlite3.connect(self.path) as con:
   con.execute("UPDATE recovery_activation_events SET next_policy_sha256=? WHERE generation=2",("f"*64,))
  with self.assertRaisesRegex(ValueError,"corrupt"):
   self.registry.state()
