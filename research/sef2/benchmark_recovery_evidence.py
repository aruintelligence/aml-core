"""Local microbenchmark for complete current-policy-bound recovery verification.

This is descriptive for the CI runner only. It includes local Ed25519
verification and JSON/Python object processing, not network/HSM latency.
"""
import argparse,hashlib,json,platform,statistics,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_policy_registry_anchor import make_registry_anchor_payload
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_current_policy_reference_verifier import verify_current_recovery_evidence

def summary(values):
 ordered=sorted(values)
 return {"median_ms":round(statistics.median(values),3),
  "p95_ms":round(ordered[min(len(ordered)-1,int((len(ordered)-1)*.95+0.999999))],3),
  "mean_ms":round(statistics.mean(values),3),"min_ms":round(min(values),3),"max_ms":round(max(values),3)}
def policy(keys,name,schema=POLICY_SCHEMA):
 return {"schema":schema,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:"benchmark-domain-"+k for k in keys}}
def main():
 p=argparse.ArgumentParser(); p.add_argument("--iterations",type=int,default=25); a=p.parse_args()
 if type(a.iterations) is not int or not 5<=a.iterations<=500: p.error("--iterations must be 5..500")
 with tempfile.TemporaryDirectory() as tmp:
  root=Path(tmp)
  recovery_keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  recovery_policy=policy(recovery_keys,"benchmark-recovery")
  registry=RecoveryPolicyRegistry(str(root/"registry.sqlite")); registry.initialize(recovery_policy); state=registry.state()
  authority_id="r0"; authority=recovery_keys[authority_id]
  signer=RecoveryAuthoritySigner(authority_id,authority,str(root/"authority.sqlite"))
  signer.approve({"witness_id":"north","generation":1,"previous_state_sha256":"a"*64},recovery_policy)
  ledger=signer.export_approval_ledger(); public=authority.public_key().public_bytes_raw().hex()
  checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":authority_id,
   "authority_key_sha256":hashlib.sha256(bytes.fromhex(public)).hexdigest(),
   "sequence":1,"head_hash":ledger["head_sha256"]}
  authority_anchor_keys={f"aa{i}":Ed25519PrivateKey.generate() for i in range(4)}
  authority_anchor_policy=policy(authority_anchor_keys,"authority-anchor",ANCHOR_SCHEMA)
  authority_anchors={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in authority_anchor_keys.items()}
  ap=make_anchor_payload(checkpoint,1,"0"*64,authority_anchor_policy)
  ac=make_anchor_certificate(ap,authority_anchor_policy,{k:authority_anchors[k] for k in ("aa0","aa1","aa2")})
  recovery_evidence={"schema":"AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1","authority_id":authority_id,
   "ledger":ledger,"checkpoint":checkpoint,"anchor_payload":ap,"anchor_certificate":ac}
  registry_anchor_keys={f"ra{i}":Ed25519PrivateKey.generate() for i in range(4)}
  registry_anchor_policy=policy(registry_anchor_keys,"registry-anchor",ANCHOR_SCHEMA)
  registry_anchors={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in registry_anchor_keys.items()}
  rp=make_registry_anchor_payload(state,1,"0"*64,registry_anchor_policy)
  rc=make_anchor_certificate(rp,registry_anchor_policy,{k:registry_anchors[k] for k in ("ra0","ra1","ra2")})
  bundle={"schema":"AML-SEF2-CURRENT-RECOVERY-EVIDENCE-V1","recovery_evidence":recovery_evidence,
   "registry_state":state,"registry_anchor_payload":rp,"registry_anchor_certificate":rc}
  timings=[]
  for _ in range(a.iterations):
   start=time.perf_counter_ns()
   assert verify_current_recovery_evidence(bundle,public,authority_anchor_policy,1,"0"*64,
     registry_anchor_policy,1,"0"*64)
   timings.append((time.perf_counter_ns()-start)/1e6)
  encoded=json.dumps(bundle,sort_keys=True,separators=(",",":")).encode()
  print(json.dumps({"benchmark":"AML-SEF2-current-policy-recovery-verification-v1",
   "environment":{"python":platform.python_version(),"platform":platform.platform(),"cryptography":"46.0.3"},
   "iterations":a.iterations,"bundle_bytes":len(encoded),"verification":summary(timings),
   "limitations":["single CI host","in-memory evidence objects during timed section","no network or HSM latency",
    "synthetic Ed25519 keys and SQLite-generated evidence","not a production capacity claim"]},indent=2,sort_keys=True))
if __name__=="__main__": main()
