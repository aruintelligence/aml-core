"""Local microbenchmark for independent recovery cutover verification.

Descriptive for the current runner only; excludes network, HSM and remote
anchor latency.
"""
import argparse,hashlib,json,platform,statistics,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_cutover import (build_cutover_certificate,make_cutover_ack,
    verify_independent_cutover_certificate)
from witness_independence import DIMENSIONS,independence_digest

def summary(values):
 ordered=sorted(values)
 p95=ordered[min(len(ordered)-1,int((len(ordered)-1)*.95+0.999999))]
 return {"median_ms":round(statistics.median(values),3),"p95_ms":round(p95,3),
  "mean_ms":round(statistics.mean(values),3),"min_ms":round(min(values),3),
  "max_ms":round(max(values),3)}

def main():
 p=argparse.ArgumentParser(); p.add_argument("--iterations",type=int,default=25); a=p.parse_args()
 if type(a.iterations) is not int or not 5<=a.iterations<=500: p.error("--iterations must be 5..500")
 rotation={"schema":"benchmark-rotation","payload":{"generation":2,
  "previous_policy_sha256":"a"*64,"next_policy_sha256":"b"*64}}
 target="b"*64; generation=2
 keys={f"verifier-{i}":Ed25519PrivateKey.generate() for i in range(4)}
 pins={n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()}
 acks=[make_cutover_ack(keys[n],n,rotation,target,generation)
  for n in ("verifier-0","verifier-1","verifier-2")]
 cert=build_cutover_certificate(rotation,target,generation,acks)
 manifest={"witnesses":{name:{**{d:name+"-"+d for d in DIMENSIONS},
  "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
  for name,raw in pins.items()}}
 manifest_pin=independence_digest(manifest)
 timings=[]
 for _ in range(a.iterations):
  start=time.perf_counter_ns()
  assert verify_independent_cutover_certificate(cert,rotation,target,generation,
   pins,3,1,manifest,manifest_pin)
  timings.append((time.perf_counter_ns()-start)/1e6)
 encoded=json.dumps({"certificate":cert,"rotation":rotation,"verifier_keys":pins,
  "independence_manifest":manifest},sort_keys=True,separators=(",",":")).encode()
 print(json.dumps({"benchmark":"AML-SEF2-independent-recovery-cutover-verification-v1",
  "environment":{"python":platform.python_version(),"platform":platform.platform(),
   "cryptography":"46.0.3"},"iterations":a.iterations,"evidence_bytes":len(encoded),
  "verification":summary(timings),
  "limitations":["single CI host","no network or HSM latency","synthetic keys and control-domain declarations",
   "microbenchmark, not a production capacity claim"]},indent=2,sort_keys=True))
if __name__=="__main__": main()
