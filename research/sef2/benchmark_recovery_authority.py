"""Reproducible local microbenchmark for threshold recovery and anchor evidence.

Results are descriptive for this runner/filesystem only. They are not a
multi-host or production capacity claim.
"""
import argparse,hashlib,json,platform,statistics,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import (POLICY_SCHEMA,RecoveryAuthoritySigner,
    make_approval_bundle,verify_approval_bundle)
from recovery_anchor_quorum import (POLICY_SCHEMA as ANCHOR_SCHEMA,
    RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate,
    verify_anchor_certificate)
from recovery_anchor_reference_verifier import verify_anchor_certificate as reference_verify
from recovery_ledger_anchor import CHECKPOINT_SCHEMA,checkpoint_pin

def percentile(values,p):
    ordered=sorted(values)
    return ordered[min(len(ordered)-1,max(0,int((len(ordered)-1)*p+0.999999)))]

def summary(values):
    return {"median_ms":round(statistics.median(values),3),
        "p95_ms":round(percentile(values,.95),3),
        "mean_ms":round(statistics.mean(values),3),
        "min_ms":round(min(values),3),"max_ms":round(max(values),3)}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--iterations",type=int,default=25)
    args=parser.parse_args()
    if type(args.iterations) is not int or not 5<=args.iterations<=500:
        parser.error("--iterations must be between 5 and 500")
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
        policy={"schema":POLICY_SCHEMA,"policy_id":"benchmark-council-v1",
            "threshold":3,"max_faults":1,
            "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
        signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".sqlite"))) for k,v in keys.items()}
        anchors={f"anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
        anchor_policy={"schema":ANCHOR_SCHEMA,"policy_id":"benchmark-anchor-v1",
            "threshold":3,"max_faults":1,
            "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in anchors.items()},
            "administrative_domains":{k:"benchmark-domain-"+k for k in anchors}}
        witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".anchor.sqlite"))) for k,v in anchors.items()}
        target_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        target_fingerprint=hashlib.sha256(target_key).hexdigest()
        previous_pin="0"*64
        timings={k:[] for k in ("threshold_sign_3of4","threshold_verify_3of4",
            "anchor_certificate_sign_3of4","anchor_certificate_verify_local",
            "anchor_certificate_verify_reference")}
        for i in range(1,args.iterations+1):
            payload={"witness_id":"benchmark-witness","generation":i,
                "previous_state_sha256":hashlib.sha256(f"state-{i-1}".encode()).hexdigest(),
                "new_key_sha256":hashlib.sha256(f"key-{i}".encode()).hexdigest()}
            start=time.perf_counter_ns()
            bundle=make_approval_bundle(payload,policy,{k:signers[k] for k in ("authority-0","authority-1","authority-2")})
            timings["threshold_sign_3of4"].append((time.perf_counter_ns()-start)/1e6)
            start=time.perf_counter_ns()
            assert verify_approval_bundle(payload,bundle,policy)
            timings["threshold_verify_3of4"].append((time.perf_counter_ns()-start)/1e6)
            checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":"benchmark-recovery-authority",
                "authority_key_sha256":target_fingerprint,"sequence":i,
                "head_hash":hashlib.sha256(f"ledger-head-{i}".encode()).hexdigest()}
            anchor_payload=make_anchor_payload(checkpoint,i,previous_pin,anchor_policy)
            start=time.perf_counter_ns()
            cert=make_anchor_certificate(anchor_payload,anchor_policy,
                {k:witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")})
            timings["anchor_certificate_sign_3of4"].append((time.perf_counter_ns()-start)/1e6)
            start=time.perf_counter_ns()
            assert verify_anchor_certificate(anchor_payload,cert,anchor_policy,i,previous_pin,
                "benchmark-recovery-authority",target_fingerprint)
            timings["anchor_certificate_verify_local"].append((time.perf_counter_ns()-start)/1e6)
            start=time.perf_counter_ns()
            assert reference_verify(anchor_payload,cert,anchor_policy,i,previous_pin,
                "benchmark-recovery-authority",target_fingerprint)
            timings["anchor_certificate_verify_reference"].append((time.perf_counter_ns()-start)/1e6)
            previous_pin=checkpoint_pin(checkpoint)
        print(json.dumps({"benchmark":"AML-SEF2-local-recovery-microbenchmark-v1",
            "environment":{"python":platform.python_version(),"platform":platform.platform(),
                "cryptography":"46.0.3","storage":"local temporary SQLite files, rollback journal, synchronous FULL"},
            "iterations":args.iterations,"measurements":{k:summary(v) for k,v in timings.items()},
            "limitations":["single host and local filesystem","synthetic keys and policies",
                "no network, HSM, TPM, remote witness, contention or power-loss measurement",
                "microbenchmark, not a capacity or production latency claim"]},indent=2,sort_keys=True))

if __name__=="__main__": main()
