"""Strict externally pinned trust manifest verification for SEF/2 research.

The expected manifest SHA-256 MUST be supplied out of band by evaluator.
"""
import argparse
import hashlib
import json
import pathlib
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from signed_receipt import canonical, key_id
from origin_event import DOMAIN, valid_event
from evidence_gate import adjudicate
from cryptography.exceptions import InvalidSignature

ROLES = ("authority", "provider", "witness")
def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def load_unique(path):
    def unique(pairs):
        d = {}
        for k,v in pairs:
            if k in d:
                raise ValueError("duplicate JSON key")
            d[k]=v
        return d
    return json.loads(pathlib.Path(path).read_bytes(), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))

def verify_trusted(directory, manifest_path, pinned_manifest_sha256):
    try:
        if type(pinned_manifest_sha256) is not str or len(pinned_manifest_sha256)!=64:
            return False
        if any(c not in "0123456789abcdef" for c in pinned_manifest_sha256):
            return False
        manifest=load_unique(manifest_path)
        if sha(manifest)!=pinned_manifest_sha256:
            return False
        if type(manifest) is not dict or set(manifest)!={"schema","public_keys","bundle_sha256","report_sha256"}:
            return False
        if manifest["schema"]!="AML-SEF2-TRUST-MANIFEST-V1" or set(manifest["public_keys"])!=set(ROLES):
            return False
        root=pathlib.Path(directory)
        bundle=load_unique(root/"bundle.json")
        report=load_unique(root/"report.json")
        if sha(bundle)!=manifest["bundle_sha256"] or sha(report)!=manifest["report_sha256"]:
            return False
        if bundle.get("schema")!="AML-SEF2-EVALUATION-BUNDLE-V1" or bundle.get("synthetic_only") is not True:
            return False
        if report.get("schema")!="AML-SEF2-EVALUATION-REPORT-V1" or report.get("bundle_sha256")!=sha(bundle):
            return False
        if set(bundle["public_keys"])!=set(ROLES) or bundle["public_keys"]!=manifest["public_keys"]:
            return False
        keys={}
        for role in ROLES:
            raw=bytes.fromhex(manifest["public_keys"][role])
            if len(raw)!=32:
                return False
            pub=Ed25519PublicKey.from_public_bytes(raw)
            keys[role]={key_id(pub):pub}
        if len(set(manifest["public_keys"].values()))!=3:
            return False
        origin=bundle["origin_event"]
        if type(origin) is not dict or set(origin)!={"event","signature"} or not valid_event(origin["event"]):
            return False
        next(iter(keys["provider"].values())).verify(bytes.fromhex(origin["signature"]),
            DOMAIN+canonical(origin["event"]))
        event=origin["event"]
        effect_hash=sha(event["synthetic_effect"])
        for role in ("provider","witness"):
            payload=bundle[role+"_receipt"]["payload"]
            if payload["evidence_sha256"]!=effect_hash or payload["operation_id"]!=event["operation_id"] or payload["request_sha256"]!=event["request_sha256"]:
                return False
        if bundle["authority_receipt"]["payload"]["operation_id"]!=event["operation_id"] or bundle["authority_receipt"]["payload"]["request_sha256"]!=event["request_sha256"]:
            return False
        verdict=adjudicate(bundle["authority_receipt"],bundle["provider_receipt"],
            bundle["witness_receipt"],keys)
        return (verdict==report.get("three_party_verdict")=="THREE_SIGNED_CONSISTENT_CLAIMS"
            and report.get("external_execution_proven") is False
            and report.get("independent_source_proven") is False
            and report.get("replay_db_rollback_resistant") is False
            and report.get("persistent_pinned_witness") is True
            and type(report.get("negative_controls")) is dict
            and len(report["negative_controls"])>=4
            and all(v is True for v in report["negative_controls"].values()))
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,InvalidSignature,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--trust-manifest",required=True)
    p.add_argument("--pinned-manifest-sha256",required=True,
        help="Expected digest received via separate trusted channel, NOT copied from bundle")
    a=p.parse_args()
    ok=verify_trusted(a.input,a.trust_manifest,a.pinned_manifest_sha256)
    print("PINNED_TRUST_VERIFIED" if ok else "PINNED_TRUST_REJECTED")
    sys.exit(0 if ok else 2)
