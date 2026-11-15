"""Deterministic producer for independently verifiable recovery evidence bundles.

The producer refuses to package inconsistent artifacts. The resulting JSON is
canonical and accompanied by a SHA-256 digest for transport/inventory. Security
verification remains the job of recovery_evidence_reference_verifier.py.
"""
import hashlib,json
from signed_receipt import canonical
from recovery_evidence_reference_verifier import BUNDLE_SCHEMA,verify_recovery_evidence

def build_recovery_evidence(authority_id,ledger,checkpoint,anchor_payload,
        anchor_certificate,authority_public_key_hex,anchor_policy,
        expected_anchor_sequence,expected_previous_anchor_pin):
    bundle={"schema":BUNDLE_SCHEMA,"authority_id":authority_id,"ledger":ledger,
        "checkpoint":checkpoint,"anchor_payload":anchor_payload,
        "anchor_certificate":anchor_certificate}
    if not verify_recovery_evidence(bundle,authority_public_key_hex,anchor_policy,
        expected_anchor_sequence,expected_previous_anchor_pin):
        raise ValueError("refusing to package inconsistent recovery evidence")
    encoded=canonical(bundle)
    return {"bundle":bundle,"canonical_json":encoded.decode("utf-8"),
        "sha256":hashlib.sha256(encoded).hexdigest()}

def write_recovery_evidence(path,*args,**kwargs):
    package=build_recovery_evidence(*args,**kwargs)
    with open(path,"x",encoding="utf-8") as stream:
        stream.write(package["canonical_json"])
        stream.flush()
    return package["sha256"]
