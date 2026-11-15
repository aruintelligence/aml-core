"""Minimal independent verifier for exported SEF/2 recovery approval ledgers.

This module deliberately does not import threshold_recovery or the signer
implementation. It uses only the Python standard library and Ed25519 verify
support. A head pin supplied through an independent channel is necessary to
detect truncation or whole-ledger rollback.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN=b"AML-SEF2-THRESHOLD-RECOVERY-APPROVAL-V1\x00"
SCHEMA="AML-SEF2-RECOVERY-APPROVAL-LEDGER-V1"
FIELDS={"sequence","previous_event_sha256","policy_id","authority_id","witness_id",
    "generation","policy_sha256","previous_state_sha256","payload_sha256","signature","event_sha256"}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("utf-8")

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate JSON object key")
        result[key]=value
    return result

def parse_bundle(raw):
    if type(raw) is bytes:
        raw=raw.decode("utf-8")
    if type(raw) is str:
        bundle=json.loads(raw,object_pairs_hook=_unique_object)
    elif type(raw) is dict:
        bundle=raw
    else:
        raise ValueError("bundle must be JSON text, bytes, or object")
    return bundle

def verify_ledger(bundle,public_key_hex,expected_head_sha256=None):
    try:
        bundle=parse_bundle(bundle)
        if type(public_key_hex) is not str or len(public_key_hex)!=64:
            return False
        if any(c not in "0123456789abcdef" for c in public_key_hex): return False
        raw=bytes.fromhex(public_key_hex)
        if len(raw)!=32: return False
        key=Ed25519PublicKey.from_public_bytes(raw)
        if type(bundle) is not dict or set(bundle)!={"schema","authority_id","events","head_sha256"}:
            return False
        if (bundle["schema"]!=SCHEMA or type(bundle["authority_id"]) is not str
            or not bundle["authority_id"] or type(bundle["events"]) is not list
            or type(bundle["head_sha256"]) is not str or len(bundle["head_sha256"])!=64
            or any(c not in "0123456789abcdef" for c in bundle["head_sha256"])):
            return False
        if expected_head_sha256 is not None:
            if (type(expected_head_sha256) is not str or len(expected_head_sha256)!=64
                or any(c not in "0123456789abcdef" for c in expected_head_sha256)):
                return False
        previous="0"*64
        seen=set()
        for sequence,event in enumerate(bundle["events"],1):
            if type(event) is not dict or set(event)!=FIELDS: return False
            if (type(event["sequence"]) is not int or event["sequence"]!=sequence
                or type(event["authority_id"]) is not str or event["authority_id"]!=bundle["authority_id"]
                or type(event["policy_id"]) is not str or not event["policy_id"]
                or type(event["witness_id"]) is not str or not event["witness_id"]
                or type(event["generation"]) is not int or event["generation"]<1
                or type(event["previous_event_sha256"]) is not str
                or event["previous_event_sha256"]!=previous
                or type(event["signature"]) is not str or len(event["signature"])!=128
                or type(event["event_sha256"]) is not str or len(event["event_sha256"])!=64):
                return False
            for name in ("policy_sha256","previous_state_sha256","payload_sha256","event_sha256"):
                value=event[name]
                if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                    return False
            scope=(event["policy_id"],event["witness_id"],event["generation"])
            if scope in seen: return False
            seen.add(scope)
            statement=DOMAIN+canonical({"policy_sha256":event["policy_sha256"],
                "payload_sha256":event["payload_sha256"]})
            signature=bytes.fromhex(event["signature"])
            if len(signature)!=64: return False
            key.verify(signature,statement)
            unsigned={name:event[name] for name in FIELDS if name!="event_sha256"}
            calculated=hashlib.sha256(canonical(unsigned)).hexdigest()
            if calculated!=event["event_sha256"]: return False
            previous=calculated
        if bundle["head_sha256"]!=previous: return False
        return expected_head_sha256 is None or previous==expected_head_sha256
    except (InvalidSignature,ValueError,TypeError,KeyError,UnicodeDecodeError,
            json.JSONDecodeError,OverflowError,AttributeError):
        return False

def main(argv=None):
    parser=argparse.ArgumentParser(description="Independently verify an ĀML recovery approval ledger export")
    parser.add_argument("bundle",type=Path)
    parser.add_argument("--public-key",required=True,help="trusted Ed25519 public key, 32-byte lowercase hex")
    parser.add_argument("--expected-head",help="independently retained 32-byte ledger head hash")
    args=parser.parse_args(argv)
    try:
        raw=args.bundle.read_bytes()
    except OSError as exc:
        print("UNREADABLE:",exc,file=sys.stderr); return 2
    if not verify_ledger(raw,args.public_key,args.expected_head):
        print("INVALID: ledger signature, chain, schema, or external pin verification failed")
        return 1
    print("VALID: signatures and hash chain verified")
    if args.expected_head:
        print("VALID: externally pinned ledger head matches")
    else:
        print("WARNING: no external head pin supplied; truncation/rollback is not excluded")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
