"""Fail-closed bridge: active signed enrollment -> externally pinned bundle verification.

Requires an externally pinned enrollment-state digest and approver identity.
A local SQLite database alone is NOT an independent monotonic trust root.
"""
import argparse
import json
import pathlib
import sqlite3
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from verify_trusted import load_unique, sha, verify_trusted

def verify_enrolled(directory, manifest_path, manifest_pin, enrollment_db,
                    active_epoch, enrollment_state_pin):
    try:
        if type(active_epoch) is not int or active_epoch <= 0:
            return False
        if type(enrollment_state_pin) is not str or len(enrollment_state_pin)!=64:
            return False
        if not verify_trusted(directory, manifest_path, manifest_pin):
            return False
        manifest=load_unique(manifest_path)
        with sqlite3.connect("file:"+pathlib.Path(enrollment_db).resolve().as_posix()+"?mode=ro",uri=True) as con:
            row=con.execute("SELECT epoch,payload FROM epochs ORDER BY epoch DESC LIMIT 1").fetchone()
            if row is None or row[0]!=active_epoch:
                return False
            payload=json.loads(row[1])
            if sha(payload)!=enrollment_state_pin:
                return False
            if payload.get("epoch")!=active_epoch or payload.get("version")!=1:
                return False
            revoked={x[0] for x in con.execute("SELECT key_hex FROM revoked")}
        keys=payload["public_keys"]
        if keys!=manifest["public_keys"] or len(set(keys.values()))!=3:
            return False
        if any(key in revoked for key in keys.values()):
            return False
        if not set(payload["revoked_key_hex"]).issubset(revoked):
            return False
        return True
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error,json.JSONDecodeError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--trust-manifest",required=True)
    p.add_argument("--pinned-manifest-sha256",required=True)
    p.add_argument("--enrollment-db",required=True)
    p.add_argument("--active-epoch",type=int,required=True)
    p.add_argument("--pinned-enrollment-sha256",required=True)
    a=p.parse_args()
    ok=verify_enrolled(a.input,a.trust_manifest,a.pinned_manifest_sha256,
        a.enrollment_db,a.active_epoch,a.pinned_enrollment_sha256)
    print("ACTIVE_ENROLLMENT_VERIFIED" if ok else "ACTIVE_ENROLLMENT_REJECTED")
    sys.exit(0 if ok else 2)
