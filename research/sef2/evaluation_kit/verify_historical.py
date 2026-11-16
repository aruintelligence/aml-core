"""Strict enterprise verification bound to full signed history and pinned head.

All pins and the approver public key must be acquired independently.
Never derive a trusted pin from the evidence bundle or history DB.
"""
import argparse
import json
import pathlib
import sqlite3
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_history import SignedHistory, digest
from verify_trusted import load_unique, verify_trusted

def verify_historical(directory, manifest_path, manifest_pin, history_db,
                      approver_public_hex, checkpoint_path, checkpoint_pin,
                      expected_epoch):
    try:
        if type(expected_epoch) is not int or expected_epoch < 1:
            return False
        if type(approver_public_hex) is not str or len(approver_public_hex)!=64:
            return False
        if type(checkpoint_pin) is not str or len(checkpoint_pin)!=64:
            return False
        if not verify_trusted(directory, manifest_path, manifest_pin):
            return False
        approver=Ed25519PublicKey.from_public_bytes(bytes.fromhex(approver_public_hex))
        checkpoint=load_unique(checkpoint_path)
        if type(checkpoint) is not dict or set(checkpoint)!={"schema","epoch","head_hash","count","approver_key_id"}:
            return False
        if checkpoint["epoch"]!=expected_epoch:
            return False
        if digest(checkpoint)!=checkpoint_pin:
            return False
        # Open the existing DB read-only. Never create an empty database as a side effect.
        uri="file:"+pathlib.Path(history_db).resolve().as_posix()+"?mode=ro"
        with sqlite3.connect(uri,uri=True) as con:
            rows=con.execute("SELECT epoch,envelope,prev_hash,entry_hash FROM signed_epochs ORDER BY epoch").fetchall()
        # Verify every signature, transition and hash, not merely the latest row.
        verifier=object.__new__(SignedHistory)
        verifier.approver=approver
        if not rows or not verifier._validate(rows):
            return False
        if rows[-1][0]!=expected_epoch or rows[-1][3]!=checkpoint["head_hash"] or len(rows)!=checkpoint["count"]:
            return False
        if checkpoint["approver_key_id"]!=__import__("hashlib").sha256(approver.public_bytes_raw()).hexdigest():
            return False
        latest=json.loads(rows[-1][1])["payload"]
        manifest=load_unique(manifest_path)
        if latest["public_keys"]!=manifest["public_keys"]:
            return False
        revoked=set()
        for _,raw,_,_ in rows:
            revoked.update(json.loads(raw)["payload"]["revoked_key_hex"])
        if set(latest["public_keys"].values()).intersection(revoked):
            return False
        return True
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error,json.JSONDecodeError,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for flag in ("input","trust-manifest","pinned-manifest-sha256","history-db",
                 "approver-public-hex","checkpoint","pinned-checkpoint-sha256"):
        p.add_argument("--"+flag,required=True)
    p.add_argument("--active-epoch",type=int,required=True)
    a=vars(p.parse_args())
    ok=verify_historical(a["input"],a["trust_manifest"],a["pinned_manifest_sha256"],
        a["history_db"],a["approver_public_hex"],a["checkpoint"],
        a["pinned_checkpoint_sha256"],a["active_epoch"])
    print("SIGNED_HISTORY_BUNDLE_VERIFIED" if ok else "SIGNED_HISTORY_BUNDLE_REJECTED")
    sys.exit(0 if ok else 2)
