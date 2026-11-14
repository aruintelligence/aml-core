"""Mandatory quorum gate on top of strict signed-history bundle verification."""
import argparse
import json
import pathlib
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from checkpoint_council import WitnessCouncil
from verify_historical import verify_historical
from verify_trusted import load_unique

def verify_with_quorum(directory,manifest_path,manifest_pin,history_db,
                       approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch,
                       witness_keys_path,attestations_path,threshold):
    if not verify_historical(directory,manifest_path,manifest_pin,history_db,
                             approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch):
        return False
    try:
        key_hex=load_unique(witness_keys_path)
        if type(key_hex) is not dict or len(key_hex)<2:
            return False
        keys={name:Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))
              for name,raw in key_hex.items()}
        if any(type(name) is not str or not name for name in keys):
            return False
        attestations=load_unique(attestations_path)
        council=WitnessCouncil(keys,threshold)
        return council.adjudicate(attestations,load_unique(checkpoint_path))=="WITNESS_QUORUM_CONSISTENT"
    except (OSError,ValueError,KeyError,TypeError,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for flag in ("input","trust-manifest","pinned-manifest-sha256","history-db",
                 "approver-public-hex","checkpoint","pinned-checkpoint-sha256",
                 "witness-keys","attestations"):
        p.add_argument("--"+flag,required=True)
    p.add_argument("--active-epoch",type=int,required=True)
    p.add_argument("--threshold",type=int,required=True)
    a=vars(p.parse_args())
    ok=verify_with_quorum(a["input"],a["trust_manifest"],a["pinned_manifest_sha256"],
        a["history_db"],a["approver_public_hex"],a["checkpoint"],
        a["pinned_checkpoint_sha256"],a["active_epoch"],a["witness_keys"],a["attestations"],a["threshold"])
    print("HISTORICAL_WITNESS_QUORUM_VERIFIED" if ok else "HISTORICAL_WITNESS_QUORUM_REJECTED")
    sys.exit(0 if ok else 2)
