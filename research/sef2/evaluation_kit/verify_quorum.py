"""Mandatory signed-history and Byzantine-bounded witness quorum gate."""
import argparse
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from checkpoint_council import WitnessCouncil
from quorum_model import validate_bft_quorum
from verify_historical import verify_historical
from verify_trusted import load_unique

def verify_with_quorum(directory,manifest_path,manifest_pin,history_db,
                       approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch,
                       witness_keys_path,attestations_path,threshold,max_faults=0):
    if not verify_historical(directory,manifest_path,manifest_pin,history_db,
                             approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch):
        return False
    try:
        key_hex=load_unique(witness_keys_path)
        if type(key_hex) is not dict or len(key_hex)<2:
            return False
        validate_bft_quorum(len(key_hex),threshold,max_faults)
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
                 "witness-keys","witness-domains","pinned-witness-domains-sha256",
                 "attestations"):
        p.add_argument("--"+flag,required=True)
    p.add_argument("--active-epoch",type=int,required=True)
    p.add_argument("--threshold",type=int,required=True)
    p.add_argument("--max-faults",type=int,default=0)
    a=vars(p.parse_args())
    from verify_independent_quorum import verify_independent_quorum
    ok=verify_independent_quorum(a["input"],a["trust_manifest"],a["pinned_manifest_sha256"],
        a["history_db"],a["approver_public_hex"],a["checkpoint"],
        a["pinned_checkpoint_sha256"],a["active_epoch"],a["witness_keys"],
        a["witness_domains"],a["pinned_witness_domains_sha256"],
        a["attestations"],a["threshold"],a["max_faults"])
    print("HISTORICAL_BFT_WITNESS_QUORUM_VERIFIED" if ok else "HISTORICAL_BFT_WITNESS_QUORUM_REJECTED")
    sys.exit(0 if ok else 2)
