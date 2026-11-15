"""Mandatory pinned key + administrative independence + Byzantine quorum gate."""
import pathlib
import sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT.parent))
from verify_trusted import load_unique
from witness_independence import verify_independence
from verify_quorum import verify_with_quorum

def verify_independent_quorum(directory,manifest_path,manifest_pin,history_db,
                              approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch,
                              witness_keys_path,witness_domains_path,witness_domains_pin,
                              attestations_path,threshold,max_faults):
    try:
        keys=load_unique(witness_keys_path)
        domains=load_unique(witness_domains_path)
        if type(keys) is not dict or not verify_independence(domains,tuple(keys),witness_domains_pin,keys):
            return False
        return verify_with_quorum(directory,manifest_path,manifest_pin,history_db,
            approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch,
            witness_keys_path,attestations_path,threshold,max_faults)
    except (OSError,ValueError,TypeError,KeyError,OverflowError):
        return False
