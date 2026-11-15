"""Independent verifier for recovery transparency from complete histories."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from threshold_recovery import validate_policy
from recovery_policy_evidence import verify_policy_registry_history
from recovery_target_evidence import verify_target_registry_history
from threshold_recovery import verify_approval_ledger
from recovery_transparency_checkpoint import (build_transparency_checkpoint_v2,
    verify_transparency_checkpoint_v2)

def verify_recovery_transparency_evidence(policy_history,target_history,
                                         authority_ledgers,checkpoint,
                                         expected_checkpoint_sha256=None):
    try:
        if not verify_policy_registry_history(policy_history,
                policy_history.get("head_sha256")):
            return False
        policy=policy_history["current_policy"]
        if not validate_policy(policy):
            return False
        if not verify_target_registry_history(target_history,policy,
                target_history.get("head_sha256")):
            return False
        if type(authority_ledgers) is not dict or set(authority_ledgers)!=set(policy["authorities"]):
            return False
        heads={}
        for authority_id,key_hex in policy["authorities"].items():
            ledger=authority_ledgers[authority_id]
            raw=bytes.fromhex(key_hex)
            if len(raw)!=32 or ledger.get("authority_id")!=authority_id:
                return False
            head=ledger.get("head_sha256")
            if not verify_approval_ledger(ledger,Ed25519PublicKey.from_public_bytes(raw),head):
                return False
            heads[authority_id]=head
        expected=build_transparency_checkpoint_v2(policy,
            policy_history["generation"],policy_history["head_sha256"],heads,
            target_history["generation"],target_history["head_sha256"],
            tuple(target_history["current_targets"]))
        if checkpoint!=expected:
            return False
        return verify_transparency_checkpoint_v2(checkpoint,policy,
            tuple(target_history["current_targets"]),policy_history["generation"],
            target_history["generation"],expected_checkpoint_sha256)
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
