"""One-shot independent verifier for a threshold-authorized witness recovery bundle."""
import json
from signed_receipt import canonical
from threshold_recovery import ThresholdRecoveryPublicKey,policy_digest,validate_policy
from recovery_council_evidence import verify_recovery_council_evidence
from evaluation_kit.verify_recovery_transaction import verify_recovery_transaction

BUNDLE_SCHEMA="AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1"

def _strict_hex_json(value):
    if type(value) is not str or len(value)%2:
        raise ValueError("invalid encoded JSON")
    raw=bytes.fromhex(value)
    def hook(pairs):
        out={}
        for key,item in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key]=item
        return out
    parsed=json.loads(raw.decode("utf-8"),object_pairs_hook=hook)
    if canonical(parsed)!=raw:
        raise ValueError("noncanonical encoded JSON")
    return parsed

def verify_recovery_bundle(bundle,expected_policy_registry_head=None):
    try:
        required={"schema","policy_registry_state","policy","before_manifest","after_manifest",
            "current_state","next_state","transition","authority_ledgers","authority_heads"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=BUNDLE_SCHEMA:
            return False
        policy=bundle["policy"]; registry=bundle["policy_registry_state"]
        if not validate_policy(policy):
            return False
        if type(registry) is not dict or set(registry)!={"generation","policy","policy_sha256","head_sha256"}:
            return False
        if (type(registry["generation"]) is not int or registry["generation"]<1
            or registry["policy"]!=policy or registry["policy_sha256"]!=policy_digest(policy)
            or type(registry["head_sha256"]) is not str or len(registry["head_sha256"])!=64
            or any(c not in "0123456789abcdef" for c in registry["head_sha256"])):
            return False
        if expected_policy_registry_head is not None:
            if (type(expected_policy_registry_head) is not str or len(expected_policy_registry_head)!=64
                or registry["head_sha256"]!=expected_policy_registry_head):
                return False
        transition=bundle["transition"]
        if type(transition) is not dict or transition.get("payload",{}).get("recovery_authority_id")!=policy["policy_id"]:
            return False
        approvals=_strict_hex_json(transition["recovery_signature"])
        if not verify_recovery_council_evidence(transition["payload"],approvals,policy,
             bundle["authority_ledgers"],bundle["authority_heads"]):
            return False
        verifier=ThresholdRecoveryPublicKey(policy)
        return verify_recovery_transaction(bundle["before_manifest"],bundle["after_manifest"],
            bundle["current_state"],bundle["next_state"],transition,verifier,policy["policy_id"])
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError,UnicodeDecodeError):
        return False
