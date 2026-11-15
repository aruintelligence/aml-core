"""Complete independent verifier for current-policy transparent recovery authorization."""
from threshold_recovery import policy_digest
from recovery_quorum_transparency_verifier import verify_transparent_recovery_quorum
from recovery_policy_registry_anchor import verify_registry_anchor

SCHEMA="AML-SEF2-COMPLETE-RECOVERY-AUTHORIZATION-V1"

def _keys(policy):
    try:
        return {bytes.fromhex(v) for v in policy["authorities"].values()}
    except (ValueError,TypeError,KeyError,AttributeError):
        return set()

def verify_complete_recovery_authorization(bundle,registry_anchor_policy,
        registry_anchor_sequence,registry_previous_anchor_pin,
        registry_id="aml-sef2-recovery-policy-registry-v1"):
    try:
        required={"schema","payload","recovery_policy","authority_records",
            "registry_state","registry_anchor_payload","registry_anchor_certificate"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        policy=bundle["recovery_policy"]; state=bundle["registry_state"]
        if state.get("policy_sha256")!=policy_digest(policy) or state.get("policy")!=policy:
            return False
        if not verify_registry_anchor(state,bundle["registry_anchor_payload"],
            bundle["registry_anchor_certificate"],registry_anchor_policy,
            registry_anchor_sequence,registry_previous_anchor_pin,registry_id):
            return False
        if not verify_transparent_recovery_quorum(bundle["payload"],policy,
            bundle["authority_records"]):
            return False
        registry_keys=_keys(registry_anchor_policy)
        if not registry_keys:
            return False
        for record in bundle["authority_records"]:
            if registry_keys & _keys(record["anchor_policy"]):
                return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
