"""Independent verifier that binds recovery evidence to the current anchored recovery policy."""
from threshold_recovery import policy_digest
from recovery_evidence_reference_verifier import verify_recovery_evidence
from recovery_policy_registry_anchor import verify_registry_anchor

SCHEMA="AML-SEF2-CURRENT-RECOVERY-EVIDENCE-V1"

def verify_current_recovery_evidence(bundle,authority_public_key_hex,
        authority_anchor_policy,authority_anchor_sequence,authority_previous_anchor_pin,
        registry_anchor_policy,registry_anchor_sequence,registry_previous_anchor_pin,
        registry_id="aml-sef2-recovery-policy-registry-v1"):
    try:
        if type(bundle) is not dict or set(bundle)!={"schema","recovery_evidence",
            "registry_state","registry_anchor_payload","registry_anchor_certificate"}:
            return False
        if bundle["schema"]!=SCHEMA:
            return False
        recovery=bundle["recovery_evidence"]
        if not verify_recovery_evidence(recovery,authority_public_key_hex,
            authority_anchor_policy,authority_anchor_sequence,authority_previous_anchor_pin):
            return False
        state=bundle["registry_state"]
        if not verify_registry_anchor(state,bundle["registry_anchor_payload"],
            bundle["registry_anchor_certificate"],registry_anchor_policy,
            registry_anchor_sequence,registry_previous_anchor_pin,registry_id):
            return False
        ledger=recovery["ledger"]
        events=ledger.get("events")
        if type(events) is not list or not events:
            return False
        current_policy_sha256=state.get("policy_sha256")
        if current_policy_sha256!=policy_digest(state.get("policy")):
            return False
        # The newest approval in the authority ledger must have been authorized
        # under the independently anchored current recovery policy.
        if events[-1].get("policy_sha256")!=current_policy_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
