"""Verify old-policy anchor history before installing successor witness state."""
from recovery_anchor_quorum import verify_anchor_certificate
from recovery_anchor_reenrollment import verify_anchor_reenrollment,install_anchor_reenrollment
from recovery_ledger_anchor import checkpoint_pin

def verify_and_install_anchor_reenrollment(witness,current_policy,next_policy,rotation,proof,
        expected_rotation_generation,expected_rotation_previous_pin,
        current_anchor_payload,current_anchor_certificate,current_anchor_previous_pin,
        expected_target_authority_id,expected_authority_key_sha256):
    try:
        if type(current_anchor_payload) is not dict:
            return "INVALID_CURRENT_ANCHOR"
        checkpoint=current_anchor_payload.get("checkpoint")
        if type(checkpoint) is not dict:
            return "INVALID_CURRENT_ANCHOR"
        sequence=current_anchor_payload.get("sequence")
        current_pin=checkpoint_pin(checkpoint)
        if not verify_anchor_certificate(current_anchor_payload,current_anchor_certificate,
            current_policy,sequence,current_anchor_previous_pin,expected_target_authority_id,
            expected_authority_key_sha256):
            return "INVALID_CURRENT_ANCHOR"
        if not verify_anchor_reenrollment(current_policy,next_policy,rotation,proof,
            expected_rotation_generation,expected_rotation_previous_pin,
            expected_target_authority_id,sequence,current_pin):
            return "INVALID_REENROLLMENT"
        return install_anchor_reenrollment(witness,current_policy,next_policy,rotation,proof,
            expected_rotation_generation,expected_rotation_previous_pin,
            expected_target_authority_id,sequence,current_pin)
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return "INVALID_CURRENT_ANCHOR"
