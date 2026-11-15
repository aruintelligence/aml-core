"""Independent verifier for a completed witness-key recovery transaction."""
from trust_enrollment import valid as valid_manifest
from witness_key_recovery import advance_state,key_fingerprint,verify_transition

def verify_recovery_transaction(before_manifest,after_manifest,current_state,next_state,
                                transition,recovery_public_key,recovery_authority_id):
    try:
        if not valid_manifest(before_manifest) or not valid_manifest(after_manifest):
            return False
        if type(current_state) is not dict or type(next_state) is not dict:
            return False
        if after_manifest["epoch"]!=before_manifest["epoch"]+1:
            return False
        for role in ("authority","provider"):
            if after_manifest["public_keys"][role]!=before_manifest["public_keys"][role]:
                return False
        old_witness=before_manifest["public_keys"]["witness"]
        new_witness=after_manifest["public_keys"]["witness"]
        if old_witness==new_witness:
            return False
        if current_state.get("public_key_sha256")!=key_fingerprint(old_witness):
            return False
        if transition.get("payload",{}).get("new_public_key_hex")!=new_witness:
            return False
        if not verify_transition(transition,current_state,recovery_public_key,recovery_authority_id):
            return False
        expected=advance_state(transition,current_state,recovery_public_key,recovery_authority_id)
        if next_state!=expected:
            return False
        if next_state.get("public_key_sha256")!=key_fingerprint(new_witness):
            return False
        before_revoked=set(before_manifest["revoked_key_hex"])
        after_revoked=set(after_manifest["revoked_key_hex"])
        if not before_revoked.issubset(after_revoked):
            return False
        if old_witness not in after_revoked:
            return False
        if new_witness in after_revoked:
            return False
        added=after_revoked-before_revoked
        if added!={old_witness}:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
