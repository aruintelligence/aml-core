"""Independent verifier for recovery activation registry evidence."""
import hashlib
from signed_receipt import canonical
from recovery_activation_registry import GENESIS
from recovery_cutover import verify_independent_cutover_certificate

SCHEMA="AML-SEF2-RECOVERY-ACTIVATION-EVIDENCE-V1"

def _digest(value): return hashlib.sha256(canonical(value)).hexdigest()
def _valid_digest(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def verify_activation_evidence(bundle,initial_policy_sha256,initial_generation,
        verifier_keys,threshold,max_faults,independence_manifest,independence_pin,
        expected_head_sha256=None):
    try:
        if type(bundle) is not dict or set(bundle)!={"schema","state","events"}:
            return False
        if bundle["schema"]!=SCHEMA or not _valid_digest(initial_policy_sha256):
            return False
        if type(initial_generation) is not int or initial_generation<1:
            return False
        state=bundle["state"]; events=bundle["events"]
        if type(state) is not dict or set(state)!={"generation","policy_sha256","head_sha256"}:
            return False
        if type(events) is not list:
            return False
        current_policy=initial_policy_sha256
        generation=initial_generation
        previous=GENESIS
        for event in events:
            required={"generation","previous_policy_sha256","next_policy_sha256",
                "cutover_sha256","previous_event_sha256","event_sha256",
                "certificate","rotation"}
            if type(event) is not dict or set(event)!=required:
                return False
            next_generation=generation+1
            if (event["generation"]!=next_generation
                or event["previous_policy_sha256"]!=current_policy
                or event["previous_event_sha256"]!=previous
                or not all(_valid_digest(event[k]) for k in ("previous_policy_sha256",
                    "next_policy_sha256","cutover_sha256","previous_event_sha256","event_sha256"))
                or _digest(event["certificate"])!=event["cutover_sha256"]):
                return False
            rotation_payload=event["rotation"].get("payload") if type(event["rotation"]) is dict else None
            if (type(rotation_payload) is not dict
                or rotation_payload.get("generation")!=next_generation
                or rotation_payload.get("previous_policy_sha256")!=current_policy
                or rotation_payload.get("next_policy_sha256")!=event["next_policy_sha256"]):
                return False
            if not verify_independent_cutover_certificate(event["certificate"],event["rotation"],
                event["next_policy_sha256"],next_generation,verifier_keys,threshold,max_faults,
                independence_manifest,independence_pin):
                return False
            calculated=_digest({"generation":next_generation,
                "previous_policy_sha256":current_policy,
                "next_policy_sha256":event["next_policy_sha256"],
                "cutover_sha256":event["cutover_sha256"],
                "previous_event_sha256":previous})
            if calculated!=event["event_sha256"]:
                return False
            current_policy=event["next_policy_sha256"]
            generation=next_generation
            previous=calculated
        if (state["generation"]!=generation or state["policy_sha256"]!=current_policy
            or state["head_sha256"]!=previous):
            return False
        if expected_head_sha256 is not None and expected_head_sha256!=previous:
            return False
        return True
    except (ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
