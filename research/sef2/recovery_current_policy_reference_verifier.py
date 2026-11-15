"""Independent verifier that binds recovery evidence to the current anchored recovery policy."""
import argparse,sys
from pathlib import Path
from threshold_recovery import policy_digest
from recovery_evidence_reference_verifier import verify_recovery_evidence
from recovery_policy_registry_anchor import verify_registry_anchor

SCHEMA="AML-SEF2-CURRENT-RECOVERY-EVIDENCE-V1"

def anchor_planes_independent(first,second):
    try:
        if type(first) is not dict or type(second) is not dict:
            return False
        if first.get("policy_id")==second.get("policy_id"):
            return False
        a=first.get("authorities"); b=second.get("authorities")
        if type(a) is not dict or type(b) is not dict:
            return False
        first_keys={bytes.fromhex(value) for value in a.values()}
        second_keys={bytes.fromhex(value) for value in b.values()}
        return bool(first_keys) and bool(second_keys) and not (first_keys & second_keys)
    except (ValueError,TypeError,AttributeError):
        return False

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
        if not anchor_planes_independent(authority_anchor_policy,registry_anchor_policy):
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

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate JSON key")
        result[key]=value
    return result

def _load(path):
    import json
    return json.loads(Path(path).read_text(encoding="utf-8"),object_pairs_hook=_unique_object)

def main(argv=None):
    p=argparse.ArgumentParser(description="Verify current-policy-bound AML recovery evidence")
    p.add_argument("bundle",type=Path)
    p.add_argument("--authority-public-key",required=True)
    p.add_argument("--authority-anchor-policy",type=Path,required=True)
    p.add_argument("--authority-anchor-sequence",type=int,required=True)
    p.add_argument("--authority-previous-anchor-pin",required=True)
    p.add_argument("--registry-anchor-policy",type=Path,required=True)
    p.add_argument("--registry-anchor-sequence",type=int,required=True)
    p.add_argument("--registry-previous-anchor-pin",required=True)
    p.add_argument("--registry-id",default="aml-sef2-recovery-policy-registry-v1")
    a=p.parse_args(argv)
    try:
        bundle=_load(a.bundle)
        authority_policy=_load(a.authority_anchor_policy)
        registry_policy=_load(a.registry_anchor_policy)
    except (OSError,ValueError,TypeError) as exc:
        print("UNREADABLE:",exc,file=sys.stderr); return 2
    ok=verify_current_recovery_evidence(bundle,a.authority_public_key,
        authority_policy,a.authority_anchor_sequence,a.authority_previous_anchor_pin,
        registry_policy,a.registry_anchor_sequence,a.registry_previous_anchor_pin,a.registry_id)
    if not ok:
        print("INVALID: current recovery policy, authority evidence, anchors, or trust-plane separation failed")
        return 1
    print("VALID: recovery evidence is linked to the independently anchored current policy")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
