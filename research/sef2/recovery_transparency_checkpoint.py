"""Deterministic recovery transparency checkpoint.

Combines the active recovery policy digest, policy-registry head, and every
recovery-authority approval-ledger head into one hash that can be pinned by an
independent compare-and-set/quorum anchor.
"""
import hashlib
from signed_receipt import canonical
from threshold_recovery import policy_digest,validate_policy

SCHEMA="AML-SEF2-RECOVERY-TRANSPARENCY-CHECKPOINT-V1"

def _hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def build_transparency_checkpoint(policy,policy_generation,policy_registry_head,authority_heads):
    if not validate_policy(policy):
        raise ValueError("invalid recovery policy")
    if type(policy_generation) is not int or policy_generation<1:
        raise ValueError("invalid recovery policy generation")
    if not _hex64(policy_registry_head):
        raise ValueError("invalid recovery policy registry head")
    if type(authority_heads) is not dict or set(authority_heads)!=set(policy["authorities"]):
        raise ValueError("authority heads must cover the complete recovery council")
    if any(type(name) is not str or not name or not _hex64(head)
           for name,head in authority_heads.items()):
        raise ValueError("invalid recovery authority head")
    payload={"schema":SCHEMA,"policy_generation":policy_generation,
        "policy_sha256":policy_digest(policy),
        "policy_registry_head_sha256":policy_registry_head,
        "authority_heads":{name:authority_heads[name] for name in sorted(authority_heads)}}
    root=hashlib.sha256(canonical(payload)).hexdigest()
    return {"payload":payload,"checkpoint_sha256":root}

def verify_transparency_checkpoint(checkpoint,policy,expected_generation=None,
                                   expected_checkpoint_sha256=None):
    try:
        if type(checkpoint) is not dict or set(checkpoint)!={"payload","checkpoint_sha256"}:
            return False
        p=checkpoint["payload"]
        if type(p) is not dict or set(p)!={"schema","policy_generation","policy_sha256",
            "policy_registry_head_sha256","authority_heads"}:
            return False
        if p["schema"]!=SCHEMA or not validate_policy(policy):
            return False
        if type(p["policy_generation"]) is not int or p["policy_generation"]<1:
            return False
        if expected_generation is not None and p["policy_generation"]!=expected_generation:
            return False
        if p["policy_sha256"]!=policy_digest(policy):
            return False
        if not _hex64(p["policy_registry_head_sha256"]):
            return False
        heads=p["authority_heads"]
        if type(heads) is not dict or list(heads)!=sorted(heads) or set(heads)!=set(policy["authorities"]):
            return False
        if any(not _hex64(value) for value in heads.values()):
            return False
        calculated=hashlib.sha256(canonical(p)).hexdigest()
        if checkpoint["checkpoint_sha256"]!=calculated:
            return False
        if expected_checkpoint_sha256 is not None and calculated!=expected_checkpoint_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError):
        return False


SCHEMA_V2="AML-SEF2-RECOVERY-TRANSPARENCY-CHECKPOINT-V2"

def _targets_digest(targets):
    if (type(targets) not in (list,tuple) or not targets
        or list(targets)!=sorted(set(targets))
        or any(type(target) is not str or not target for target in targets)):
        raise ValueError("invalid tracked target set")
    return hashlib.sha256(canonical(list(targets))).hexdigest()

def build_transparency_checkpoint_v2(policy,policy_generation,policy_registry_head,
                                     authority_heads,target_registry_generation,
                                     target_registry_head,tracked_targets):
    base=build_transparency_checkpoint(policy,policy_generation,policy_registry_head,authority_heads)
    if type(target_registry_generation) is not int or target_registry_generation<1:
        raise ValueError("invalid target registry generation")
    if not _hex64(target_registry_head):
        raise ValueError("invalid target registry head")
    payload={"schema":SCHEMA_V2,
        "policy_generation":base["payload"]["policy_generation"],
        "policy_sha256":base["payload"]["policy_sha256"],
        "policy_registry_head_sha256":base["payload"]["policy_registry_head_sha256"],
        "authority_heads":base["payload"]["authority_heads"],
        "target_registry_generation":target_registry_generation,
        "target_registry_head_sha256":target_registry_head,
        "tracked_targets_sha256":_targets_digest(tracked_targets)}
    return {"payload":payload,
        "checkpoint_sha256":hashlib.sha256(canonical(payload)).hexdigest()}

def verify_transparency_checkpoint_v2(checkpoint,policy,tracked_targets,
                                      expected_policy_generation=None,
                                      expected_target_generation=None,
                                      expected_checkpoint_sha256=None):
    try:
        if type(checkpoint) is not dict or set(checkpoint)!={"payload","checkpoint_sha256"}:
            return False
        p=checkpoint["payload"]
        required={"schema","policy_generation","policy_sha256","policy_registry_head_sha256",
            "authority_heads","target_registry_generation","target_registry_head_sha256",
            "tracked_targets_sha256"}
        if type(p) is not dict or set(p)!=required or p["schema"]!=SCHEMA_V2:
            return False
        legacy={"payload":{"schema":SCHEMA,"policy_generation":p["policy_generation"],
            "policy_sha256":p["policy_sha256"],
            "policy_registry_head_sha256":p["policy_registry_head_sha256"],
            "authority_heads":p["authority_heads"]},
            "checkpoint_sha256":"0"*64}
        legacy["checkpoint_sha256"]=hashlib.sha256(canonical(legacy["payload"])).hexdigest()
        if not verify_transparency_checkpoint(legacy,policy,expected_policy_generation):
            return False
        if (type(p["target_registry_generation"]) is not int or p["target_registry_generation"]<1
            or not _hex64(p["target_registry_head_sha256"])
            or p["tracked_targets_sha256"]!=_targets_digest(tracked_targets)):
            return False
        if (expected_target_generation is not None
            and p["target_registry_generation"]!=expected_target_generation):
            return False
        calculated=hashlib.sha256(canonical(p)).hexdigest()
        if checkpoint["checkpoint_sha256"]!=calculated:
            return False
        if expected_checkpoint_sha256 is not None and calculated!=expected_checkpoint_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError):
        return False


SCHEMA_V3="AML-SEF2-RECOVERY-TRANSPARENCY-CHECKPOINT-V3"

def build_transparency_checkpoint_v3(policy,policy_generation,policy_registry_head,
                                     authority_heads,target_registry_generation,
                                     target_registry_head,tracked_targets,
                                     sequence,previous_checkpoint_sha256):
    if type(sequence) is not int or sequence<1:
        raise ValueError("invalid transparency checkpoint sequence")
    if not _hex64(previous_checkpoint_sha256):
        raise ValueError("invalid transparency checkpoint predecessor")
    v2=build_transparency_checkpoint_v2(policy,policy_generation,policy_registry_head,
        authority_heads,target_registry_generation,target_registry_head,tracked_targets)
    p=v2["payload"]
    payload={"schema":SCHEMA_V3,"sequence":sequence,
        "previous_checkpoint_sha256":previous_checkpoint_sha256,
        "policy_generation":p["policy_generation"],"policy_sha256":p["policy_sha256"],
        "policy_registry_head_sha256":p["policy_registry_head_sha256"],
        "authority_heads":p["authority_heads"],
        "target_registry_generation":p["target_registry_generation"],
        "target_registry_head_sha256":p["target_registry_head_sha256"],
        "tracked_targets_sha256":p["tracked_targets_sha256"]}
    return {"payload":payload,
        "checkpoint_sha256":hashlib.sha256(canonical(payload)).hexdigest()}

def verify_transparency_checkpoint_v3(checkpoint,policy,tracked_targets,
                                      expected_sequence,expected_previous_checkpoint_sha256,
                                      expected_policy_generation=None,
                                      expected_target_generation=None,
                                      expected_checkpoint_sha256=None):
    try:
        if type(checkpoint) is not dict or set(checkpoint)!={"payload","checkpoint_sha256"}:
            return False
        p=checkpoint["payload"]
        required={"schema","sequence","previous_checkpoint_sha256","policy_generation","policy_sha256",
            "policy_registry_head_sha256","authority_heads","target_registry_generation",
            "target_registry_head_sha256","tracked_targets_sha256"}
        if type(p) is not dict or set(p)!=required or p["schema"]!=SCHEMA_V3:
            return False
        if (type(expected_sequence) is not int or expected_sequence<1
            or p["sequence"]!=expected_sequence
            or not _hex64(expected_previous_checkpoint_sha256)
            or p["previous_checkpoint_sha256"]!=expected_previous_checkpoint_sha256):
            return False
        v2_payload={"schema":SCHEMA_V2,"policy_generation":p["policy_generation"],
            "policy_sha256":p["policy_sha256"],
            "policy_registry_head_sha256":p["policy_registry_head_sha256"],
            "authority_heads":p["authority_heads"],
            "target_registry_generation":p["target_registry_generation"],
            "target_registry_head_sha256":p["target_registry_head_sha256"],
            "tracked_targets_sha256":p["tracked_targets_sha256"]}
        v2={"payload":v2_payload,
            "checkpoint_sha256":hashlib.sha256(canonical(v2_payload)).hexdigest()}
        if not verify_transparency_checkpoint_v2(v2,policy,tracked_targets,
            expected_policy_generation,expected_target_generation):
            return False
        calculated=hashlib.sha256(canonical(p)).hexdigest()
        if checkpoint["checkpoint_sha256"]!=calculated:
            return False
        if expected_checkpoint_sha256 is not None and calculated!=expected_checkpoint_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError):
        return False

def verify_transparency_chain(checkpoints,policies,tracked_target_sets,expected_head_sha256=None):
    try:
        if (type(checkpoints) is not list or not checkpoints
            or type(policies) is not list or type(tracked_target_sets) is not list
            or len(policies)!=len(checkpoints) or len(tracked_target_sets)!=len(checkpoints)):
            return False
        previous="0"*64
        last_policy_generation=0
        last_target_generation=0
        for index,checkpoint in enumerate(checkpoints,1):
            policy=policies[index-1]; targets=tracked_target_sets[index-1]
            p=checkpoint.get("payload",{}) if type(checkpoint) is dict else {}
            if not verify_transparency_checkpoint_v3(checkpoint,policy,targets,index,previous,
                p.get("policy_generation"),p.get("target_registry_generation")):
                return False
            if p["policy_generation"]<last_policy_generation or p["target_registry_generation"]<last_target_generation:
                return False
            last_policy_generation=p["policy_generation"]
            last_target_generation=p["target_registry_generation"]
            previous=checkpoint["checkpoint_sha256"]
        return expected_head_sha256 is None or previous==expected_head_sha256
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
