"""Independent verifier for a transparently logged threshold recovery quorum.

Each counted recovery authority must:
* be enrolled in the pinned recovery policy,
* use the exact pinned authority key,
* have an independently verifiable approval ledger anchored to a quorum,
* have its newest anchored event bind the same policy and recovery payload,
* use an anchor key plane disjoint from every other counted authority.

This proves a threshold of independently anchored approval records under the
supplied trust assumptions. It does not prove organizational independence
behind distinct keys or operators.
"""
from threshold_recovery import validate_policy,policy_digest,payload_digest
from recovery_evidence_reference_verifier import verify_recovery_evidence

def _policy_keys(policy):
    try:
        return {bytes.fromhex(value) for value in policy["authorities"].values()}
    except (ValueError,TypeError,KeyError,AttributeError):
        return set()

def verify_transparent_recovery_quorum(payload,recovery_policy,authority_records):
    try:
        if not validate_policy(recovery_policy) or type(authority_records) is not list:
            return False
        pd=policy_digest(recovery_policy); md=payload_digest(payload)
        seen=set(); anchor_planes=[]; valid=0
        for record in authority_records:
            required={"authority_id","authority_public_key_hex","evidence",
                "anchor_policy","anchor_sequence","previous_anchor_pin"}
            if type(record) is not dict or set(record)!=required:
                return False
            aid=record["authority_id"]
            if type(aid) is not str or aid in seen or aid not in recovery_policy["authorities"]:
                return False
            if record["authority_public_key_hex"]!=recovery_policy["authorities"][aid]:
                return False
            anchor_keys=_policy_keys(record["anchor_policy"])
            if not anchor_keys:
                return False
            if any(anchor_keys & prior for prior in anchor_planes):
                return False
            if not verify_recovery_evidence(record["evidence"],record["authority_public_key_hex"],
                record["anchor_policy"],record["anchor_sequence"],record["previous_anchor_pin"]):
                return False
            evidence=record["evidence"]
            if evidence.get("authority_id")!=aid:
                return False
            events=evidence.get("ledger",{}).get("events")
            if type(events) is not list or not events:
                return False
            latest=events[-1]
            if latest.get("policy_sha256")!=pd or latest.get("payload_sha256")!=md:
                return False
            seen.add(aid); anchor_planes.append(anchor_keys); valid+=1
        return valid>=recovery_policy["threshold"]
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
