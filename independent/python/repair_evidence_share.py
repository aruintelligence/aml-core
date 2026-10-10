#!/usr/bin/env python3
"""Rebuild one missing AML carrier using independently verified survivors."""
import base64
import hashlib
import json
import pathlib
import sys

from recover_evidence_shards import (BOUNDARY, ENCODING, PROTOCOL, SCHEME,
                                     read_share, recover, xor)
from verify_evidence_archive import strict_json
from verify_evidence_capsule import canonical


def digest(algorithm, data):
    return hashlib.new(algorithm, data).hexdigest()


def rebuild(material, migration):
    size = (len(material) + 1) // 2
    first = material[:size]
    second = material[size:].ljust(size, b"\x00")
    segments = (first, second, xor(first, second))
    result = []
    for index, segment in enumerate(segments):
        payload = {"protocol": PROTOCOL, "encoding": ENCODING, "scheme": SCHEME,
                   "claim_boundary": BOUNDARY, "index": index,
                   "total_bytes": len(material), "segment_bytes": size,
                   "payload_sha512": digest("sha512", material),
                   "migration_root_sha3_512": migration["root_sha3_512"],
                   "migration_root_sha512": migration["root_sha512"],
                   "segment_base64": base64.b64encode(segment).decode("ascii"),
                   "segment_sha512": digest("sha512", segment)}
        result.append({**payload, "root_sha3_512": digest("sha3_512", canonical(payload))})
    return result


def repair(shares, policy):
    if not isinstance(policy, dict) or not policy.get("accepted_head"):
        raise ValueError("external_accepted_head_required")
    if not isinstance(shares, list) or len(shares) != 2:
        raise ValueError("exactly_two_shares_required")
    parsed = [read_share(share) for share in shares]
    if any(item is None for item in parsed):
        raise ValueError("invalid_surviving_share")
    indices = [share["index"] for share in shares]
    if indices[0] == indices[1]:
        raise ValueError("distinct_share_indices_required")
    material, _ = recover(shares, policy)
    migration = strict_json(material.decode("utf-8"))
    canonical_set = rebuild(material, migration)
    if any(canonical(share) != canonical(canonical_set[share["index"]]) for share in shares):
        raise ValueError("survivors_do_not_match_canonical_set")
    missing = next(index for index in range(3) if index not in indices)
    for a, b in ((0, 1), (0, 2), (1, 2)):
        candidate, _ = recover([canonical_set[a], canonical_set[b]], policy)
        if candidate != material:
            raise ValueError("repaired_set_failed_drill")
    return canonical_set[missing], {"protocol": "aml-evidence-share-repair-python-report/1",
                                    "repaired": True, "reason": None, "policy_hint_trusted": False,
                                    "missing_index": missing, "payload_sha512": digest("sha512", material),
                                    "verified_pairs": 3}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 5:
            raise ValueError("Usage: python3 independent/python/repair_evidence_share.py <share-a.json> <share-b.json> <trusted-policy.json> <new-share.json>")
        shares = [strict_json(pathlib.Path(file).read_text(encoding="utf-8")) for file in sys.argv[1:3]]
        policy = strict_json(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
        share, report = repair(shares, policy)
        with open(sys.argv[4], "xb") as output:
            output.write(canonical(share) + b"\n")
        report["destination"] = sys.argv[4]
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-share-repair-python-report/1", "repaired": False,
                  "policy_hint_trusted": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["repaired"] else 1)
