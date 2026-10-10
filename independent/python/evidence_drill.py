#!/usr/bin/env python3
"""Independent Python report for the three-pair ĀML recovery rehearsal."""
import hashlib
import json
import pathlib
import sys

from verify_evidence_capsule import canonical
from verify_evidence_archive import strict_json
from verify_evidence_migration import verify as verify_migration
from recover_evidence_shards import recover

PROTOCOL = "aml-evidence-recovery-drill/1"
BOUNDARY = "A project-authored local recovery rehearsal. The external policy and accepted head must be preserved separately; this report is not independent witnessing or a trusted timestamp."
PAIRS = ((0, 1), (0, 2), (1, 2))


def run_drill(shares, policy):
    report = {"protocol": PROTOCOL, "claim_boundary": BOUNDARY, "ready": False,
              "recovery_possible": False, "health": "unrecoverable",
              "policy_hint_trusted": False, "policy_sha256": None, "subject": None,
              "passed_pairs": 0, "required_pairs": 3, "pairs": []}
    if not isinstance(shares, list) or len(shares) != 3:
        return {**report, "reason": "three_share_slots_required"}
    if not isinstance(policy, dict):
        return {**report, "reason": "external_trust_required"}
    try:
        report["policy_sha256"] = hashlib.sha256(canonical(policy)).hexdigest()
    except (TypeError, ValueError, OverflowError):
        return {**report, "reason": "invalid_external_policy"}
    positioned = [share if isinstance(share, dict) and share.get("index") == index else None
                  for index, share in enumerate(shares)]
    recovered = []
    for a, b in PAIRS:
        if positioned[a] is None or positioned[b] is None:
            report["pairs"].append({"shares": [a, b], "recovered": False,
                                    "reason": "missing_or_misidentified_share"})
            continue
        try:
            material, _ = recover([positioned[a], positioned[b]], policy)
            migration = strict_json(material.decode("utf-8", errors="strict"))
            verification = verify_migration(migration, policy)
            digest = hashlib.sha512(material).hexdigest()
            recovered.append((migration, digest, verification))
            report["pairs"].append({"shares": [a, b], "recovered": True,
                                    "payload_sha512": digest,
                                    "migration_root_sha3_512": migration["root_sha3_512"]})
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as error:
            report["pairs"].append({"shares": [a, b], "recovered": False, "reason": str(error)})
    report["passed_pairs"] = len(recovered)
    report["recovery_possible"] = bool(recovered)
    if not recovered:
        return {**report, "reason": "no_trusted_recovery_pair"}
    first, digest, verification = recovered[0]
    if any(other_digest != digest or migration["root_sha3_512"] != first["root_sha3_512"]
           for migration, other_digest, _ in recovered):
        return {**report, "health": "conflict", "reason": "recovery_pairs_disagree"}
    report["subject"] = {"payload_sha512": digest,
                         "migration_root_sha3_512": first["root_sha3_512"],
                         "source_archive_root_sha3_512": verification["source_archive_root_sha3_512"],
                         "accepted_head_bound": verification["freshness_bound"] is True}
    if len(recovered) < 3:
        return {**report, "health": "degraded", "reason": "one_or_more_pairs_failed"}
    if not report["subject"]["accepted_head_bound"]:
        return {**report, "health": "unbounded", "reason": "accepted_head_required_for_drill"}
    return {**report, "ready": True, "health": "ready", "reason": None}


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 independent/python/evidence_drill.py <share-0.json> <share-1.json> <share-2.json> <trusted-policy.json>", file=sys.stderr)
        sys.exit(2)

    def read_share(file, index):
        try:
            return strict_json(pathlib.Path(file).read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeError):
            return {"index": index, "unreadable": True}

    try:
        policy = strict_json(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
        report = run_drill([read_share(file, index) for index, file in enumerate(sys.argv[1:4])], policy)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": PROTOCOL, "ready": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["ready"] else 1)
