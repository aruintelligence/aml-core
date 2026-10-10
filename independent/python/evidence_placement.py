#!/usr/bin/env python3
"""Independent failure-domain simulation for declared cold storage placement."""
import hashlib
import json
import pathlib
import sys

from evidence_drill import run_drill
from recover_evidence_shards import recover
from verify_evidence_archive import strict_json
from verify_evidence_capsule import canonical

PROTOCOL = "aml-evidence-placement-assessment/1"
BOUNDARY = "A local simulation over operator-declared failure domains and supplied share files. It does not verify physical placement, custody, independence, or future availability."
DIMENSIONS = ("site", "infrastructure", "custodian")


def valid_label(value):
    return isinstance(value, str) and 0 < len(value) <= 128 and value.strip() == value and all(
        ord(character) >= 32 and ord(character) != 127 for character in value)


def assess(shares, policy, placement):
    base = {"protocol": PROTOCOL, "claim_boundary": BOUNDARY, "ready": False,
            "health": "invalid", "policy_hint_trusted": False,
            "placement_sha256": None, "drill_health": None, "scenarios": [], "failed_scenarios": 0}
    if (not isinstance(placement, dict) or set(placement) != {"protocol", "shares"} or
        placement["protocol"] != "aml-evidence-placement/1" or
        not isinstance(placement["shares"], list) or len(placement["shares"]) != 3 or
        any(not isinstance(item, dict) or set(item) != {"index", *DIMENSIONS} or
            type(item["index"]) is not int or item["index"] != index or
            any(not valid_label(item[dimension]) for dimension in DIMENSIONS)
            for index, item in enumerate(placement["shares"]))):
        return {**base, "reason": "invalid_placement_manifest"}
    drill = run_drill(shares, policy)
    report = {**base, "placement_sha256": hashlib.sha256(canonical(placement)).hexdigest(),
              "drill_health": drill["health"], "policy_sha256": drill["policy_sha256"],
              "payload_sha512": drill["subject"]["payload_sha512"] if drill["subject"] else None}
    if not drill["recovery_possible"]:
        return {**report, "health": "unrecoverable", "reason": "baseline_recovery_failed"}
    for dimension in DIMENSIONS:
        for value in sorted({item[dimension] for item in placement["shares"]}):
            survivors = [item["index"] for item in placement["shares"] if item[dimension] != value]
            lost = [item["index"] for item in placement["shares"] if item[dimension] == value]
            recovered, reason = False, "fewer_than_two_survivors"
            if len(survivors) >= 2:
                try:
                    material, _ = recover([shares[index] for index in survivors], policy)
                    recovered = hashlib.sha512(material).hexdigest() == report["payload_sha512"]
                    reason = None if recovered else "subject_mismatch"
                except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as error:
                    reason = str(error)
            report["scenarios"].append({"dimension": dimension, "value": value,
                                        "lost_indices": lost, "surviving_indices": survivors,
                                        "recovered": recovered, "reason": reason})
    report["failed_scenarios"] = sum(not scenario["recovered"] for scenario in report["scenarios"])
    if report["failed_scenarios"]:
        return {**report, "health": "correlated", "reason": "single_domain_loss_breaks_recovery"}
    if not drill["ready"]:
        return {**report, "health": "unverified", "reason": "baseline_drill_not_ready"}
    return {**report, "ready": True, "health": "declared_resilient", "reason": None}


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 independent/python/evidence_placement.py <share-0.json> <share-1.json> <share-2.json> <trusted-policy.json> <placement.json>", file=sys.stderr)
        sys.exit(2)

    def read_share(file, index):
        try:
            return strict_json(pathlib.Path(file).read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeError):
            return {"index": index, "unreadable": True}

    try:
        shares = [read_share(file, index) for index, file in enumerate(sys.argv[1:4])]
        policy = strict_json(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
        placement = strict_json(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
        report = assess(shares, policy, placement)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": PROTOCOL, "ready": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["ready"] else 1)
