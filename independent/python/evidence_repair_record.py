#!/usr/bin/env python3
"""Independent Python generator and verifier for local repair records."""
import hashlib
import json
import pathlib
import sys

from repair_evidence_share import repair
from verify_evidence_archive import strict_json
from verify_evidence_capsule import canonical

PROTOCOL = "aml-evidence-repair-record/1"
BOUNDARY = "A project-authored local reconstruction record; not an independent witness, custody proof, trusted timestamp, or physical storage guarantee."


def digest(algorithm, data):
    return hashlib.new(algorithm, data).hexdigest()


def create(survivors, replacement, policy):
    rebuilt, repair_report = repair(survivors, policy)
    if canonical(replacement) != canonical(rebuilt):
        raise ValueError("replacement_mismatch")
    ordered = sorted(survivors, key=lambda share: share["index"])
    payload = {"protocol": PROTOCOL, "claim_boundary": BOUNDARY,
               "survivor_indices": [share["index"] for share in ordered],
               "survivor_roots_sha3_512": [share["root_sha3_512"] for share in ordered],
               "replacement_index": repair_report["missing_index"],
               "replacement_root_sha3_512": replacement["root_sha3_512"],
               "payload_sha512": repair_report["payload_sha512"],
               "migration_root_sha3_512": replacement["migration_root_sha3_512"],
               "policy_sha256": digest("sha256", canonical(policy)),
               "accepted_head": {"sequence": policy["accepted_head"]["sequence"],
                                 "root_sha3_512": policy["accepted_head"]["root_sha3_512"]},
               "verified_pairs": 3, "policy_hint_trusted": False}
    return {**payload, "root_sha3_512": digest("sha3_512", canonical(payload))}


def verify(record, survivors, replacement, policy):
    try:
        expected = create(survivors, replacement, policy)
        if canonical(record) != canonical(expected):
            raise ValueError("record_mismatch")
        return {"protocol": "aml-evidence-repair-record-python-report/1", "verified": True,
                "reason": None, "policy_hint_trusted": False,
                "root_sha3_512": expected["root_sha3_512"],
                "replacement_index": expected["replacement_index"],
                "payload_sha512": expected["payload_sha512"]}
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as error:
        return {"protocol": "aml-evidence-repair-record-python-report/1", "verified": False,
                "reason": str(error), "policy_hint_trusted": False}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 7 or sys.argv[1] not in ("create", "verify"):
            raise ValueError("Usage: python3 independent/python/evidence_repair_record.py create <share-a.json> <share-b.json> <replacement.json> <policy.json> <new-record.json>\n       python3 independent/python/evidence_repair_record.py verify <record.json> <share-a.json> <share-b.json> <replacement.json> <policy.json>")
        if sys.argv[1] == "create":
            survivors = [strict_json(pathlib.Path(file).read_text(encoding="utf-8")) for file in sys.argv[2:4]]
            replacement = strict_json(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
            policy = strict_json(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
            record = create(survivors, replacement, policy)
            with open(sys.argv[6], "xb") as output:
                output.write(canonical(record) + b"\n")
            report = {"protocol": "aml-evidence-repair-record-python-report/1", "created": True,
                      "destination": sys.argv[6], "root_sha3_512": record["root_sha3_512"]}
        else:
            record = strict_json(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
            survivors = [strict_json(pathlib.Path(file).read_text(encoding="utf-8")) for file in sys.argv[3:5]]
            replacement = strict_json(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
            policy = strict_json(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
            report = verify(record, survivors, replacement, policy)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-repair-record-python-report/1", "verified": False,
                  "created": False, "policy_hint_trusted": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report.get("created") or report.get("verified") else 1)
