#!/usr/bin/env python3
"""Independent expectation for the serialized proposal that reaches a local callback."""
import hashlib
import json
import pathlib
import sys

MODES = ("allow", "requires_approval")
BASE = {"protocol": "aml-proposed-action/1", "tool": "send_message", "effect": "send",
        "resource": "team@example.test", "purpose": "Snapshot binding fixture",
        "arguments": {"to": "team@example.test", "body": "First observed body"}}
DIGEST = hashlib.sha256(json.dumps(BASE, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")).hexdigest()
PROVENANCE = "project-authored stateful accessor and local callback fixtures"
LIMITS = ("Two local fixtures with a changing JavaScript getter. No human approval, "
          "provider effect, arbitrary object behavior, or production safety proof.")


def expected(mode):
    approval = mode == "requires_approval"
    return {"mode": mode, "accessor_reads": 1, "approval_requests": int(approval),
            "approval_digest": DIGEST if approval else None, "claim_attempts": int(approval),
            "callback_count": 1, "callback_body": "First observed body",
            "callback_sha256": DIGEST,
            "receipt": {"protocol": "aml-action-dispatch/1", "proposal_sha256": DIGEST,
                        "policy_decision": mode, "execution_status": "dispatched",
                        "reason": "host_dispatch_returned"},
            "receipt_matches_callback": True}


def verify(report, source_bytes):
    if (set(report) != {"protocol", "provenance", "limits", "boundary_source_sha256", "rows"}
            or report.get("protocol") != "aml-action-snapshot-proof/1"
            or report.get("provenance") != PROVENANCE or report.get("limits") != LIMITS
            or report.get("boundary_source_sha256") != hashlib.sha256(source_bytes).hexdigest()):
        raise ValueError("snapshot protocol, source binding, provenance, or limits changed")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != len(MODES):
        raise ValueError("snapshot cases missing or repeated")
    for index, (mode, observed) in enumerate(zip(MODES, rows)):
        if observed != expected(mode):
            raise ValueError(f"snapshot case {index} ({mode}) differs")
    return {"protocol": "aml-action-snapshot-oracle/1", "cases_verified": len(MODES),
            "scope": "Project-authored local getter fixture; not an outside or formal proof"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 verify_snapshot_proof.py <report.json|->")
    path = pathlib.Path(__file__).with_name("boundary.mjs")
    data = json.load(sys.stdin if sys.argv[1] == "-" else pathlib.Path(sys.argv[1]).open(encoding="utf-8"))
    print(json.dumps(verify(data, path.read_bytes()), sort_keys=True))
