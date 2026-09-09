#!/usr/bin/env python3
"""Independent verifier for ĀML Decision Core 1.

This intentionally does not import aml-core. It implements the published
Decision Core 1 rule directly so the vectors can test cross-implementation
agreement rather than a wrapper around the reference runtime.
"""

import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "decision-core-1.json"
INVALID_VECTORS = ROOT / "decision-core-1-invalid.json"
PROTOCOL = "aml-conformance/decision-core-1"


def decision(attention_cost, restoration_value):
    if isinstance(attention_cost, bool) or isinstance(restoration_value, bool):
        raise TypeError("scores must be JSON numbers, not booleans")
    if not isinstance(attention_cost, (int, float)) or not isinstance(restoration_value, (int, float)):
        raise TypeError("scores must be JSON numbers")
    if not math.isfinite(attention_cost) or not math.isfinite(restoration_value):
        raise ValueError("scores must be finite")
    return "ALLOW" if restoration_value >= attention_cost else "SUPPRESS"


def load(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("protocol") != PROTOCOL:
        raise ValueError(f"unexpected conformance protocol in {path}")
    return payload


def main():
    try:
        payload = load(VECTORS)
        invalid_payload = load(INVALID_VECTORS)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    failures = []

    for vector in payload["vectors"]:
        try:
            actual = decision(vector["attention_cost"], vector["restoration_value"])
        except Exception as exc:
            failures.append((vector["id"], vector["expected_decision"], f"ERROR:{type(exc).__name__}"))
            continue
        expected = vector["expected_decision"]
        if actual != expected:
            failures.append((vector["id"], expected, actual))

    rejected = 0
    for vector in invalid_payload["vectors"]:
        try:
            decision(vector["attention_cost"], vector["restoration_value"])
        except (KeyError, TypeError, ValueError):
            rejected += 1
        else:
            failures.append((vector["id"], "REJECT", "ACCEPT"))

    if failures:
        for vector_id, expected, actual in failures:
            print(f"FAIL {vector_id}: expected {expected}, got {actual}", file=sys.stderr)
        return 1

    valid_count = len(payload["vectors"])
    invalid_count = len(invalid_payload["vectors"])
    print(f"PASS {PROTOCOL} ({valid_count}/{valid_count} decisions; {rejected}/{invalid_count} invalid rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
