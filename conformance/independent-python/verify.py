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

VECTORS = Path(__file__).resolve().parents[1] / "decision-core-1.json"


def decision(attention_cost, restoration_value):
    if isinstance(attention_cost, bool) or isinstance(restoration_value, bool):
        raise TypeError("scores must be JSON numbers, not booleans")
    if not isinstance(attention_cost, (int, float)) or not isinstance(restoration_value, (int, float)):
        raise TypeError("scores must be JSON numbers")
    if not math.isfinite(attention_cost) or not math.isfinite(restoration_value):
        raise ValueError("scores must be finite")
    return "ALLOW" if restoration_value >= attention_cost else "SUPPRESS"


def main():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    if payload.get("protocol") != "aml-conformance/decision-core-1":
        print("FAIL: unexpected conformance protocol", file=sys.stderr)
        return 2

    failures = []
    for vector in payload["vectors"]:
        actual = decision(vector["attention_cost"], vector["restoration_value"])
        expected = vector["expected_decision"]
        if actual != expected:
            failures.append((vector["id"], expected, actual))

    if failures:
        for vector_id, expected, actual in failures:
            print(f"FAIL {vector_id}: expected {expected}, got {actual}", file=sys.stderr)
        return 1

    print(f"PASS aml-conformance/decision-core-1 ({len(payload['vectors'])}/{len(payload['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
