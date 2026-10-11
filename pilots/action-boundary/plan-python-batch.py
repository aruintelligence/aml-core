#!/usr/bin/env python3
"""Independent-process plan bytes for a deterministic differential regression.

legacy_wire replays the project Python key-order algorithm before the fix;
it is baseline evidence, not a suggested alternative encoder.
"""
import hashlib
import json
from pathlib import Path
import sys

from python_boundary import _snapshot, plan_action


def old_lexicographic(value):
    if isinstance(value, dict):
        return {key: old_lexicographic(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [old_lexicographic(item) for item in value]
    return value


def run(data):
    rows = []
    for case in data["cases"]:
        proposal = case["proposal"]
        wire, _, _ = _snapshot(proposal)
        legacy = json.dumps(old_lexicographic(proposal), ensure_ascii=False,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
        rows.append({"id": case["id"], "python_plan": plan_action(proposal, case["policy"]),
                     "python_wire": wire.decode("utf-8"),
                     "legacy_wire": legacy.decode("utf-8"),
                     "legacy_digest": hashlib.sha256(legacy).hexdigest()})
    return {"protocol": "aml-action-key-order-batch/1", "cases": rows}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 plan-python-batch.py <cases.json>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(run(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),
                     ensure_ascii=False, separators=(",", ":")))
