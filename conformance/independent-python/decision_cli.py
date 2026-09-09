#!/usr/bin/env python3

import json
import math
import sys


def fail(message):
    print(json.dumps({"error": message}))
    return 1


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return fail("invalid JSON input")

    if not isinstance(payload, dict):
        return fail("input must be a JSON object")
    if "attention_cost" not in payload or "restoration_value" not in payload:
        return fail("missing required score")

    attention = payload["attention_cost"]
    restoration = payload["restoration_value"]

    if isinstance(attention, bool) or isinstance(restoration, bool):
        return fail("scores must be JSON numbers")
    if not isinstance(attention, (int, float)) or not isinstance(restoration, (int, float)):
        return fail("scores must be JSON numbers")
    if not math.isfinite(attention) or not math.isfinite(restoration):
        return fail("scores must be finite")

    decision = "ALLOW" if restoration >= attention else "SUPPRESS"
    print(json.dumps({"decision": decision}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
