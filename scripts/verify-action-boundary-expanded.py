#!/usr/bin/env python3
"""Recompute every receipt hash from published evidence, then replay in Python.

Project-maintained cross-language checker; this is not an independent witness.
"""
import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pilots" / "action-boundary"))
ADAPTER_PATH = ROOT / "pilots" / "action-boundary" / "challenge-python-adapter.py"
spec = importlib.util.spec_from_file_location("challenge_python_adapter", ADAPTER_PATH)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
run_case = adapter.run_case


def canonical(value):
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int and -(2**53 - 1) <= value <= 2**53 - 1:
        return value
    if type(value) is list:
        return [canonical(item) for item in value]
    if type(value) is dict and all(type(k) is str and all(ord(c) <= 0xFFFF for c in k) for k in value):
        def key(item):
            if re.fullmatch(r"(0|[1-9][0-9]*)", item) and int(item) < 2**32 - 1:
                return (0, int(item))
            return (1, item)
        return {k: canonical(value[k]) for k in sorted(value, key=key)}
    raise ValueError("unsupported_json_subset")


def digest(value):
    wire = json.dumps(canonical(value), ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(wire).hexdigest()


async def main():
    cases = json.loads((ROOT / "conformance/action-boundary-expanded-cases.json").read_text())
    receipts = [json.loads(line) for line in
                (ROOT / "conformance/action-boundary-expanded-receipts.jsonl").read_text().splitlines()]
    assert len(cases["cases"]) == len(receipts) >= 50
    blocked = callbacks = 0
    for row, receipt in zip(cases["cases"], receipts):
        recorded_hash = receipt.pop("receipt_sha256")
        try:
            assert recorded_hash == digest(receipt), row["id"]
            assert receipt["case_id"] == row["id"]
            assert receipt["proposal"] == row["proposal"]
            assert receipt["host_policy"] == row["policy"]
            assert receipt["host_fixture"] == row["host"]
            assert receipt["proposal_input_sha256"] == digest(row["proposal"])
            assert receipt["initial_policy_sha256"] == digest(row["policy"])
            assert receipt["expected_plan"] == row["expected"]["plan"]
            assert receipt["expected_dispatch_receipt"] == row["expected"]["receipt"]
            assert receipt["expected_tool_calls"] == row["expected"]["tool_calls"]
            assert receipt["expected_executed_proposal"] == row["expected"]["executed_proposal"]
            result = await run_case({"protocol": "aml-action-challenge-case/1", "case_id": row["id"],
                                     "proposal": row["proposal"], "policy": row["policy"], "host": row["host"]})
            assert result["plan"] == row["expected"]["plan"]
            assert result["receipt"] == row["expected"]["receipt"]
            assert result["tool_calls"] == row["expected"]["tool_calls"]
            assert result["executed_proposal"] == row["expected"]["executed_proposal"]
            blocked += result["receipt"]["execution_status"] == "blocked"
            callbacks += result["tool_calls"]
        finally:
            receipt["receipt_sha256"] = recorded_hash
    print(json.dumps({"cases": len(cases["cases"]), "receipts": len(receipts),
                      "blocked": blocked, "callbacks": callbacks}))


if __name__ == "__main__":
    asyncio.run(main())
