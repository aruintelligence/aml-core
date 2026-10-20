#!/usr/bin/env python3
"""Independent Python recomputation and replay of the 375 stress receipts."""
import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pilots" / "action-boundary"))
ADAPTER = ROOT / "pilots/action-boundary/challenge-python-adapter.py"
spec = importlib.util.spec_from_file_location("stress_python_adapter", ADAPTER)
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
    corpus = json.loads((ROOT / "conformance/action-stress-375-cases.json").read_text())
    receipts = [json.loads(line) for line in
                (ROOT / "conformance/action-stress-375-receipts.jsonl").read_text().splitlines()]
    assert corpus["protocol"] == "aml-action-stress-challenge/1"
    assert len(corpus["cases"]) == len(receipts) == 375
    blocked = callbacks = 0
    for row, receipt in zip(corpus["cases"], receipts):
        recorded = receipt.pop("receipt_sha256")
        try:
            assert recorded == digest(receipt), row["id"]
            assert receipt["case_id"] == row["id"]
            assert receipt["proposal"] == row["proposal"]
            assert receipt["host_policy"] == row["policy"]
            assert receipt["host_fixture"] == row["host"]
            assert receipt["proposal_input_sha256"] == digest(row["proposal"])
            assert receipt["initial_policy_sha256"] == digest(row["policy"])
            for key, expected_key in [("expected_plan", "plan"), ("expected_dispatch_receipt", "receipt"),
                                      ("expected_tool_calls", "tool_calls"),
                                      ("expected_executed_proposal", "executed_proposal")]:
                assert receipt[key] == row["expected"][expected_key], row["id"]
            observed = await run_case({"protocol": "aml-action-challenge-case/1", "case_id": row["id"],
                                       "proposal": row["proposal"], "policy": row["policy"], "host": row["host"]})
            for key, value in row["expected"].items():
                assert observed[key] == value, (row["id"], key)
            blocked += observed["receipt"]["execution_status"] == "blocked"
            callbacks += observed["tool_calls"]
        finally:
            receipt["receipt_sha256"] = recorded
    print(json.dumps({"cases": 375, "receipts": len(receipts),
                      "blocked": blocked, "callbacks": callbacks}))


if __name__ == "__main__":
    asyncio.run(main())
