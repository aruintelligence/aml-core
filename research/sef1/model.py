#!/usr/bin/env python3
"""Bounded state exploration of the lab's claim/effect split, not a proof.

One operation, two epochs, a boolean revocation, one provider record and at
most two historical effects. The model deliberately excludes cryptography,
filesystem behavior, time, network delivery and Byzantine provider reports.
"""
import json
from collections import deque
from dataclasses import dataclass
import sys


@dataclass(frozen=True)
class State:
    issued: int = 0
    epoch: int = 1
    revoked: bool = False
    claimed: bool = False
    pending: bool = False
    provider_record: bool = False
    history: int = 0


def steps(s, mode):
    if not s.issued:
        yield "issue", State(s.epoch, s.epoch, s.revoked, s.claimed, s.pending, s.provider_record, s.history)
    if not s.revoked:
        yield "revoke", State(s.issued, s.epoch, True, s.claimed, s.pending, s.provider_record, s.history)
    if s.epoch == 1:
        yield "advance_epoch", State(s.issued, 2, s.revoked, s.claimed, s.pending, s.provider_record, s.history)
    if s.issued == s.epoch and not s.revoked and not s.claimed:
        yield "claim", State(s.issued, s.epoch, s.revoked, True, True, s.provider_record, s.history)
    if s.pending and s.history < 2:
        yield "effect", State(s.issued, s.epoch, s.revoked, s.claimed, False, True, s.history + 1)
        yield "crash_before_effect", State(s.issued, s.epoch, s.revoked, s.claimed, False, s.provider_record, s.history)
    if s.provider_record:
        yield "provider_only_rollback", State(s.issued, s.epoch, s.revoked, s.claimed, s.pending, False, s.history)
    if mode == "joint_rollback" and s.claimed:
        yield "joint_store_rollback", State(s.issued, 1, False, False, False, False, s.history)
    if mode == "direct_bypass" and s.history < 2:
        yield "unsandboxed_provider_write", State(s.issued, s.epoch, s.revoked, s.claimed, s.pending, True, s.history + 1)


def explore(mode, max_depth=10):
    start = State()
    queue = deque([(start, ())])
    visited = {start}
    edges = 0
    counterexample = None
    while queue:
        state, trace = queue.popleft()
        if state.history > 1 and counterexample is None:
            counterexample = list(trace)
        if len(trace) >= max_depth:
            continue
        for label, next_state in steps(state, mode):
            edges += 1
            if next_state not in visited:
                visited.add(next_state)
                queue.append((next_state, trace + (label,)))
    return {"mode": mode, "states": len(visited), "transitions_examined": edges,
            "max_depth": max_depth, "duplicate_effect_trace": counterexample}


def main():
    results = [explore(mode) for mode in ("confined_agent", "joint_rollback", "direct_bypass")]
    assert results[0]["duplicate_effect_trace"] is None
    assert results[1]["duplicate_effect_trace"] is not None
    assert results[2]["duplicate_effect_trace"] is not None
    print(json.dumps({"schema": "aml-sef-bounded-model/1", "bounds":
        "one operation; two epochs; two historical effects; 10 transition steps", "results": results}, indent=2))


if __name__ == "__main__":
    main()
