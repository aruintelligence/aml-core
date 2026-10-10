#!/usr/bin/env python3
"""Project-authored Python recovery reader for ĀML's 2-of-3 cold storage.

This is physical redundancy, not secrecy. The reconstructed migration must
pass the independent Python verifier under trust supplied outside the shares.
"""
import base64
import binascii
import hashlib
import itertools
import json
import pathlib
import re
import sys

from verify_evidence_capsule import canonical
from verify_evidence_archive import strict_json
from verify_evidence_migration import verify as verify_migration

PROTOCOL = "aml-evidence-shard/1"
ENCODING = "canonical-json-utf8-base64/1"
SCHEME = "xor-2-of-3/1"
BOUNDARY = "Any two distinct shares repair one missing share. This is redundancy, not secrecy, trusted identity, or a future cryptographic guarantee."
FIELDS = {"protocol", "encoding", "scheme", "claim_boundary", "index", "total_bytes",
          "segment_bytes", "payload_sha512", "migration_root_sha3_512",
          "migration_root_sha512", "segment_base64", "segment_sha512", "root_sha3_512"}
META = {"protocol", "encoding", "scheme", "claim_boundary", "total_bytes", "segment_bytes",
        "payload_sha512", "migration_root_sha3_512", "migration_root_sha512"}
HEX128 = re.compile(r"[a-f0-9]{128}\Z")


def digest(algorithm, data):
    return hashlib.new(algorithm, data).hexdigest()


def xor(first, second):
    return bytes(a ^ b for a, b in zip(first, second))


def read_share(share):
    if (not isinstance(share, dict) or set(share) != FIELDS or
        share["protocol"] != PROTOCOL or share["encoding"] != ENCODING or
        share["scheme"] != SCHEME or share["claim_boundary"] != BOUNDARY or
        type(share["index"]) is not int or share["index"] not in (0, 1, 2) or
        type(share["total_bytes"]) is not int or share["total_bytes"] < 1 or
        type(share["segment_bytes"]) is not int or
        share["segment_bytes"] != (share["total_bytes"] + 1) // 2 or
        not all(isinstance(share[name], str) and HEX128.fullmatch(share[name])
                for name in ("payload_sha512", "migration_root_sha3_512",
                             "migration_root_sha512", "segment_sha512", "root_sha3_512")) or
        not isinstance(share["segment_base64"], str)):
        return None
    try:
        data = base64.b64decode(share["segment_base64"], validate=True)
        if (len(data) != share["segment_bytes"] or
            base64.b64encode(data).decode("ascii") != share["segment_base64"] or
            digest("sha512", data) != share["segment_sha512"]):
            return None
        payload = {key: value for key, value in share.items() if key != "root_sha3_512"}
        if digest("sha3_512", canonical(payload)) != share["root_sha3_512"]:
            return None
        return share, data
    except (binascii.Error, ValueError, TypeError, OverflowError):
        return None


def assemble(left, right):
    (a, first), (b, second) = sorted((left, right), key=lambda item: item[0]["index"])
    if {key: a[key] for key in META} != {key: b[key] for key in META}:
        return None
    data0 = first if a["index"] == 0 else xor(first, second)
    data1 = first if a["index"] == 1 else second if b["index"] == 1 else xor(first, second)
    material = (data0 + data1)[:a["total_bytes"]]
    if digest("sha512", material) != a["payload_sha512"]:
        return None
    try:
        migration = strict_json(material.decode("utf-8", errors="strict"))
        if (canonical(migration) != material or
            migration["root_sha3_512"] != a["migration_root_sha3_512"] or
            migration["root_sha512"] != a["migration_root_sha512"]):
            return None
        return material, migration
    except (ValueError, UnicodeError, KeyError, TypeError, OverflowError):
        return None


def recover(shares, policy):
    if policy is None:
        raise ValueError("external_trust_required")
    if not isinstance(shares, list) or len(shares) not in (2, 3):
        raise ValueError("two_or_three_shares_required")
    valid = [parsed for share in shares if (parsed := read_share(share)) is not None]
    if len(valid) < 2:
        raise ValueError("insufficient_valid_shares")
    candidates = []
    for a, b in itertools.combinations(valid, 2):
        if a[0]["index"] == b[0]["index"]:
            continue
        candidate = assemble(a, b)
        if candidate is None:
            continue
        try:
            if verify_migration(candidate[1], policy)["verified"]:
                candidates.append(candidate[0])
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
            continue
    if not candidates:
        raise ValueError("no_trusted_recovery_pair")
    if any(candidate != candidates[0] for candidate in candidates):
        raise ValueError("ambiguous_recovery")
    return candidates[0], {"protocol": "aml-evidence-shards-python-report/1", "recovered": True,
                           "policy_hint_trusted": False, "payload_sha512": digest("sha512", candidates[0]),
                           "shares_examined": len(shares), "valid_pairs": len(candidates),
                           "scope": "Project-authored Python repair and independent migration verification under external trust; no secrecy or future algorithm guarantee."}


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (5, 6):
            raise ValueError("Usage: python3 independent/python/recover_evidence_shards.py <share-a.json> <share-b.json> [share-c.json] <trusted-policy.json> <new-handoff.json>")
        share_paths, policy_path, destination = sys.argv[1:-2], sys.argv[-2], sys.argv[-1]
        shares = [strict_json(pathlib.Path(file).read_text(encoding="utf-8")) for file in share_paths]
        policy = strict_json(pathlib.Path(policy_path).read_text(encoding="utf-8"))
        material, report = recover(shares, policy)
        with open(destination, "xb") as output:
            output.write(material + b"\n")
        report["destination"] = destination
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-shards-python-report/1", "recovered": False,
                  "policy_hint_trusted": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["recovered"] else 1)
