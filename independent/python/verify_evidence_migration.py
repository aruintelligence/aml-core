#!/usr/bin/env python3
"""Independent Python reader for the lossless ĀML v1 archive handoff.

The embedded policy is a hint. Caller-supplied trust is required, and this
project-authored second runtime cannot establish independent historical truth.
"""
import base64
import binascii
import hashlib
import json
import pathlib
import sys

from verify_evidence_capsule import canonical
from verify_evidence_archive import strict_json, verify as verify_archive

PROTOCOL = "aml-evidence-migration/1"
ENCODING = "canonical-json-utf8-base64/2"
BOUNDARY = "A lossless format handoff, not a cryptographic security upgrade. Original v1 bytes and external trust remain necessary."
README = "ĀML migration handoff v1 retains a canonical v1 archive in source_archive_base64 and repeats its three components in a versioned v2 layout. Verify both roots, each component digest, exact component equivalence, and the embedded v1 archive with trust supplied outside this file. The archive policy hint never establishes trust. Preserve this handoff alongside the original archive and its trust history."
PARTS = ("source_archive", "capsule", "renewals", "policy_hint")
FIELDS = {"protocol", "encoding", "claim_boundary", "readme", "source_archive_base64",
          "capsule_base64", "renewals_base64", "policy_hint_base64", "summary",
          "manifest", "root_sha3_512", "root_sha512"}
MANIFEST = {f"{part}_{algorithm}" for part in PARTS for algorithm in ("sha3_512", "sha512")}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(algorithm, data):
    return hashlib.new(algorithm, data).hexdigest()


def unpack(encoded):
    require(isinstance(encoded, str), "invalid_base64")
    try:
        data = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(data).decode("ascii") == encoded, "noncanonical_base64")
        parsed = strict_json(data.decode("utf-8", errors="strict"))
        require(canonical(parsed) == data, "noncanonical_json_or_unsupported_numeric_serialization")
        return data, parsed
    except (binascii.Error, UnicodeError) as error:
        raise ValueError("invalid_component_encoding") from error


def verify(migration, policy):
    require(policy is not None, "external_trust_required")
    require(isinstance(migration, dict) and set(migration) == FIELDS
            and migration.get("protocol") == PROTOCOL and migration.get("encoding") == ENCODING
            and migration.get("claim_boundary") == BOUNDARY and migration.get("readme") == README
            and isinstance(migration.get("manifest"), dict) and set(migration["manifest"]) == MANIFEST,
            "unsupported_contract")
    payload = {key: value for key, value in migration.items() if key not in ("root_sha3_512", "root_sha512")}
    material = canonical(payload)
    require(migration["root_sha3_512"] == digest("sha3_512", material)
            and migration["root_sha512"] == digest("sha512", material), "migration_root_mismatch")
    components = {part: unpack(migration[f"{part}_base64"]) for part in PARTS}
    expected = {f"{part}_{algorithm}": digest(algorithm, components[part][0])
                for part in PARTS for algorithm in ("sha3_512", "sha512")}
    require(migration["manifest"] == expected, "component_digest_mismatch")
    source = components["source_archive"][1]
    source_report = verify_archive(source, policy)
    require(source_report["verified"], "unverified_source_archive")
    for part in PARTS[1:]:
        require(source[f"{part}_base64"] == migration[f"{part}_base64"], "component_equivalence_mismatch")
    summary = {"source_archive_root_sha3_512": source["root_sha3_512"], **source["summary"]}
    require(canonical(migration["summary"]) == canonical(summary), "summary_mismatch")
    return {"protocol": "aml-evidence-migration-python-report/1", "verified": True,
            "policy_hint_trusted": False, "component_equivalent": True,
            "source_archive_root_sha3_512": source["root_sha3_512"],
            "migration_root_sha3_512": migration["root_sha3_512"],
            "migration_root_sha512": migration["root_sha512"],
            "renewal_count": source_report["renewal_count"],
            "freshness_bound": source_report["freshness_bound"],
            "scope": "Project-authored independent Python format and v1 trust check; no algorithm security upgrade or historical truth."}


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (3, 5) or (len(sys.argv) == 5 and sys.argv[1] != "recover"):
            raise ValueError("Usage: python3 independent/python/verify_evidence_migration.py <handoff.json> <trusted-policy.json>\n"
                             "       python3 independent/python/verify_evidence_migration.py recover <handoff.json> <trusted-policy.json> <new-v1.json>")
        recovering = len(sys.argv) == 5
        source_path, policy_path = (sys.argv[2], sys.argv[3]) if recovering else (sys.argv[1], sys.argv[2])
        migration = strict_json(pathlib.Path(source_path).read_text(encoding="utf-8"))
        policy = strict_json(pathlib.Path(policy_path).read_text(encoding="utf-8"))
        report = verify(migration, policy)
        if recovering:
            data, _ = unpack(migration["source_archive_base64"])
            with open(sys.argv[4], "xb") as output:
                output.write(data + b"\n")
            report["recovered"] = sys.argv[4]
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-migration-python-report/1", "verified": False,
                  "policy_hint_trusted": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["verified"] else 1)
