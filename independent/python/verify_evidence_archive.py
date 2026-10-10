#!/usr/bin/env python3
"""Independent offline verifier for the unsigned-capsule ĀML archive subset.

Uses Python's JSON/hash libraries and cryptography's Ed25519 implementation,
not the JavaScript archive or renewal modules. Trust comes only from a second
file supplied by the verifier. Neither integrity nor signatures prove history.
"""
import base64
import binascii
import hashlib
import json
import pathlib
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_evidence_capsule import canonical, reject_constant, unique_pairs, verify as verify_capsule

PROTOCOL = "aml-evidence-archive/1"
ENCODING = "canonical-json-utf8-base64/1"
BOUNDARY = "Embedded policy is an archival hint, never a trust source. Supply trusted keys and accepted head separately."
README = "ĀML evidence archive v1. Decode each base64 component as UTF-8 canonical JSON. Verify its digest and the archive root, then verify the capsule and renewal signatures using trusted keys and any remembered head obtained outside this archive. policy_hint is historical context, never a trust source. Signed times and integrity hashes do not prove historical truth or independent witnessing."
FIELDS = {"protocol", "encoding", "claim_boundary", "readme", "capsule_base64", "renewals_base64", "policy_hint_base64", "summary", "manifest", "root_sha3_512"}
MANIFEST = {"capsule_sha3_512", "renewals_sha3_512", "policy_hint_sha3_512"}
RECORD_FIELDS = {"protocol", "sequence", "previous_root_sha3_512", "created_at", "capsule_sha512", "capsule_sha3_512", "algorithm", "root_sha3_512"}
WITNESS_FIELDS = {"protocol", "signer", "signed_at", "public_key_pem", "public_key_fingerprint_sha256", "signature_base64"}
HEX128 = re.compile(r"[a-f0-9]{128}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\Z")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha3(data):
    return hashlib.sha3_512(data).hexdigest()


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def component(archive, name, digest_name):
    encoded = archive[name]
    require(isinstance(encoded, str), "invalid_base64")
    try:
        data = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(data).decode("ascii") == encoded, "noncanonical_base64")
        parsed = strict_json(data.decode("utf-8", errors="strict"))
        require(canonical(parsed) == data, "noncanonical_json_or_unsupported_numeric_serialization")
    except (binascii.Error, UnicodeError) as error:
        raise ValueError("invalid_component_encoding") from error
    require(archive["manifest"][digest_name] == sha3(data), "component_digest_mismatch")
    return parsed


def valid_fingerprints(value):
    return isinstance(value, list) and all(isinstance(x, str) and HEX64.fullmatch(x) for x in value)


def trusted_policy(policy):
    require(isinstance(policy, dict) and type(policy.get("threshold")) is int and policy["threshold"] >= 1
            and valid_fingerprints(policy.get("trusted_fingerprints")) and policy["trusted_fingerprints"], "invalid_trust_policy")
    require(valid_fingerprints(policy.get("revoked_fingerprints", [])), "invalid_trust_policy")
    by_sequence = policy.get("trusted_fingerprints_by_sequence")
    require(by_sequence is None or isinstance(by_sequence, dict), "invalid_trust_policy")
    head = policy.get("accepted_head")
    if head is not None:
        require(isinstance(head, dict) and type(head.get("sequence")) is int and head["sequence"] >= 1
                and isinstance(head.get("root_sha3_512"), str) and HEX128.fullmatch(head["root_sha3_512"]), "invalid_accepted_head")
    return head


def witness_fingerprint(record, witness, trusted, revoked):
    if not isinstance(witness, dict) or set(witness) != WITNESS_FIELDS or witness.get("protocol") != "aml-evidence-renewal-attestation/1":
        return None
    if (witness.get("signer") is not None and not isinstance(witness["signer"], str)) or not isinstance(witness.get("signed_at"), str) or not UTC.fullmatch(witness["signed_at"]):
        return None
    try:
        key = serialization.load_pem_public_key(witness["public_key_pem"].encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            return None
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        fingerprint = hashlib.sha256(der).hexdigest()
        if witness["public_key_fingerprint_sha256"] != fingerprint or fingerprint not in trusted or fingerprint in revoked:
            return None
        encoded = witness["signature_base64"]
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
            return None
        material = {"protocol": "aml-evidence-renewal-attestation/1", "record_root_sha3_512": record["root_sha3_512"],
                    "sequence": record["sequence"], "capsule_sha3_512": record["capsule_sha3_512"],
                    "signer": witness["signer"], "signed_at": witness["signed_at"]}
        key.verify(signature, canonical(material))
        return fingerprint
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, binascii.Error):
        return None


def verify_chain(capsule, entries, policy):
    head = trusted_policy(policy)
    require(isinstance(entries, list) and entries, "empty_chain")
    previous = None
    head_matched = head is None
    capsule_sha3 = sha3(canonical(capsule))
    revoked = set(policy.get("revoked_fingerprints", []))
    for sequence, entry in enumerate(entries, 1):
        require(isinstance(entry, dict) and set(entry) == {"record", "witnesses"}, "invalid_entry")
        record = entry["record"]
        require(isinstance(record, dict) and set(record) == RECORD_FIELDS, "invalid_record")
        payload = {k: v for k, v in record.items() if k != "root_sha3_512"}
        require(record["protocol"] == "aml-evidence-renewal/1" and record["algorithm"] == "SHA3-512"
                and type(record["sequence"]) is int and record["sequence"] == sequence
                and record["previous_root_sha3_512"] == previous
                and record["capsule_sha512"] == capsule["digests"]["sha512"]
                and record["capsule_sha3_512"] == capsule_sha3
                and isinstance(record["created_at"], str) and UTC.fullmatch(record["created_at"])
                and isinstance(record["root_sha3_512"], str) and HEX128.fullmatch(record["root_sha3_512"])
                and record["root_sha3_512"] == sha3(canonical(payload)), "invalid_record_or_succession")
        by_sequence = policy.get("trusted_fingerprints_by_sequence")
        fingerprints = policy["trusted_fingerprints"] if by_sequence is None else by_sequence.get(str(sequence))
        require(valid_fingerprints(fingerprints), "invalid_trust_policy")
        require(isinstance(entry["witnesses"], list), "invalid_witnesses")
        seen = {fingerprint for witness in entry["witnesses"]
                if (fingerprint := witness_fingerprint(record, witness, set(fingerprints), revoked))}
        require(len(seen) >= policy["threshold"], "quorum_not_met")
        if head is not None and head["sequence"] == sequence:
            head_matched = head["root_sha3_512"] == record["root_sha3_512"]
        previous = record["root_sha3_512"]
    require(head_matched, "accepted_head_missing_or_forked")
    return previous, head is not None


def verify(archive, policy):
    require(policy is not None, "external_trust_required")
    require(isinstance(archive, dict) and set(archive) == FIELDS and archive.get("protocol") == PROTOCOL
            and archive.get("encoding") == ENCODING and archive.get("claim_boundary") == BOUNDARY
            and archive.get("readme") == README and isinstance(archive.get("manifest"), dict)
            and set(archive["manifest"]) == MANIFEST, "unsupported_contract")
    payload = {key: value for key, value in archive.items() if key != "root_sha3_512"}
    require(archive["root_sha3_512"] == sha3(canonical(payload)), "archive_root_mismatch")
    capsule = component(archive, "capsule_base64", "capsule_sha3_512")
    entries = component(archive, "renewals_base64", "renewals_sha3_512")
    component(archive, "policy_hint_base64", "policy_hint_sha3_512")  # Never used as authority.
    require(isinstance(capsule, dict) and verify_capsule(capsule)["verified"], "invalid_or_unsupported_capsule")
    chain_head, freshness_bound = verify_chain(capsule, entries, policy)
    summary = {"receipt_sha256": capsule["receipt"]["receipt_sha256"], "renewal_count": len(entries), "head_root_sha3_512": chain_head}
    require(canonical(archive["summary"]) == canonical(summary), "summary_mismatch")
    return {"protocol": "aml-evidence-archive-python-report/1", "verified": True, "policy_hint_trusted": False,
            "receipt_sha256": summary["receipt_sha256"], "renewal_count": len(entries),
            "head_root_sha3_512": chain_head, "freshness_bound": freshness_bound,
            "scope": "Project-authored cross-runtime check of unsigned capsules and verifier-trusted Ed25519 renewals; not independent witnessing or historical truth."}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 independent/python/verify_evidence_archive.py <archive.json> <trusted-policy.json>")
        archive = strict_json(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
        policy = strict_json(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
        report = verify(archive, policy)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-archive-python-report/1", "verified": False,
                  "policy_hint_trusted": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["verified"] else 1)
