#!/usr/bin/env python3
"""Ed25519-only key policy for capability tokens and threshold authorizations
(Python, stdlib only).

Same rule, reasons and order of checks as protocol/keyPolicy.js,
runtime/capabilityToken.js (verifyCapabilityToken) and
runtime/thresholdAuthorization.js (verifyThresholdAuthorization):

  * a capability token whose public key is a parseable non-Ed25519 key
    (ECDSA, RSA, RSA-PSS, Ed448, ...) is refused with "key_type_not_ed25519",
    before the fingerprint and signature checks, with or without a trust config;
  * a threshold authorization with ANY parseable non-Ed25519 signer key is
    refused as a whole with "key_type_not_ed25519" and the sorted list of
    rejected key types (named as Node.js names them: ec, rsa, rsa-pss, ed448);
  * unparseable key material is a failed signer (threshold) or
    "signature_invalid" (token), exactly as in JavaScript.

This module checks the signature layer only (what verifyCapabilityToken /
verifyThresholdAuthorization decide); it is not an authorization decision.

    python3 independent/python/key_policy.py conformance conformance/key-policy/vectors.json
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trust_config import canonical, ed25519_verify, strict_json  # noqa: E402

CAPABILITY_TOKEN_TYPE = "aml-capability-token/1"
THRESHOLD_AUTHORIZATION_VERSION = "1.1"
MAX_SIGNATURE_BYTES = 512
MAX_SIGNATURE_CHARS = 4 * ((MAX_SIGNATURE_BYTES + 2) // 3)
STANDARD_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
PEM_BLOCK = re.compile(r"-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*")
# SPKI algorithm OIDs (DER content bytes) -> Node.js asymmetricKeyType.
KEY_TYPES = {
    bytes.fromhex("2b6570"): "ed25519",              # 1.3.101.112
    bytes.fromhex("2b6571"): "ed448",                # 1.3.101.113
    bytes.fromhex("2b656e"): "x25519",               # 1.3.101.110
    bytes.fromhex("2b656f"): "x448",                 # 1.3.101.111
    bytes.fromhex("2a8648ce3d0201"): "ec",           # 1.2.840.10045.2.1
    bytes.fromhex("2a864886f70d010101"): "rsa",      # 1.2.840.113549.1.1.1
    bytes.fromhex("2a864886f70d01010a"): "rsa-pss",  # 1.2.840.113549.1.1.10
    bytes.fromhex("2a8648ce380401"): "dsa",          # 1.2.840.10040.4.1
}


def _tlv(data, offset):
    """(tag, content_start, content_end) of one DER element, or raise ValueError."""
    if offset + 2 > len(data):
        raise ValueError("short")
    tag, length = data[offset], data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or start + count > len(data):
            raise ValueError("length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise ValueError("overrun")
    return tag, start, end


def parse_public_key(pem):
    """(key_type, spki_der, raw_public_key) or None when not a parseable SPKI public key."""
    if not isinstance(pem, str):
        return None
    match = PEM_BLOCK.fullmatch(pem)
    if match is None:
        return None
    try:
        der = base64.b64decode("".join(match.group(1).split()), validate=True)
        tag, start, end = _tlv(der, 0)
        if tag != 0x30 or end != len(der):
            return None
        tag, alg_start, alg_end = _tlv(der, start)
        if tag != 0x30:
            return None
        tag, oid_start, oid_end = _tlv(der, alg_start)
        if tag != 0x06:
            return None
        tag, bits_start, bits_end = _tlv(der, alg_end)
        if tag != 0x03 or bits_end != end or bits_end - bits_start < 2 or der[bits_start] != 0:
            return None
    except (binascii.Error, ValueError):
        return None
    key_type = KEY_TYPES.get(der[oid_start:oid_end])
    if key_type is None:
        return None
    raw = der[bits_start + 1:bits_end]
    if key_type == "ed25519" and (alg_end != oid_end or len(raw) != 32):
        return None
    return key_type, der, raw


def decode_signature_base64(value):
    if not isinstance(value, str) or not value or len(value) > MAX_SIGNATURE_CHARS or STANDARD_BASE64.fullmatch(value) is None:
        return None
    raw = base64.b64decode(value)
    if not raw or len(raw) > MAX_SIGNATURE_BYTES or base64.b64encode(raw).decode("ascii") != value:
        return None
    return raw


def verify_capability_token(token):
    if not isinstance(token, dict) or token.get("type") != CAPABILITY_TOKEN_TYPE:
        return {"valid": False, "reason": "invalid_type"}
    body = {k: v for k, v in token.items() if k not in ("public_key_pem", "public_key_fingerprint", "signature_base64")}
    parsed = parse_public_key(token.get("public_key_pem"))
    if parsed is None:
        return {"valid": False, "reason": "signature_invalid"}
    key_type, der, raw = parsed
    if key_type != "ed25519":
        return {"valid": False, "reason": "key_type_not_ed25519"}
    if hashlib.sha256(der).hexdigest() != token.get("public_key_fingerprint"):
        return {"valid": False, "reason": "fingerprint_mismatch"}
    signature = decode_signature_base64(token.get("signature_base64"))
    try:
        message = canonical(body).encode("utf-8")
    except (TypeError, ValueError):
        return {"valid": False, "reason": "signature_invalid"}
    if signature is None or not ed25519_verify(raw, message, signature):
        return {"valid": False, "reason": "signature_invalid"}
    return {"valid": True, "reason": None}


def _int(value):
    """JSON number that JavaScript's Number.isInteger accepts (bool is never a number)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
        return int(value)
    return None


def verify_threshold_authorization(authorization):
    def deny(reason, rejected=None, valid_signatures=0):
        return {"valid": False, "reason": reason, "valid_signatures": valid_signatures, "rejected_key_types": rejected or []}
    threshold = _int(authorization.get("threshold")) if isinstance(authorization, dict) else None
    if threshold is None or threshold < 1:
        return deny("invalid_threshold")
    if authorization.get("version") != THRESHOLD_AUTHORIZATION_VERSION:
        return deny("legacy_threshold_unbound")
    signatures = authorization.get("signatures")
    if not isinstance(signatures, list):
        return deny("invalid_signatures")
    try:
        message = canonical({"context": authorization.get("type"), "version": authorization["version"],
                             "threshold": threshold, "payload": authorization.get("payload")}).encode("utf-8")
    except (TypeError, ValueError):
        return deny("invalid_payload")
    rejected = set()
    parsed = []
    for item in signatures:
        key = parse_public_key(item.get("public_key_pem")) if isinstance(item, dict) else None
        if key is not None and key[0] != "ed25519":
            rejected.add(key[0])
        parsed.append(key)
    if rejected:
        return deny("key_type_not_ed25519", sorted(rejected))
    seen = set()
    valid = 0
    for item, key in zip(signatures, parsed):
        if key is None:
            continue
        fingerprint = hashlib.sha256(key[1]).hexdigest()
        if fingerprint != item.get("key_fingerprint") or fingerprint in seen:
            continue
        signature = decode_signature_base64(item.get("signature_base64"))
        if signature is not None and ed25519_verify(key[2], message, signature):
            seen.add(fingerprint)
            valid += 1
    met = valid >= threshold
    return {"valid": met, "reason": None if met else "threshold_not_met", "valid_signatures": valid, "rejected_key_types": []}


def decide(kind, artifact):
    if kind == "capability-token":
        return verify_capability_token(artifact)
    if kind == "threshold-authorization":
        return verify_threshold_authorization(artifact)
    raise ValueError(f"unknown vector kind {kind}")


def main(argv):
    if len(argv) != 3 or argv[1] != "conformance":
        sys.stderr.write("usage: key_policy.py conformance <vectors.json>\n")
        return 2
    with open(argv[2], encoding="utf-8") as handle:
        vectors = strict_json(handle.read())
    results = [{"name": c["name"], "decision": decide(c["kind"], c["artifact"])} for c in vectors["cases"]]
    print(json.dumps({"implementation": "python", "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
