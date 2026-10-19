#!/usr/bin/env python3
"""Project-authored AML witness verifier using only Python's standard library.

This file deliberately does not import AML JavaScript runtime code.
It implements the public prototype contracts directly:
- sorted-json-v1 canonicalization for the supported JSON domain
- SHA-256 receipt/evidence/bundle integrity
- verifier challenge binding
- P-256 ECDSA/SHA-256 verification from public JWK

Claim boundary: PASS proves these project-defined checks for the exact supplied bytes.
It does not prove identity, official authorization, policy quality, truthful intent,
or regulatory compliance.
"""

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import sys

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")


def safe_json(value):
    """Fail closed where Python and JS sorted-json-v1 bytes are not portable."""
    if type(value) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("unsupported_canonical_value")
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int and -(2 ** 53 - 1) <= value <= 2 ** 53 - 1:
        return
    if type(value) is list:
        for item in value:
            safe_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if (not isinstance(key, str) or
                    any(ord(c) > 0xFFFF or 0xD800 <= ord(c) <= 0xDFFF for c in key) or
                    (len(key) <= 10 and key.isascii() and key.isdecimal() and str(int(key)) == key and
                     int(key) < 2 ** 32 - 1)):
                raise ValueError("unsupported_object_key")
            safe_json(item)
        return
    raise ValueError("unsupported_canonical_value")


def canonical_json(value):
    safe_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def without(obj, key):
    return {k: v for k, v in obj.items() if k != key}


def b64url_decode(value):
    if not isinstance(value, str) or not BASE64URL.fullmatch(value):
        raise ValueError("invalid_base64url")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeError) as error:
        raise ValueError("invalid_base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("noncanonical_base64url")
    return decoded


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        if y1 % P == 0:
            return None
        slope = ((3 * x1 * x1 + A) * pow((2 * y1) % P, -1, P)) % P
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def verify_p256_raw_signature(public_jwk, message_bytes, signature_b64url):
    if not isinstance(public_jwk, dict) or public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        return False, "AML_PY_KEY_UNSUPPORTED"
    operations = public_jwk.get("key_ops")
    if ("d" in public_jwk or
            (operations is not None and (
                not isinstance(operations, list) or
                any(not isinstance(operation, str) for operation in operations) or
                len(set(operations)) != len(operations) or "verify" not in operations
            )) or
            ("ext" in public_jwk and type(public_jwk["ext"]) is not bool) or
            public_jwk.get("use", "sig") != "sig" or
            public_jwk.get("alg", "ES256") != "ES256"):
        return False, "AML_PY_KEY_USAGE_INVALID"
    try:
        x_bytes = b64url_decode(public_jwk["x"])
        y_bytes = b64url_decode(public_jwk["y"])
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            return False, "AML_PY_KEY_INVALID"
        x, y = int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big")
    except (ValueError, TypeError, KeyError):
        return False, "AML_PY_KEY_INVALID"
    if x >= P or y >= P or (y * y - (x * x * x + A * x + B)) % P != 0:
        return False, "AML_PY_KEY_NOT_ON_CURVE"

    try:
        signature = b64url_decode(signature_b64url)
    except (ValueError, TypeError):
        return False, "AML_PY_SIGNATURE_ENCODING_UNSUPPORTED"
    if len(signature) != 64:
        return False, "AML_PY_SIGNATURE_ENCODING_UNSUPPORTED"
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False, "AML_PY_SIGNATURE_RANGE_INVALID"

    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
    w = pow(s, -1, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(point_mul(u1, (GX, GY)), point_mul(u2, (x, y)))
    if point is None or point[0] % N != r:
        return False, "AML_PY_SIGNATURE_INVALID"
    return True, "AML_PY_SIGNATURE_VALID"


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("AML_PY_CHALLENGE_TIME_INVALID")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("AML_PY_CHALLENGE_TIME_INVALID")
    return parsed


def canonical_challenge_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", value):
        raise ValueError("AML_PY_CHALLENGE_TIME_INVALID")
    parsed = parse_time(value)
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        raise ValueError("AML_PY_CHALLENGE_TIME_INVALID")
    return parsed


def verify_challenge(challenge, now):
    if (not isinstance(challenge, dict) or
            set(challenge) != {"schema", "prototype", "nonce", "issued_at", "expires_at"} or
            challenge.get("schema") != "aml-verification-challenge/1" or
            challenge.get("prototype") is not True):
        return False, "AML_PY_CHALLENGE_INVALID"
    nonce = challenge.get("nonce")
    try:
        if len(b64url_decode(nonce)) != 32 or len(nonce) != 43:
            return False, "AML_PY_CHALLENGE_NONCE_INVALID"
    except ValueError:
        return False, "AML_PY_CHALLENGE_NONCE_INVALID"
    try:
        issued = canonical_challenge_time(challenge.get("issued_at"))
        expires = canonical_challenge_time(challenge.get("expires_at"))
        if expires <= issued or now.tzinfo is None:
            return False, "AML_PY_CHALLENGE_TIME_INVALID"
    except (ValueError, TypeError, OverflowError):
        return False, "AML_PY_CHALLENGE_TIME_INVALID"
    if now < issued:
        return False, "AML_PY_CHALLENGE_NOT_YET_VALID"
    if now > expires:
        return False, "AML_PY_CHALLENGE_EXPIRED"
    return True, "AML_PY_CHALLENGE_VALID"


def verify_integrity(payload, label):
    if not isinstance(payload, dict) or not isinstance(payload.get("integrity"), dict):
        return False, f"AML_PY_{label}_UNSEALED"
    integrity = payload["integrity"]
    if (set(integrity) != {"schema", "algorithm", "canonicalization", "value"} or
            integrity["schema"] != "aml-integrity/1" or
            integrity["canonicalization"] != "sorted-json-v1" or
            not isinstance(integrity["value"], str) or not HEX64.fullmatch(integrity["value"])):
        return False, f"AML_PY_{label}_INTEGRITY_INVALID"
    if integrity["algorithm"] != "SHA-256":
        return False, f"AML_PY_{label}_ALGORITHM_UNSUPPORTED"
    if sha256_json(without(payload, "integrity")) != integrity["value"]:
        return False, f"AML_PY_{label}_HASH_MISMATCH"
    return True, f"AML_PY_{label}_INTEGRITY_VALID"


def verify_bundle(bundle, now=None, expected_challenge=None):
    try:
        return _verify_bundle(bundle, now, expected_challenge)
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as error:
        return False, str(error) or "AML_PY_BUNDLE_INVALID"


def _verify_bundle(bundle, now, expected_challenge):
    safe_json(bundle)
    if expected_challenge is not None:
        safe_json(expected_challenge)
    if not isinstance(bundle, dict):
        return False, "AML_PY_BUNDLE_INVALID"
    if bundle.get("schema") != "aml-witness-bundle/1":
        return False, "AML_PY_BUNDLE_INVALID"

    valid, reason = verify_integrity(bundle, "BUNDLE")
    if not valid:
        return valid, reason

    evidence = bundle.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("schema") != "aml-browser-evidence/1":
        return False, "AML_PY_EVIDENCE_INVALID"
    receipt = evidence.get("receipt")
    if not isinstance(receipt, dict) or receipt.get("schema") != "aml-dom-receipt/1":
        return False, "AML_PY_RECEIPT_INVALID"
    for payload, label in ((receipt, "RECEIPT"), (evidence, "EVIDENCE")):
        valid, reason = verify_integrity(payload, label)
        if not valid:
            return valid, reason
    evidence_integrity = evidence["integrity"]

    challenge = bundle.get("challenge")
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    if expected_challenge is not None:
        valid, reason = verify_challenge(expected_challenge, now)
        if not valid:
            return valid, reason
        if canonical_json(challenge) != canonical_json(expected_challenge):
            return False, "AML_PY_BUNDLE_CHALLENGE_MISMATCH"
    valid, reason = verify_challenge(challenge, now)
    if not valid:
        return valid, reason

    attestation = bundle.get("attestation")
    if not isinstance(attestation, dict) or attestation.get("schema") != "aml-session-attestation/1":
        return False, "AML_PY_ATTESTATION_INVALID"
    if attestation.get("algorithm") != "ECDSA-P256-SHA256":
        return False, "AML_PY_ATTESTATION_ALGORITHM_UNSUPPORTED"
    if attestation.get("evidence_hash") != evidence_integrity.get("value"):
        return False, "AML_PY_ATTESTATION_EVIDENCE_MISMATCH"
    if attestation.get("challenge_nonce") != challenge.get("nonce"):
        return False, "AML_PY_ATTESTATION_CHALLENGE_MISMATCH"
    if attestation.get("challenge_expires_at") != challenge.get("expires_at"):
        return False, "AML_PY_ATTESTATION_CHALLENGE_EXPIRY_MISMATCH"

    public_jwk = attestation.get("session_public_key_jwk") or {}
    fingerprint = sha256_json(public_jwk)
    if fingerprint != attestation.get("session_key_fingerprint"):
        return False, "AML_PY_KEY_FINGERPRINT_MISMATCH"

    payload = without(attestation, "signature")
    signature_ok, reason = verify_p256_raw_signature(
        public_jwk,
        canonical_json(payload).encode("utf-8"),
        attestation.get("signature", ""),
    )
    if not signature_ok:
        return False, reason

    # These are claims in the supplied artifact, not trusted time evidence.
    # Still reject a timeline that cannot hold at the replay instant.
    def canonical_utc_millis(value):
        if not isinstance(value, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
            raise ValueError("AML_PY_BUNDLE_TIME_INVALID")
        try:
            parsed = parse_time(value)
            if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
                raise ValueError("AML_PY_BUNDLE_TIME_INVALID")
            return parsed
        except (ValueError, OverflowError) as error:
            raise ValueError("AML_PY_BUNDLE_TIME_INVALID") from error

    attested = canonical_utc_millis(attestation.get("issued_at"))
    created = canonical_utc_millis(bundle.get("created_at"))
    evidenced = canonical_utc_millis(evidence.get("generated_at"))
    receipted = canonical_utc_millis(receipt["generated_at"]) if "generated_at" in receipt else None
    if (receipted is not None and receipted > evidenced) or evidenced > attested or \
            attested < parse_time(challenge["issued_at"]) or created < attested or \
            created > parse_time(challenge["expires_at"]):
        return False, "AML_PY_BUNDLE_TIME_ORDER_INVALID"
    if created > now:
        return False, "AML_PY_BUNDLE_NOT_YET_CREATED"

    return True, "AML_PY_WITNESS_BUNDLE_VALID"


def load_json(filename):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    with open(filename, encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non_json_number")))


def main():
    parser = argparse.ArgumentParser(description="Verify an aml-witness-bundle/1 artifact")
    parser.add_argument("bundle")
    parser.add_argument("--challenge", help="Separately retained verifier challenge")
    parser.add_argument("--now", help="Test-only ISO-8601 time override for fixed vectors")
    args = parser.parse_args()
    try:
        bundle = load_json(args.bundle)
        expected_challenge = load_json(args.challenge) if args.challenge else None
        if args.challenge and not isinstance(expected_challenge, dict):
            raise ValueError("AML_PY_HELD_CHALLENGE_INVALID")
        now = parse_time(args.now) if args.now else None
        valid, reason = verify_bundle(bundle, now=now, expected_challenge=expected_challenge)
    except (OSError, ValueError) as error:
        valid, reason = False, str(error)
    print(json.dumps({"valid": valid, "reason": reason}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
