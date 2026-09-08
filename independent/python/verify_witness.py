#!/usr/bin/env python3
"""Independent-style AML witness verifier using only Python's standard library.

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
import datetime as dt
import hashlib
import json
import sys

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def without(obj, key):
    return {k: v for k, v in obj.items() if k != key}


def b64url_decode(value):
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode("ascii"))


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
    if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        return False, "AML_PY_KEY_UNSUPPORTED"
    try:
        x = int.from_bytes(b64url_decode(public_jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(public_jwk["y"]), "big")
    except Exception:
        return False, "AML_PY_KEY_INVALID"
    if (y * y - (x * x * x + A * x + B)) % P != 0:
        return False, "AML_PY_KEY_NOT_ON_CURVE"

    signature = b64url_decode(signature_b64url)
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
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify_bundle(bundle, now=None):
    if bundle.get("schema") != "aml-witness-bundle/1":
        return False, "AML_PY_BUNDLE_INVALID"

    integrity = bundle.get("integrity") or {}
    if integrity.get("algorithm") != "SHA-256":
        return False, "AML_PY_BUNDLE_ALGORITHM_UNSUPPORTED"
    if sha256_json(without(bundle, "integrity")) != integrity.get("value"):
        return False, "AML_PY_BUNDLE_HASH_MISMATCH"

    evidence = bundle.get("evidence") or {}
    receipt = evidence.get("receipt") or {}
    receipt_integrity = receipt.get("integrity") or {}
    if sha256_json(without(receipt, "integrity")) != receipt_integrity.get("value"):
        return False, "AML_PY_RECEIPT_HASH_MISMATCH"
    evidence_integrity = evidence.get("integrity") or {}
    if sha256_json(without(evidence, "integrity")) != evidence_integrity.get("value"):
        return False, "AML_PY_EVIDENCE_HASH_MISMATCH"

    challenge = bundle.get("challenge") or {}
    if challenge.get("schema") != "aml-verification-challenge/1":
        return False, "AML_PY_CHALLENGE_INVALID"
    if not challenge.get("nonce") or len(challenge["nonce"]) < 32:
        return False, "AML_PY_CHALLENGE_NONCE_INVALID"
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    if now > parse_time(challenge["expires_at"]):
        return False, "AML_PY_CHALLENGE_EXPIRED"

    attestation = bundle.get("attestation") or {}
    if attestation.get("schema") != "aml-session-attestation/1":
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

    return True, "AML_PY_WITNESS_BUNDLE_VALID"


def main():
    parser = argparse.ArgumentParser(description="Verify an aml-witness-bundle/1 artifact")
    parser.add_argument("bundle")
    parser.add_argument("--now", help="ISO-8601 verification time, useful for fixed vectors")
    args = parser.parse_args()

    with open(args.bundle, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)

    now = parse_time(args.now) if args.now else None
    valid, reason = verify_bundle(bundle, now=now)
    print(json.dumps({"valid": valid, "reason": reason}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
