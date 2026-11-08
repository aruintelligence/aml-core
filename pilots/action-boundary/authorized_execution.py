"""Experimental provider-side signed authorization and one-use SQLite claim.

The database and pinned issuer key must be administered outside the AI host.
This module does not make two SQLite databases atomic or protect direct DB writes.
"""
import base64
import hashlib
import json
import re
import sqlite3
from sqlite_path import sqlite_file_uri
import subprocess
import tempfile
import time
from pathlib import Path

DOMAIN = b"AML-AUTHORIZED-EXECUTION/1\x00"
FIELDS = {"version", "issuer", "principal", "policy_id", "policy_epoch",
          "operation_id", "request_sha256", "destination", "effect",
          "expires_at_ms"}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def initialize(database, issuer_public_pem, policy_epoch=1):
    if not isinstance(policy_epoch, int) or isinstance(policy_epoch, bool) or policy_epoch < 1:
        raise ValueError("invalid_epoch")
    fingerprint = hashlib.sha256(Path(issuer_public_pem).read_bytes()).hexdigest()
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("BEGIN IMMEDIATE")
        con.execute("CREATE TABLE IF NOT EXISTS config (issuer_key_sha256 TEXT NOT NULL, policy_epoch INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS claims (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS revoked (operation_id TEXT PRIMARY KEY)")
        rows = con.execute("SELECT issuer_key_sha256,policy_epoch FROM config").fetchall()
        if not rows:
            con.execute("INSERT INTO config VALUES (?,?)", (fingerprint, policy_epoch))
        elif rows != [(fingerprint, policy_epoch)]:
            raise ValueError("trust_configuration_conflict")
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def revoke(database, operation_id):
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True, timeout=10, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (operation_id,))
        con.execute("COMMIT")
    finally:
        con.close()


def set_epoch(database, epoch):
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True, timeout=10, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        current, = con.execute("SELECT policy_epoch FROM config").fetchone()
        if not isinstance(epoch, int) or epoch <= current:
            raise ValueError("epoch_must_increase")
        con.execute("UPDATE config SET policy_epoch=?", (epoch,))
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def _verify_signature(public_key_bytes, statement, signature):
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid_authorization_signature") from error
    if len(signature_bytes) != 64:
        raise ValueError("invalid_authorization_signature")
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "message"
        sigfile = Path(directory) / "signature"
        keyfile = Path(directory) / "issuer.pem"
        message.write_bytes(DOMAIN + canonical(statement))
        sigfile.write_bytes(signature_bytes)
        keyfile.write_bytes(public_key_bytes)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                                 "-inkey", str(keyfile), "-sigfile", str(sigfile), "-in", str(message)],
                                capture_output=True, timeout=10, check=False)
        if result.returncode != 0:
            raise ValueError("invalid_authorization_signature")


def _verify_authorization_binding(public_key, statement, signature, request_bytes):
    if not isinstance(statement, dict) or set(statement) != FIELDS or statement.get("version") != "aml-authorized-execution/1":
        raise ValueError("invalid_authorization")
    # Snapshot the flat, strictly typed statement before signature/state checks.
    statement = dict(statement)
    if any(not isinstance(statement[k], str) or not statement[k] or not statement[k].isascii()
           for k in ("issuer", "principal", "policy_id", "operation_id", "destination", "effect")):
        raise ValueError("invalid_authorization")
    if (not isinstance(statement["request_sha256"], str) or not HEX.fullmatch(statement["request_sha256"]) or
        not isinstance(statement["policy_epoch"], int) or isinstance(statement["policy_epoch"], bool) or
        not isinstance(statement["expires_at_ms"], int) or isinstance(statement["expires_at_ms"], bool)):
        raise ValueError("invalid_authorization")
    if hashlib.sha256(request_bytes).hexdigest() != statement["request_sha256"]:
        raise ValueError("request_digest_mismatch")
    def unique(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise ValueError("duplicate_request_key")
            record[key] = value
        return record
    request = json.loads(request_bytes, object_pairs_hook=unique)
    if (not isinstance(request, dict) or set(request) != {"operation_id", "destination", "effect", "body"} or
        any(request.get(k) != statement[k] for k in ("operation_id", "destination", "effect"))):
        raise ValueError("request_binding_mismatch")
    # One immutable snapshot of the supplied key must be used for both checks;
    # otherwise a caller with write access can swap it between verification and
    # comparison with the authority's pinned fingerprint.
    public_key_bytes = Path(public_key).read_bytes()
    _verify_signature(public_key_bytes, statement, signature)
    return statement, request, hashlib.sha256(public_key_bytes).hexdigest()


def _consume_verified_in_transaction(con, verified):
    if not con.in_transaction:
        raise ValueError("authorization_transaction_required")
    statement, request, key_digest = verified
    rows = con.execute("SELECT issuer_key_sha256,policy_epoch FROM config").fetchall()
    if len(rows) != 1 or rows[0][0] != key_digest:
        raise ValueError("untrusted_issuer_key")
    if statement["policy_epoch"] != rows[0][1]:
        raise ValueError("stale_policy_epoch")
    if statement["expires_at_ms"] <= time.time_ns() // 1000000:
        raise ValueError("authorization_expired")
    op = statement["operation_id"]
    if con.execute("SELECT 1 FROM revoked WHERE operation_id=?", (op,)).fetchone():
        raise ValueError("authorization_revoked")
    if con.execute("SELECT 1 FROM claims WHERE operation_id=?", (op,)).fetchone():
        raise ValueError("authorization_spent")
    con.execute("INSERT INTO claims VALUES (?,?)", (op, statement["request_sha256"]))
    return request


def consume_in_transaction(con, public_key, statement, signature, request_bytes):
    """Verify and claim in a trusted provider's existing transaction; never commit.

    The caller owns BEGIN IMMEDIATE, effect validation, COMMIT and ROLLBACK.
    Only effects in this same SQLite transaction can share its atomicity. This
    is not a callback/SQL execution API and does not span another DB or service.
    The connection, key path and transaction owner must not be agent-controlled.
    """
    if not con.in_transaction:
        raise ValueError("authorization_transaction_required")
    verified = _verify_authorization_binding(public_key, statement, signature, request_bytes)
    return _consume_verified_in_transaction(con, verified)


def consume(database, public_key, statement, signature, request_bytes):
    """Legacy one-use claim API: commit before returning the parsed request."""
    # Preserve validation-before-open and the immutable key snapshot used by the
    # existing two-database fixture. Its intentional crash counterexample stays.
    verified = _verify_authorization_binding(public_key, statement, signature, request_bytes)
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        request = _consume_verified_in_transaction(con, verified)
        con.execute("COMMIT")
        return request
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
