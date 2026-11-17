#!/usr/bin/env python3
"""Pilot 003: one retained provider DB, one fixed row effect, one transaction.

This is a controlled local fixture, not an external provider or an AVEP product.
The provider administrator controls the DB, public-key pin and CLI arguments.
The agent supplies only the JSON envelope. No callbacks, SQL or network effects
are accepted. Same-identity writes and provider rollback are outside its promise.
"""
import hashlib
import json
import os
import re
import sqlite3
from sqlite_path import sqlite_file_uri
import sys
import uuid
from authorized_execution import consume_in_transaction, initialize

DESTINATION = "fixture:atomic"
EFFECT = "record:simulated"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FAILPOINTS = {"before_claim": 80, "after_claim": 81, "after_effect": 82,
              "before_commit": 83, "after_commit": 84}
MAX_INPUT_BYTES = 65536


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_input_key")
        value[key] = item
    return value


def reject_constant(_):
    raise ValueError("nonfinite_input")


def read_input():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("oversized_input")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("invalid_input")
    return value


def valid_operation(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_fixed_request(request):
    body = request["body"]
    if (not valid_operation(request["operation_id"]) or request["destination"] != DESTINATION or
            request["effect"] != EFFECT or not isinstance(body, dict) or set(body) != {"value"} or
            not isinstance(body["value"], str) or len(body["value"].encode("utf8")) > 1024):
        raise ValueError("unsupported_fixture_effect")


def initialize_provider(database, issuer_key):
    # Explicit administrative initialization only; request/status never recreate
    # missing state. The separate schema step can fail closed during cold setup.
    initialize(database, issuer_key)
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("BEGIN IMMEDIATE")
        con.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, "
                    "request_sha256 TEXT NOT NULL, destination TEXT NOT NULL, effect_id TEXT NOT NULL)")
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def request_effect(database, issuer_key, envelope, fault=None):
    if (set(envelope) != {"authorization", "signature", "request_bytes"} or
            not isinstance(envelope["request_bytes"], str)):
        raise ValueError("invalid_envelope")
    # Parse with strict duplicate/constant handling before shared legacy parsing.
    request_bytes = envelope["request_bytes"].encode("utf8")
    json.loads(request_bytes, object_pairs_hook=unique, parse_constant=reject_constant)
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True, timeout=10, isolation_level=None)
    def crash(point):
        if fault == point:
            # Abrupt process death: no Python finally/ROLLBACK. SQLite must recover.
            os._exit(FAILPOINTS[point])
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        crash("before_claim")
        request = consume_in_transaction(con, issuer_key, envelope["authorization"],
                                         envelope["signature"], request_bytes)
        crash("after_claim")
        validate_fixed_request(request)
        effect_id = str(uuid.uuid4())
        digest = hashlib.sha256(request_bytes).hexdigest()
        con.execute("INSERT INTO effects VALUES (?,?,?,?)",
                    (request["operation_id"], digest, request["destination"], effect_id))
        crash("after_effect")
        crash("before_commit")
        con.execute("COMMIT")
        crash("after_commit")
        return {"operation_id": request["operation_id"], "request_sha256": digest,
                "destination": request["destination"], "effect_id": effect_id}
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def status(database, expected):
    if (set(expected) != {"operation_id", "request_sha256", "destination"} or
            not valid_operation(expected["operation_id"]) or
            not isinstance(expected["request_sha256"], str) or not DIGEST.fullmatch(expected["request_sha256"]) or
            expected["destination"] != DESTINATION):
        raise ValueError("invalid_status_binding")
    # A consistent read snapshot, never a retry or a status rewrite. Absence is
    # INCOMPLETE: it is not evidence of no earlier effect under provider rollback.
    con = sqlite3.connect(sqlite_file_uri(database, "ro"), uri=True, timeout=10, isolation_level=None)
    try:
        con.execute("BEGIN")
        claim = con.execute("SELECT request_sha256 FROM claims WHERE operation_id=?",
                            (expected["operation_id"],)).fetchone()
        effect = con.execute("SELECT request_sha256,destination,effect_id FROM effects WHERE operation_id=?",
                             (expected["operation_id"],)).fetchone()
        if claim is None and effect is None:
            return {"protocol": "aml-atomic-provider-status/1", "result": "INCOMPLETE",
                    "record": None, "independent_confirmation": False}
        if claim is None or effect is None or claim[0] != effect[0]:
            raise ValueError("atomic_history_inconsistent")
        if (claim[0] != expected["request_sha256"] or effect[1] != expected["destination"] or
                not valid_operation(effect[2])):
            raise ValueError("request_history_conflict")
        record = dict(zip(("request_sha256", "destination", "effect_id"), effect))
        record["operation_id"] = expected["operation_id"]
        return {"protocol": "aml-atomic-provider-status/1", "result": "PROVIDER_REPORTED",
                "record": record, "independent_confirmation": False}
    finally:
        con.close()


def main():
    if len(sys.argv) < 3:
        raise ValueError("usage_database_command_required")
    database, command = sys.argv[1:3]
    if command == "initialize" and len(sys.argv) == 4:
        initialize_provider(database, sys.argv[3])
        return {"initialized": True}
    if command == "request" and len(sys.argv) in (4, 5):
        fault = None
        if len(sys.argv) == 5:
            if not sys.argv[4].startswith("--fault=") or sys.argv[4][8:] not in FAILPOINTS:
                raise ValueError("invalid_test_failpoint")
            fault = sys.argv[4][8:]
        return request_effect(database, sys.argv[3], read_input(), fault)
    if command == "status" and len(sys.argv) == 3:
        return status(database, read_input())
    raise ValueError("invalid_command")


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True, separators=(",", ":")))
    except (ValueError, KeyError, TypeError, RecursionError, sqlite3.Error, OSError) as error:
        # Error codes only; do not echo request bodies, keys or private payloads.
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
