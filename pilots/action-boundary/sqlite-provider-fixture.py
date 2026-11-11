#!/usr/bin/env python3
"""Separate-process provider fixture; ungated requests need diagnostic opt-in."""
import hashlib
import json
import sqlite3
from sqlite_path import sqlite_file_uri
import sys
import uuid
from sqlite_execution_gate import consume


def main(database, command, gate=None):
    if command == "status":
        # Read-only open cannot silently create a missing provider history.
        con = sqlite3.connect(sqlite_file_uri(database, "ro"), uri=True)
        try:
            op = sys.stdin.read().strip()
            row = con.execute("SELECT request_sha256,destination,effect_id FROM effects WHERE operation_id=?", (op,)).fetchone()
            record = None if row is None else dict(zip(
                ("request_sha256", "destination", "effect_id"), row)) | {"operation_id": op}
            print(json.dumps({"record": record}))
        finally:
            con.close()
        return
    if command != "request":
        raise ValueError("invalid_command")
    diagnostic_only = gate == "--diagnostic-only-unguarded"
    if gate is None:
        raise ValueError("execution_gate_required")
    if diagnostic_only:
        gate = None
    elif gate.startswith("--"):
        raise ValueError("invalid_gate_argument")
    envelope = json.load(sys.stdin)
    raw = envelope["request_bytes"].encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != envelope["request_sha256"]:
        raise ValueError("request_digest_mismatch")
    request = json.loads(raw)
    op = request.get("operation_id")
    destination = request.get("destination")
    if not isinstance(op, str) or not isinstance(destination, str) or not op or not destination:
        raise ValueError("invalid_request")
    if gate is not None and not consume(gate, op, digest):
        raise ValueError("execution_claim_spent")
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, destination TEXT NOT NULL, effect_id TEXT NOT NULL)")
        if envelope.get("fault") == "before_commit":
            sys.exit(76)
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT request_sha256,destination,effect_id FROM effects WHERE operation_id=?", (op,)).fetchone()
        if row is None:
            row = (digest, destination, str(uuid.uuid4()))
            con.execute("INSERT INTO effects VALUES (?,?,?,?)", (op, *row))
        elif row[:2] != (digest, destination):
            con.execute("ROLLBACK")
            raise ValueError("operation_request_conflict")
        con.execute("COMMIT")
        if envelope.get("fault") == "after_commit":
            sys.exit(75)
        print(json.dumps({"operation_id": op, "request_sha256": row[0],
                          "destination": row[1], "effect_id": row[2],
                          "diagnostic_only_unguarded": diagnostic_only}))
    finally:
        con.close()


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(2)
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    except (ValueError, KeyError, sqlite3.Error, OSError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
