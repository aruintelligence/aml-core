#!/usr/bin/env python3
"""Experimental protected route; SQLite effect is a controlled fixture only.

The process owner must restrict effect database writes and all alternate routes.
"""
import json
import sqlite3
import sys
import uuid
from authorized_execution import consume


def main(provider_db, gate_db, issuer_key):
    envelope = json.load(sys.stdin)
    if set(envelope) != {"authorization", "signature", "request_bytes"} or not isinstance(envelope["request_bytes"], str):
        raise ValueError("invalid_envelope")
    request = consume(gate_db, issuer_key, envelope["authorization"],
                      envelope["signature"], envelope["request_bytes"].encode("utf8"))
    # A successful consumption precedes the attempted provider effect. There
    # is no atomic transaction across the two databases; crashes can strand it.
    con = sqlite3.connect(provider_db, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, destination TEXT NOT NULL, effect_id TEXT NOT NULL)")
        effect_id = str(uuid.uuid4())
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO effects VALUES (?,?,?)", (request["operation_id"], request["destination"], effect_id))
        con.execute("COMMIT")
        print(json.dumps({"operation_id": request["operation_id"], "effect_id": effect_id}))
    finally:
        con.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(2)
    try:
        main(*sys.argv[1:])
    except (ValueError, KeyError, TypeError, sqlite3.Error, OSError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
