#!/usr/bin/env python3
"""Controlled retained-status witness. Same-identity local SQLite, not a remote trust root."""
import hashlib
import json
import re
import sqlite3
import sys

UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
HEX = re.compile(r"^[0-9a-f]{64}$")


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_witness_key")
        value[key] = item
    return value


def main(database, action):
    if action == "read":
        operation = sys.stdin.read().strip()
        con = sqlite3.connect("file:" + database + "?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT envelope FROM snapshots WHERE operation_id=? ORDER BY sequence",
                               (operation,)).fetchall()
            print(json.dumps({"envelopes": [json.loads(row[0]) for row in rows]}))
        finally:
            con.close()
        return
    if action != "append":
        raise ValueError("invalid_witness_action")
    raw = sys.stdin.read()
    if len(raw.encode("utf-8")) > 8192:
        raise ValueError("oversized_witness_input")
    record = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(record, dict) or set(record) != {
        "protocol", "issuer", "operation_id", "challenge", "record", "signature"
    } or record.get("protocol") != "aml-fixture-provider-status/2" or record.get("issuer") != "fixture-provider":
        raise ValueError("invalid_witness_envelope")
    operation, challenge = record.get("operation_id"), record.get("challenge")
    if not isinstance(operation, str) or not UUID.fullmatch(operation) or not isinstance(challenge, str) or not HEX.fullmatch(challenge) or not isinstance(record["signature"], str) or not re.fullmatch(r"[A-Za-z0-9+/]{86}==", record["signature"]):
        raise ValueError("invalid_witness_binding")
    effect = record["record"]
    if effect is not None and (not isinstance(effect, dict) or set(effect) != {
        "operation_id", "request_sha256", "destination", "effect_id"
    } or effect["operation_id"] != operation or not isinstance(effect["request_sha256"], str) or not HEX.fullmatch(effect["request_sha256"]) or not isinstance(effect["destination"], str) or not effect["destination"] or not isinstance(effect["effect_id"], str) or not UUID.fullmatch(effect["effect_id"])):
        raise ValueError("invalid_witness_effect")
    if raw != json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")):
        raise ValueError("noncanonical_witness_input")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE IF NOT EXISTS snapshots (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "operation_id TEXT NOT NULL, challenge TEXT NOT NULL, digest TEXT NOT NULL, "
                    "envelope TEXT NOT NULL, UNIQUE(operation_id,challenge))")
        con.execute("BEGIN IMMEDIATE")
        existing = con.execute("SELECT digest FROM snapshots WHERE operation_id=? AND challenge=?",
                               (operation, challenge)).fetchone()
        if existing and existing[0] != digest:
            raise ValueError("witness_challenge_conflict")
        if not existing:
            con.execute("INSERT INTO snapshots(operation_id,challenge,digest,envelope) VALUES (?,?,?,?)",
                        (operation, challenge, digest, raw))
        con.execute("COMMIT")
        print(json.dumps({"retained": True, "duplicate": bool(existing)}))
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(2)
    try:
        main(sys.argv[1], sys.argv[2])
    except (ValueError, sqlite3.Error, OSError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
