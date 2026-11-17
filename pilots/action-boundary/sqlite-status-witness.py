#!/usr/bin/env python3
"""Controlled retained-status witness. Same-identity local SQLite, not a remote trust root."""
import hashlib
import base64
import json
import re
import sqlite3
from sqlite_path import sqlite_file_uri
import subprocess
import sys
import tempfile
from pathlib import Path

UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
HEX = re.compile(r"^[0-9a-f]{64}$")


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_witness_key")
        value[key] = item
    return value


def main(database, action, public_key=None):
    if action == "read":
        operation = sys.stdin.read().strip()
        con = sqlite3.connect(sqlite_file_uri(database, "ro"), uri=True)
        try:
            rows = con.execute("SELECT envelope FROM snapshots WHERE operation_id=? ORDER BY sequence",
                               (operation,)).fetchall()
            print(json.dumps({"envelopes": [json.loads(row[0]) for row in rows]}))
        finally:
            con.close()
        return
    if action not in ("initialize", "append"):
        raise ValueError("invalid_witness_action")
    if not public_key or not Path(public_key).is_file():
        raise ValueError("pinned_witness_key_required")
    key_hash = hashlib.sha256(Path(public_key).read_bytes()).hexdigest()
    if action == "initialize":
        con = sqlite3.connect(database, timeout=10, isolation_level=None)
        try:
            con.execute("PRAGMA synchronous=FULL")
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("BEGIN IMMEDIATE")
            con.execute("CREATE TABLE IF NOT EXISTS meta (key_sha256 TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS snapshots (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "operation_id TEXT NOT NULL, challenge TEXT NOT NULL, digest TEXT NOT NULL, "
                        "envelope TEXT NOT NULL, UNIQUE(operation_id,challenge))")
            rows = con.execute("SELECT key_sha256 FROM meta").fetchall()
            if not rows:
                con.execute("INSERT INTO meta VALUES (?)", (key_hash,))
            elif rows != [(key_hash,)]:
                raise ValueError("witness_trust_root_mismatch")
            con.execute("COMMIT")
            print(json.dumps({"initialized": True}))
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return
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
    statement = {key: value for key, value in record.items() if key != "signature"}
    signed = b"AML-LOCAL-PROVIDER-STATUS/2\0" + json.dumps(
        statement, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="aml-witness-verify-") as temp:
        data = Path(temp) / "statement"
        signature = Path(temp) / "signature"
        data.write_bytes(signed)
        signature.write_bytes(base64.b64decode(record["signature"], validate=True))
        check = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                                public_key, "-rawin", "-in", str(data), "-sigfile",
                                str(signature)], capture_output=True, timeout=10, check=False)
        if check.returncode != 0:
            raise ValueError("invalid_witness_signature")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("BEGIN IMMEDIATE")
        if con.execute("SELECT key_sha256 FROM meta").fetchall() != [(key_hash,)]:
            raise ValueError("witness_trust_root_mismatch")
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
    if len(sys.argv) not in (3, 4):
        sys.exit(2)
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    except (ValueError, sqlite3.Error, OSError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
