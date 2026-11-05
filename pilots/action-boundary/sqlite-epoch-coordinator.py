#!/usr/bin/env python3
"""Test coordinator for the existing epochAnchor hook. One-machine SQLite only."""
import json
import re
import sqlite3
import sys

HEX = re.compile(r"^[0-9a-f]{64}$")


def valid_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def valid_epoch(value):
    return type(value) is int and 0 <= value < 2**53


def run(database, request):
    if not isinstance(request, dict) or request.get("protocol") != "aml-sqlite-epoch-test/1":
        raise ValueError("invalid_coordinator_request")
    action = request.get("action")
    if action not in ("initialize", "claim", "advance", "inspect"):
        raise ValueError("invalid_coordinator_action")
    connection = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        if action == "initialize":
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS meta (version INTEGER NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS epochs (issuer TEXT PRIMARY KEY, epoch INTEGER NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS claims (claim_key TEXT PRIMARY KEY, binding TEXT NOT NULL, issuer TEXT NOT NULL, epoch INTEGER NOT NULL)")
            if connection.execute("SELECT count(*) FROM meta").fetchone()[0] == 0:
                connection.execute("INSERT INTO meta VALUES (1)")
            connection.execute("COMMIT")
            return {"ready": True}
        if connection.execute("SELECT version FROM meta").fetchall() != [(1,)]:
            raise ValueError("coordinator_uninitialized")
        if action == "inspect":
            return {"claims": connection.execute("SELECT count(*) FROM claims").fetchone()[0],
                    "epochs": connection.execute("SELECT count(*) FROM epochs").fetchone()[0]}
        issuer = request.get("issuer_sha256")
        epoch = request.get("epoch") if action == "claim" else request.get("expected_epoch")
        if not valid_digest(issuer) or not valid_epoch(epoch):
            raise ValueError("invalid_issuer_or_epoch")
        if action == "claim":
            if request.get("claim_protocol") != "aml-file-authority-external-claim/2" or not valid_digest(request.get("claim_key_sha256")) or not valid_digest(request.get("binding_sha256")):
                raise ValueError("invalid_external_claim")
        elif request.get("epoch_protocol") != "aml-file-authority-external-epoch/1" or not valid_epoch(request.get("next_epoch")) or request["next_epoch"] != epoch + 1:
            raise ValueError("invalid_external_epoch")
        connection.execute("BEGIN IMMEDIATE")  # Single SQLite writer is the linearization domain.
        current = connection.execute("SELECT epoch FROM epochs WHERE issuer=?", (issuer,)).fetchone()
        current = current[0] if current else 0
        accepted = current == epoch
        if accepted and action == "claim":
            try:
                connection.execute("INSERT INTO claims VALUES (?,?,?,?)", (request["claim_key_sha256"], request["binding_sha256"], issuer, epoch))
            except sqlite3.IntegrityError:
                accepted = False
        elif accepted:
            connection.execute("INSERT INTO epochs(issuer, epoch) VALUES (?,?) ON CONFLICT(issuer) DO UPDATE SET epoch=excluded.epoch", (issuer, request["next_epoch"]))
        connection.execute("COMMIT")  # Return acceptance only after commit succeeds.
        if request.get("fault") == "exit_after_commit" and accepted:
            sys.exit(75)  # Simulates lost acknowledgment after a committed transaction.
        return {"accepted": accepted}
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(2)
    try:
        result = run(sys.argv[1], json.load(sys.stdin))
        print(json.dumps(result, separators=(",", ":")))
    except (ValueError, sqlite3.Error, OSError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
