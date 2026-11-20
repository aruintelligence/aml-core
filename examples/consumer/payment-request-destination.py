"""Local demonstration destination. Only a trusted operator invokes this process."""

import hashlib
import json
import os
import signal
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.serialization import load_pem_private_key


def submit(database, stop_at=None):
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError("request too large")
    request = json.loads(raw)
    operation = request["operation_id"]
    if (str(UUID(operation)) != operation or set(request) != {"operation_id", "amount_minor", "currency"}
            or type(request["amount_minor"]) is not int or request["amount_minor"] <= 0
            or request["currency"] != "USD"):
        raise ValueError("invalid sandbox payment request")

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS requests (operation TEXT PRIMARY KEY, request BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT INTO requests VALUES (?, ?) ON CONFLICT(operation) DO NOTHING", (operation, raw)
            )
            stored, = connection.execute(
                "SELECT request FROM requests WHERE operation = ?", (operation,)
            ).fetchone()
            if stored != raw:
                raise ValueError("operation ID already binds different bytes")
            if stop_at == "before-commit":
                os.kill(os.getpid(), signal.SIGKILL)
        if stop_at == "after-commit":
            os.kill(os.getpid(), signal.SIGKILL)
    print("recorded")


def status(database, operation, signing_key):
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        row = connection.execute("SELECT request FROM requests WHERE operation = ?", (operation,)).fetchone()
    if row is None:
        print("null")
        return
    statement = {
        "profile": "aml-sandbox-payment-status/1",
        "destination": "sandbox-payment-ledger",
        "operation_id": operation,
        "request_sha256": hashlib.sha256(row[0]).hexdigest(),
        "outcome": "recorded",
    }
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("ascii")
    key = load_pem_private_key(signing_key.read_bytes(), password=None)
    print(json.dumps({"statement": statement, "signature_hex": key.sign(canonical).hex()}))


if __name__ == "__main__":
    command, database, *args = sys.argv[1:]
    if command == "submit" and not args:
        submit(Path(database))
    elif command == "submit" and args in (["before-commit"], ["after-commit"]):
        # Fixture trigger comes from the operator, outside the request.
        submit(Path(database), stop_at=args[0])
    elif command == "status" and len(args) == 2:
        status(Path(database), args[0], Path(args[1]))
    else:
        raise SystemExit("invalid destination command")
