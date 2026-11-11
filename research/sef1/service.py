#!/usr/bin/env python3
"""PRIVATE SEF/1 lab. No production effects or new published wire standard.

One trusted process owns a retained claim store and a fixed provider fixture.
Only the agent subprocess is sandboxed; host/kernel administrators are trusted.
Reuses the already disclosed aml-authorized-execution/1 signature profile.
"""
import argparse
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pilots/action-boundary"))
from authorized_execution import consume
from sqlite_path import sqlite_file_uri

MAX_WIRE = 65536
MAX_SCAN_BATCH = 64
DESTINATION = "fixture:merchant-a"
EFFECT = "payment:simulate"


class EvidenceConflict(Exception):
    """Trusted stores disagree about a possible effect; never deny as absent."""


def strict_json(raw):
    if len(raw) > MAX_WIRE:
        raise ValueError("input_limit")
    text = raw.decode("utf-8", errors="strict")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 16:
                raise ValueError("depth_limit")
        elif char in "]}":
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    def reject(_):
        raise ValueError("numeric_profile")
    def integer(value):
        if len(value) > 17 or abs(int(value)) > 2**53 - 1:
            raise ValueError("numeric_profile")
        return int(value)
    return json.loads(text, object_pairs_hook=pairs, parse_float=reject,
                      parse_constant=reject, parse_int=integer)


def connect(database, mode="rw"):
    # Never create or repair missing state during a request or status lookup.
    con = sqlite3.connect(sqlite_file_uri(database, mode), uri=True, timeout=5, isolation_level=None)
    con.execute("PRAGMA synchronous=FULL")
    return con


def initialize_provider(database):
    con = sqlite3.connect(database)
    try:
        con.execute("CREATE TABLE effects (operation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                    "destination TEXT NOT NULL, effect_id TEXT NOT NULL)")
        con.commit()
    finally:
        con.close()


def fixed_request(envelope):
    if (not isinstance(envelope, dict) or set(envelope) != {"authorization", "signature", "request_bytes"}
            or not isinstance(envelope["request_bytes"], str)):
        raise ValueError("envelope_profile")
    raw = envelope["request_bytes"].encode("utf-8", errors="strict")
    request = strict_json(raw)
    if not isinstance(request, dict) or set(request) != {"operation_id", "destination", "effect", "body"}:
        raise ValueError("request_profile")
    op = request["operation_id"]
    if not isinstance(op, str) or str(uuid.UUID(op)) != op:
        raise ValueError("operation_profile")
    body = request["body"]
    if (request["destination"] != DESTINATION or request["effect"] != EFFECT or
        not isinstance(body, dict) or set(body) != {"amount_minor", "currency"} or
        type(body["amount_minor"]) is not int or not 1 <= body["amount_minor"] <= 10000 or body["currency"] != "USD"):
        raise ValueError("policy_denied")
    statement = envelope["authorization"]
    if (not isinstance(statement, dict) or statement.get("principal") != "agent:lab" or
        statement.get("issuer") != "issuer:lab" or statement.get("policy_id") != "payables:lab"):
        raise ValueError("identity_policy_denied")
    return raw, request


class Fabric:
    def __init__(self, authority, provider, public_key, fault=None):
        self.authority, self.provider, self.public_key, self.fault = authority, provider, public_key, fault

    def handle(self, message):
        if (not isinstance(message, dict) or message.get("protocol") != "aml-sef-lab-request/1" or
            not isinstance(message.get("challenge"), str) or not re.fullmatch(r"[0-9a-f]{32}", message["challenge"])):
            raise ValueError("message_profile")
        if message.get("command") == "submit" and set(message) == {"protocol", "command", "challenge", "envelope"}:
            envelope = message["envelope"]
            raw, request = fixed_request(envelope)
            # Retain the one-use decision BEFORE the effect; no reusable dispatch
            # token is returned to the untrusted agent. This sacrifices liveness
            # across the gap rather than retrying an ambiguous external effect.
            consume(self.authority, self.public_key, envelope["authorization"], envelope["signature"], raw)
            if self.fault == "after_claim":
                os._exit(85)
            con = connect(self.provider)
            try:
                con.execute("BEGIN IMMEDIATE")
                effect_id = str(uuid.uuid4())
                con.execute("INSERT INTO effects VALUES (?,?,?,?)", (request["operation_id"],
                    hashlib.sha256(raw).hexdigest(), request["destination"], effect_id))
                con.execute("COMMIT")
            finally:
                con.close()
            if self.fault == "after_effect":
                os._exit(86)
            return self.status({"operation_id": request["operation_id"],
                "request_sha256": hashlib.sha256(raw).hexdigest(), "destination": request["destination"]}, message["challenge"])
        if message.get("command") == "status" and set(message) == {"protocol", "command", "challenge", "binding"}:
            return self.status(message["binding"], message["challenge"])
        raise ValueError("unsupported_command")

    def status(self, binding, challenge):
        if (not isinstance(binding, dict) or set(binding) != {"operation_id", "request_sha256", "destination"} or
            not isinstance(binding["request_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", binding["request_sha256"]) or
            binding["destination"] != DESTINATION or not isinstance(binding["operation_id"], str)):
            raise ValueError("status_profile")
        a = connect(self.authority, "ro")
        try:
            p = connect(self.provider, "ro")
            try:
                claim = a.execute("SELECT request_sha256 FROM claims WHERE operation_id=?", (binding["operation_id"],)).fetchone()
                row = p.execute("SELECT digest,destination,effect_id FROM effects WHERE operation_id=?", (binding["operation_id"],)).fetchone()
            finally:
                p.close()
        finally:
            a.close()
        if claim and claim[0] != binding["request_sha256"]:
            raise ValueError("binding_conflict")
        if row and (not claim or row[:2] != (binding["request_sha256"], binding["destination"])):
            raise EvidenceConflict("evidence_conflict")
        return {"protocol": "aml-sef-lab-status/1", "challenge": challenge, **binding,
                "state": "PROVIDER_REPORTED" if row else "UNCERTAIN" if claim else "INCOMPLETE",
                "effect_id": row[2] if row else None, "independent_confirmation": False}


def serve(inbox, outbox, fabric):
    """Lab file transport; only the trusted process reads the request queue."""
    while True:
        # Avoid materializing an attacker-controlled directory in memory.
        for entry in islice(Path(inbox).glob("*.request"), MAX_SCAN_BATCH):
            identifier = entry.name[:-8]
            if not re.fullmatch(r"[0-9a-f]{32}", identifier):
                try:
                    entry.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            try:
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    raw = os.read(fd, MAX_WIRE + 1)
                finally:
                    os.close(fd)
                entry.unlink()
                response = fabric.handle(strict_json(raw))
            except (ValueError, TypeError, KeyError, RecursionError):
                try:
                    entry.unlink(missing_ok=True)
                except OSError:
                    pass
                response = {"state": "DENIED", "reason": "AML_SEF_REQUEST_REJECTED", "independent_confirmation": False}
            except (EvidenceConflict, sqlite3.Error, OSError):
                try:
                    entry.unlink(missing_ok=True)
                except OSError:
                    pass
                # A claim or effect may already be committed. A storage fault
                # cannot truthfully be reported as an authorization denial.
                response = {"state": "UNCERTAIN", "reason": "AML_SEF_STORAGE_UNAVAILABLE",
                            "independent_confirmation": False}
            destination = Path(outbox) / (identifier + ".response")
            staged = Path(outbox) / (identifier + ".tmp")
            try:
                with staged.open("x", encoding="utf-8") as stream:
                    json.dump(response, stream, separators=(",", ":"))
                    stream.flush()
                    os.fsync(stream.fileno())
                if fabric.fault == "before_response_publish":
                    os._exit(87)
                # A same-name retry cannot replace an earlier response. The
                # new name becomes visible only after all bytes are written.
                os.link(staged, destination, follow_symlinks=False)
            except OSError:
                pass  # Lost acknowledgment never authorizes another attempt.
            finally:
                staged.unlink(missing_ok=True)
        time.sleep(0.01)


def main():
    parser = argparse.ArgumentParser()
    for flag in ("inbox", "outbox", "authority", "provider", "public-key"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--fault", choices=("after_claim", "after_effect", "before_response_publish"))
    args = parser.parse_args()
    # Only the trusted launcher chooses paths/failpoints; none are API inputs.
    serve(args.inbox, args.outbox, Fabric(args.authority, args.provider, args.public_key, args.fault))


if __name__ == "__main__":
    main()
