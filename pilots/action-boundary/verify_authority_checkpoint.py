#!/usr/bin/env python3
"""Read-only, offline verifier for a protocol-3 file authority checkpoint.

This is a separate Python implementation of the on-disk commitment, not a
trusted witness or a replacement for the authority's live admission checks.
Run it on quiescent copies of the two separately retained directories.
"""
import hashlib
import json
import os
import pathlib
import re
import stat
import sys


HEX = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
MAX_SAFE = 2**53 - 1
PROTOCOL = "aml-file-authority-checkpoint/3"
COLLECTIONS = ("epochs", "grants", "operations", "claimed")
NAMES = {"epochs": re.compile(r"[0-9a-f]{64}\.json\Z"),
         "grants": re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json\Z"),
         "operations": re.compile(r"[0-9a-f]{64}\.json\Z"),
         "claimed": re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json\Z")}


class Invalid(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Invalid(code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def directory(path):
    # Check every ancestor, not only the leaf: a symlinked or replaceable
    # parent could silently direct this inspection at another snapshot.
    current = pathlib.Path(path.anchor)
    for component in (None, *path.parts[1:]):
        if component is not None:
            current /= component
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                "unsafe_directory")
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
            "unsafe_directory")


def read_record(path):
    # NOFOLLOW and fstat also reject leaf symlinks, FIFOs, and device files.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077 and 2 <= info.st_size <= 2048,
                "unsafe_record")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(2049)
        require(len(raw) == info.st_size, "record_changed_during_read")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False, "invalid_number"))
        require(type(value) is dict, "invalid_record")
        return value, raw
    finally:
        os.close(fd)


def canonical(value):
    # Protocol-3 writer records contain only ASCII keys/strings and safe
    # integers. Reject extensions instead of guessing at JS number/Unicode
    # serialization, or silently accepting a changed commitment protocol.
    require(type(value) is dict and all(type(k) is str and k.isascii()
            and type(v) in (str, int) and (type(v) is not str or v.isascii())
            and (type(v) is not int or -MAX_SAFE <= v <= MAX_SAFE)
            for k, v in value.items()), "unsupported_record_shape")
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fields(record, required, optional=()):
    require(set(required) <= record.keys() and
            record.keys() <= set(required) | set(optional), "invalid_record_fields")


def string(value, pattern):
    return type(value) is str and bool(pattern.fullmatch(value))


def number(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_SAFE


def validate_checkpoint(record):
    require(record.get("protocol") == PROTOCOL, "unsupported_checkpoint_protocol")
    fields(record, ("protocol", "store_id", "sequence", "head_sha256", "state_sha256"))
    require(string(record["store_id"], UUID) and number(record["sequence"])
            and string(record["head_sha256"], HEX)
            and string(record["state_sha256"], HEX), "invalid_checkpoint")
    canonical(record)
    if record["sequence"] == 0:
        genesis = json.dumps(["genesis", record["store_id"]],
                             separators=(",", ":")).encode("ascii")
        require(record["head_sha256"] == digest(genesis), "invalid_genesis_head")


def validate_record(kind, name, record):
    stem = name[:-5]
    if kind == "epochs":
        fields(record, ("protocol", "issuer_sha256", "epoch"))
        require(record["protocol"] == "aml-file-authority-epoch/1"
                and record["issuer_sha256"] == stem and number(record["epoch"], 1),
                "invalid_epoch_record")
    elif kind == "operations":
        fields(record, ("protocol", "operation_sha256", "grant_id",
                        "issuer_sha256", "binding_sha256", "epoch"))
        require(record["protocol"] == "aml-file-authority-operation/1"
                and record["operation_sha256"] == stem
                and string(record["grant_id"], UUID)
                and string(record["issuer_sha256"], HEX)
                and string(record["binding_sha256"], HEX)
                and number(record["epoch"]), "invalid_operation_record")
    elif kind == "grants":
        fields(record, ("protocol", "grant_id", "issuer_sha256", "binding_sha256",
                        "epoch", "issued_at_ms", "expires_at_ms"),
               ("operation_sha256", "required_claim_protocol"))
        require(record["protocol"] == "aml-file-authority-grant/1"
                and record["grant_id"] == stem
                and string(record["issuer_sha256"], HEX)
                and string(record["binding_sha256"], HEX)
                and number(record["epoch"])
                and number(record["issued_at_ms"], -MAX_SAFE)
                and number(record["expires_at_ms"], -MAX_SAFE)
                and record["expires_at_ms"] > record["issued_at_ms"]
                and ("operation_sha256" not in record or
                     string(record["operation_sha256"], HEX))
                and ("required_claim_protocol" not in record or
                     record["required_claim_protocol"] == "aml-file-authority-external-claim/1"),
                "invalid_grant_record")
    else:
        fields(record, ("protocol", "grant_id", "binding_sha256",
                        "idempotency_key_sha256"))
        require(record["protocol"] == "aml-file-authority-claim/1"
                and record["grant_id"] == stem
                and string(record["binding_sha256"], HEX)
                and string(record["idempotency_key_sha256"], HEX),
                "invalid_claim_record")
    canonical(record)


def inspect(authority, anchor):
    authority = pathlib.Path(os.path.abspath(authority))
    anchor = pathlib.Path(os.path.abspath(anchor))
    require(authority != anchor and authority not in anchor.parents
            and anchor not in authority.parents, "independent_directories_required")
    directory(authority)
    directory(anchor)
    for name in (*COLLECTIONS, "outcomes"):
        directory(authority / name)
    require(not os.path.lexists(authority / "authority.lock")
            and not os.path.lexists(anchor / "anchor.lock"), "authority_busy_or_crashed")
    require(not any(n.startswith(("checkpoint.json.", "clock.json.")) and
                    n.endswith(".tmp") for n in os.listdir(authority))
            and not any(n.startswith("checkpoint.json.") and n.endswith(".tmp")
                        for n in os.listdir(anchor)), "uncertain_checkpoint")

    local, local_bytes = read_record(authority / "checkpoint.json")
    external, external_bytes = read_record(anchor / "checkpoint.json")
    validate_checkpoint(local)
    validate_checkpoint(external)
    require(local == external, "anchor_mismatch")
    mode, _ = read_record(authority / "authority-mode.json")
    fields(mode, ("protocol", "mode"))
    require(mode["protocol"] == "aml-file-authority-mode/1" and mode["mode"] in
            ("checkpoint-anchored", "checkpoint-claim-anchored"), "invalid_authority_mode")
    entries = []
    counts = {}
    grants = {}
    operations = {}
    claims = {}
    for kind in COLLECTIONS:
        child = authority / kind
        names = os.listdir(child)
        require(all(NAMES[kind].fullmatch(n) for n in names), "unexpected_state_entry")
        counts[kind] = len(names)
        for name in sorted(names):
            record, _ = read_record(child / name)
            validate_record(kind, name, record)
            entries.append([f"{kind}/{name}", digest(canonical(record))])
            if kind == "grants":
                grants[record["grant_id"]] = record
            elif kind == "operations":
                operations[record["operation_sha256"]] = record
            elif kind == "claimed":
                claims[record["grant_id"]] = record
    for grant_id, grant in grants.items():
        op_id = grant.get("operation_sha256")
        if op_id:
            op = operations.get(op_id)
            require(op is not None and all(op[k] == grant[k] for k in
                    ("grant_id", "issuer_sha256", "binding_sha256", "epoch")),
                    "operation_grant_mismatch")
        require(("required_claim_protocol" in grant) ==
                (mode["mode"] == "checkpoint-claim-anchored"), "grant_mode_mismatch")
    for op_id, op in operations.items():
        grant = grants.get(op["grant_id"])
        require(grant is not None, "orphan_operation")
        require(grant.get("operation_sha256") == op_id,
                "operation_grant_mismatch")
    require(all(grant_id in grants and claim["binding_sha256"] ==
                grants[grant_id]["binding_sha256"] for grant_id, claim in claims.items()),
            "claim_grant_mismatch")
    entries.append(["authority-mode.json", digest(canonical(mode))])
    state = digest(json.dumps(entries, separators=(",", ":")).encode("ascii"))
    require(state == local["state_sha256"], "state_mismatch")
    require(not os.path.lexists(authority / "authority.lock")
            and not os.path.lexists(anchor / "anchor.lock"), "authority_busy_or_crashed")
    require(read_record(authority / "checkpoint.json")[1] == local_bytes and
            read_record(anchor / "checkpoint.json")[1] == external_bytes,
            "checkpoint_changed_during_read")
    return {"status": "consistent", "protocol": PROTOCOL,
            "store_id": local["store_id"], "sequence": local["sequence"],
            "state_sha256": state, "records": counts,
            "scope": "Offline checkpoint and current decision files; no historical or provider proof"}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python3 verify_authority_checkpoint.py <authority-dir> <anchor-dir>")
    try:
        result = inspect(sys.argv[1], sys.argv[2])
    except Invalid as error:
        result = {"status": "inconsistent", "reason": str(error)}
    except (OSError, ValueError, UnicodeError, TypeError) as error:
        result = {"status": "inconsistent", "reason": "unreadable_or_invalid_input",
                  "detail": type(error).__name__}
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if result["status"] == "consistent" else 1)
