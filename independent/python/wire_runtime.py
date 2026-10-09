#!/usr/bin/env python3
"""Dependency-free AML wire verifier. Does not import the JavaScript runtime."""

import argparse
from datetime import datetime, timezone
from functools import cmp_to_key
import hashlib
import json
from pathlib import Path
import re


HEX = re.compile(r"^[0-9a-f]{64}$")
LOWER_KEY = re.compile(r"^[a-z]+$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
MAX_SAFE_INTEGER = 2**53 - 1


class UnsupportedCanonicalValue(ValueError):
    pass


def _js_property_order(keys):
    def array_index(key):
        if not key.isascii() or not key.isdecimal():
            return None
        number = int(key)
        return number if str(number) == key and number < 2**32 - 1 else None

    indexes = sorted((key for key in keys if array_index(key) is not None), key=int)
    return indexes + [key for key in keys if array_index(key) is None]


def _json_value(value, sorted_keys):
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise UnsupportedCanonicalValue("object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass")) if sorted_keys else _js_property_order(value)
        return {key: _json_value(value[key], sorted_keys) for key in keys}
    if isinstance(value, list):
        return [_json_value(item, sorted_keys) for item in value]
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and abs(value) <= MAX_SAFE_INTEGER:
        return value
    raise UnsupportedCanonicalValue("only safe integer JSON numbers are supported")


def json_bytes(value, *, sorted_keys=True):
    normalized = _json_value(value, sorted_keys)
    try:
        return json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeError as error:
        raise UnsupportedCanonicalValue("invalid Unicode scalar") from error


def digest(value, *, raw_string=False, sorted_keys=True):
    material = value.encode("utf-8") if raw_string and isinstance(value, str) else json_bytes(value, sorted_keys=sorted_keys)
    return hashlib.sha256(material).hexdigest()


def failure(reason, **details):
    return {"valid": False, "reason": reason, **details}


def parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def compare_versions(left, right):
    if left == right:
        return 0
    if VERSION.fullmatch(left) and VERSION.fullmatch(right):
        left_parts = [int(part) for part in left.split(".")]
        right_parts = [int(part) for part in right.split(".")]
        for a, b in zip(left_parts + [0] * len(right_parts), right_parts + [0] * len(left_parts)):
            if a != b:
                return -1 if a < b else 1
    return -1 if left < right else 1


def negotiate(local, remote, required=()):
    def versions(endpoint):
        value = endpoint.get("wire_versions", endpoint.get("versions"))
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValueError("wire versions must be nonempty strings")
        return value

    def capabilities(endpoint):
        value = endpoint.get("capabilities")
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValueError("capabilities must be nonempty strings")
        return value

    common = sorted(set(capabilities(local)) & set(capabilities(remote)))
    shared_versions = sorted(set(versions(local)) & set(versions(remote)), key=cmp_to_key(compare_versions))
    missing = [item for item in required if item not in common]
    return {"protocol": "aml-wire-session/1", "accepted": bool(shared_versions) and not missing,
            "version": shared_versions[-1] if shared_versions else None,
            "capabilities": common, "missing_required": missing}


def verify_envelope(envelope, *, now=None, allowed_kinds=()):
    if not isinstance(envelope, dict) or envelope.get("protocol") != "aml-wire/1":
        return failure("invalid_protocol")
    required = {"protocol", "version", "kind", "capabilities", "payload"}
    optional = {"session_id", "nonce", "issued_at", "expires_at"}
    if not required <= envelope.keys() or envelope.keys() - required - optional:
        return failure("invalid_structure")
    if not isinstance(envelope["version"], str) or not envelope["version"] or not isinstance(envelope["kind"], str) or not envelope["kind"]:
        return failure("missing_header")
    caps = envelope["capabilities"]
    if not isinstance(caps, list) or any(not isinstance(cap, str) for cap in caps) or len(caps) != len(set(caps)):
        return failure("invalid_capabilities")
    if allowed_kinds and envelope["kind"] not in allowed_kinds:
        return failure("unsupported_kind")
    for key in ("session_id", "nonce"):
        if envelope.get(key) is not None and not isinstance(envelope[key], str):
            return failure("invalid_" + key)
    for key in ("issued_at", "expires_at"):
        if envelope.get(key) is not None and parse_time(envelope[key]) is None:
            return failure("invalid_" + key)
    if now is not None:
        current = parse_time(now)
        if current is None:
            return failure("invalid_now")
        expiry = parse_time(envelope.get("expires_at"))
        if expiry is not None and current >= expiry:
            return failure("expired")
    return {"valid": True, "reason": None, "kind": envelope["kind"], "version": envelope["version"]}


def verify_passport(passport, *, now=None):
    if not isinstance(passport, dict) or passport.get("type") != "aml-policy-passport/1":
        return failure("invalid_type")
    required = {"type", "profile", "preferences", "passport_hash"}
    allowed = required | {"subject", "issued_at", "expires_at"}
    if not required <= passport.keys() or passport.keys() - allowed or not isinstance(passport["profile"], str) or not passport["profile"] or not isinstance(passport["preferences"], dict):
        return failure("invalid_structure")
    if passport.get("subject") is not None and not isinstance(passport["subject"], str):
        return failure("invalid_subject")
    claimed = passport["passport_hash"]
    if not isinstance(claimed, str) or not HEX.fullmatch(claimed):
        return failure("invalid_hash")
    try:
        if digest({key: value for key, value in passport.items() if key != "passport_hash"}) != claimed:
            return failure("hash_mismatch")
    except UnsupportedCanonicalValue:
        return failure("unsupported_canonical_value")
    issued = parse_time(passport.get("issued_at"))
    expires = parse_time(passport.get("expires_at"))
    if passport.get("issued_at") is not None and issued is None:
        return failure("invalid_issued_at")
    if passport.get("expires_at") is not None and expires is None:
        return failure("invalid_expires_at")
    if issued is not None and expires is not None and expires <= issued:
        return failure("invalid_time_window")
    if now is None:
        return {"valid": True, "reason": None, "passport_hash": claimed, "temporal_validation": "skipped_explicitly"}
    current = parse_time(now)
    if current is None:
        return failure("invalid_now")
    if issued is not None and current < issued:
        return failure("not_yet_valid")
    if expires is not None and current >= expires:
        return failure("expired")
    return {"valid": True, "reason": None, "passport_hash": claimed, "temporal_validation": "enforced"}


def verify_bundle(bundle):
    if not isinstance(bundle, dict) or bundle.get("type") != "aml-content-bundle/1":
        return failure("invalid_type")
    files, index, root = bundle.get("files"), bundle.get("index"), bundle.get("root")
    if not isinstance(files, dict) or not isinstance(index, dict) or not isinstance(root, str) or not HEX.fullmatch(root):
        return failure("invalid_structure")
    if files.keys() != index.keys():
        return failure("index_file_set_mismatch")
    try:
        for name, entry in files.items():
            if not isinstance(entry, dict) or "value" not in entry or not isinstance(entry.get("hash"), str) or not HEX.fullmatch(entry["hash"]):
                return failure("invalid_entry", entry=name)
            if digest(entry["value"], raw_string=True) != entry["hash"]:
                return failure("entry_hash_mismatch", entry=name)
            if index[name] != entry["hash"]:
                return failure("index_mismatch", entry=name)
        if digest(index) != root:
            return failure("root_mismatch")
    except UnsupportedCanonicalValue:
        return failure("unsupported_canonical_value")
    return {"valid": True, "reason": None, "root": root}


def verify_disclosure(proof):
    if not isinstance(proof, dict) or proof.get("type") != "aml-selective-disclosure/1":
        return failure("invalid_type")
    if not isinstance(proof.get("disclosed"), list) or not isinstance(proof.get("hidden"), list):
        return failure("invalid_structure")
    root = proof.get("root")
    if not isinstance(root, str) or not HEX.fullmatch(root):
        return failure("invalid_root")
    leaves = []
    keys = set()
    try:
        for hidden, entries in ((False, proof["disclosed"]), (True, proof["hidden"])):
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("key"), str) or not LOWER_KEY.fullmatch(entry["key"]):
                    return failure("unsupported_key_order")
                key = entry["key"]
                if key in keys:
                    return failure("duplicate_key")
                keys.add(key)
                if hidden:
                    if not isinstance(entry.get("leaf"), str) or not HEX.fullmatch(entry["leaf"]):
                        return failure("invalid_entry")
                    leaf = entry["leaf"]
                else:
                    if "value" not in entry:
                        return failure("invalid_entry")
                    leaf = digest(key + ":" + json_bytes(entry["value"], sorted_keys=False).decode("utf-8"), raw_string=True)
                leaves.append((key, leaf))
        actual = digest("|".join(leaf for _, leaf in sorted(leaves)), raw_string=True)
    except UnsupportedCanonicalValue:
        return failure("unsupported_canonical_value")
    return {"valid": actual == root, "reason": None if actual == root else "root_mismatch", "root": actual}


def verify_graph(graph):
    if not isinstance(graph, dict) or graph.get("protocol") != "aml-causal-graph/1":
        return failure("invalid_protocol")
    events = graph.get("events")
    if not isinstance(events, dict):
        return failure("invalid_events")
    if not isinstance(graph.get("roots"), list) or not isinstance(graph.get("heads"), list):
        return failure("invalid_topology")
    try:
        for key, event in events.items():
            if not isinstance(event, dict) or event.get("event_hash") != key or event.get("protocol") != "aml-causal-event/1":
                return failure("invalid_event", event_hash=key)
            parents = event.get("parents")
            if not isinstance(parents, list) or any(not isinstance(parent, str) for parent in parents):
                return failure("invalid_parents", event_hash=key)
            if digest({field: value for field, value in event.items() if field != "event_hash"}) != key:
                return failure("event_hash_mismatch", event_hash=key)
            for parent in parents:
                if parent not in events:
                    return failure("missing_parent", event_hash=key, parent=parent)
        visiting, visited = set(), set()

        def visit(key):
            if key in visiting:
                return False
            if key in visited:
                return True
            visiting.add(key)
            if not all(visit(parent) for parent in events[key]["parents"]):
                return False
            visiting.remove(key)
            visited.add(key)
            return True

        if not all(visit(key) for key in events):
            return failure("cycle_detected")
        roots = sorted(key for key, event in events.items() if not event["parents"])
        referenced = {parent for event in events.values() for parent in event["parents"]}
        heads = sorted(set(events) - referenced)
        if sorted(graph["roots"]) != roots or len(graph["roots"]) != len(roots):
            return failure("roots_mismatch")
        if sorted(graph["heads"]) != heads or len(graph["heads"]) != len(heads):
            return failure("heads_mismatch")
    except (UnsupportedCanonicalValue, UnicodeError):
        return failure("unsupported_canonical_value")
    return {"valid": True, "reason": None, "event_count": len(events), "roots": roots, "heads": heads}


VERIFIERS = {"envelope": verify_envelope, "passport": verify_passport, "bundle": verify_bundle,
             "disclosure": verify_disclosure, "graph": verify_graph}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verification = commands.add_parser("verify")
    verification.add_argument("kind", choices=VERIFIERS)
    verification.add_argument("artifact", type=Path)
    verification.add_argument("--now")
    verification.add_argument("--allowed-kind", action="append", default=[])
    negotiation = commands.add_parser("negotiate")
    negotiation.add_argument("local", type=Path)
    negotiation.add_argument("remote", type=Path)
    negotiation.add_argument("--required", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.command == "negotiate":
            result = negotiate(json.loads(args.local.read_text(encoding="utf-8")),
                               json.loads(args.remote.read_text(encoding="utf-8")), args.required)
            accepted = result["accepted"]
        else:
            artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
            options = {"now": args.now} if args.kind in ("envelope", "passport") else {}
            if args.kind == "envelope":
                options["allowed_kinds"] = args.allowed_kind
            result = VERIFIERS[args.kind](artifact, **options)
            accepted = result["valid"]
    except (ValueError, OSError, TypeError) as error:
        result, accepted = failure("invalid_input", detail=str(error)), False
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
