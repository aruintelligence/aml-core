#!/usr/bin/env python3
"""Signed, versioned trust config and durable single use (Python, stdlib only).

Same semantics, check names and reasons as runtime/trustConfig.js and
runtime/consumptionStore.js; conformance/trust-config/vectors.json holds the
shared cases that JavaScript, Python and Go must all agree on.

A config is trusted only when every check is explicitly true: a threshold of
the current root signed it (each Ed25519 key counted once); a rotated root is
also signed by a threshold of the new root; the version is not lower than the
highest accepted one and the same version has the same digest; no caller time
was supplied; the host clock is not earlier than the persisted time floor,
not earlier than issued_at and earlier than expires_at; and the new version
was persisted (append-only, exclusive create). Revocations are sticky.

    python3 independent/python/trust_config.py trust-verify --trust-config <envelope.json> [--trust-state <dir>]
    python3 independent/python/trust_config.py conformance <vectors.json>
"""
import hashlib
import json
import os
import re
import sys
import time

TRUST_CONFIG_TYPE = "aml-trust-config/1"
TRUST_ANCHOR_TYPE = "aml-trust-anchor/1"
TRUST_STATE_RECORD_TYPE = "aml-trust-state-record/1"
SYSTEM_TRUST_STATE_DIR = "/etc/aml/trust"
MAX_SAFE_INTEGER = 2 ** 53 - 1
TRUST_ROLES = ("receipt", "policy-pack", "build-attestation", "brand-authorization", "capability-issuer")
EXIT_AUTHORIZED = 0
EXIT_NOT_AUTHORIZED = 3

HEX64 = re.compile(r"[a-f0-9]{64}")
ISO = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,3}))?Z")
PEM = re.compile(r"-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*[A-Za-z0-9+/]{1,63}={0,2}\n-----END PUBLIC KEY-----\n?")
SIG_B64 = re.compile(r"[A-Za-z0-9+/]{85}[AQgw]==")
RECORD_FILE = re.compile(r"v(\d{12})\.json")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_KEYS = 64
MAX_STATE_RECORDS = 100000
MAX_SAFE = 2 ** 53 - 1
BODY_KEYS = sorted(["expires_at", "issued_at", "policy_sha256", "profile_sha256", "registry_sha256", "require_single_use",
                    "revoked_keys", "root", "trusted_keys", "type", "version"])
CHECKS = ["anchor_present", "state_readable", "envelope_well_formed", "root_threshold_met", "new_root_threshold_met",
          "not_rolled_back", "no_version_fork", "caller_time_absent", "trusted_time", "issued_not_in_future",
          "not_expired", "state_persisted"]


# ---------- Ed25519 verification (RFC 8032, section 5.1.7) ----------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % _P
    pb = (y1 + x1) * (y2 + x2) % _P
    pc = t1 * 2 * _D * t2 % _P
    pd = z1 * 2 * z2 % _P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


# ---------- encodings ----------
def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_key")
        out[key] = value
    return out


def _reject_constant(name):
    raise ValueError(f"unsupported_constant_{name}")


def strict_json(text):
    return json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_canonical(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def as_int(value):
    """JSON number as a JS safe integer, else None (bool is never a number)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -MAX_SAFE <= value <= MAX_SAFE else None
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
        return int(value) if -MAX_SAFE <= value <= MAX_SAFE else None
    return None


def iso_ms(value):
    """Milliseconds since the epoch for a calendar-exact ISO-8601 UTC string, else None."""
    if not isinstance(value, str):
        return None
    m = ISO.fullmatch(value)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    frac = int((m.group(7) or "0").ljust(3, "0"))
    if y < 1970 or not 1 <= mo <= 12 or h > 23 or mi > 59 or se > 59:
        return None
    days_in = [31, 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not 1 <= d <= days_in[mo - 1]:
        return None
    import calendar
    return calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) * 1000 + frac


def iso_from_ms(ms):
    seconds, millis = divmod(int(ms), 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{millis:03d}Z"


def is_hex64(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def unique_hex_list(value, minimum=0):
    return (isinstance(value, list) and minimum <= len(value) <= MAX_KEYS and all(is_hex64(x) for x in value)
            and len(set(value)) == len(value))


def key_fingerprint(pem):
    """SHA-256 of the canonical Ed25519 SPKI DER; raises ValueError otherwise."""
    import base64
    import binascii
    if not isinstance(pem, str) or PEM.fullmatch(pem) is None:
        raise ValueError("AML_TRUST_KEY_PEM_INVALID")
    body = "".join(line for line in pem.split("\n") if line and not line.startswith("-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("AML_TRUST_KEY_PEM_INVALID")
    if len(der) != 44 or der[:12] != ED25519_SPKI_PREFIX:
        raise ValueError("AML_TRUST_KEY_NOT_ED25519")
    if _decompress(der[12:]) is None:
        raise ValueError("AML_TRUST_KEY_NOT_ED25519")
    return hashlib.sha256(der).hexdigest(), der[12:]


def valid_root(root):
    return (isinstance(root, dict) and sorted(root.keys()) == ["keyids", "threshold"]
            and unique_hex_list(root.get("keyids"), 1) and as_int(root.get("threshold")) is not None
            and 1 <= as_int(root["threshold"]) <= len(root["keyids"]))


def validate_body(body):
    """Return (error or None, normalized body). Mirrors validateTrustConfigBody."""
    if not isinstance(body, dict):
        return "body_not_object", None
    if sorted(body.keys()) != BODY_KEYS:
        return "body_fields", None
    if body["type"] != TRUST_CONFIG_TYPE or not isinstance(body["type"], str):
        return "type", None
    version = as_int(body["version"])
    if version is None or version < 1 or version > 999999999999:
        return "version", None
    issued, expires = iso_ms(body["issued_at"]), iso_ms(body["expires_at"])
    if issued is None or expires is None or expires <= issued:
        return "time_window", None
    if not valid_root(body["root"]):
        return "root", None
    keys = body["trusted_keys"]
    if not isinstance(keys, list) or len(keys) > MAX_KEYS:
        return "trusted_keys", None
    seen = set()
    for entry in keys:
        if not isinstance(entry, dict) or sorted(entry.keys()) != ["keyid", "roles"]:
            return "trusted_keys", None
        if not is_hex64(entry["keyid"]) or entry["keyid"] in seen:
            return "trusted_keys", None
        seen.add(entry["keyid"])
        roles = entry["roles"]
        if (not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles)
                or len(set(roles)) != len(roles) or not all(r in TRUST_ROLES for r in roles)):
            return "trusted_key_roles", None
    if not unique_hex_list(body["revoked_keys"]):
        return "revoked_keys", None
    for name in ("policy_sha256", "registry_sha256", "profile_sha256"):
        if body[name] is not None and not is_hex64(body[name]):
            return "digests", None
    if not isinstance(body["require_single_use"], bool):
        return "require_single_use", None
    normalized = dict(body, version=version, root={"keyids": list(body["root"]["keyids"]),
                                                     "threshold": as_int(body["root"]["threshold"])})
    return None, normalized


def count_threshold(envelope, body, root):
    import base64
    message = canonical(body).encode("utf-8")
    good = set()
    for sig in envelope["signatures"]:
        try:
            if (not isinstance(sig, dict) or not isinstance(sig.get("public_key_pem"), str)
                    or not isinstance(sig.get("signature_base64"), str) or SIG_B64.fullmatch(sig["signature_base64"]) is None):
                continue
            keyid, raw = key_fingerprint(sig["public_key_pem"])
            if keyid != sig.get("keyid") or keyid not in root["keyids"] or keyid in good:
                continue
            if ed25519_verify(raw, message, base64.b64decode(sig["signature_base64"], validate=True)):
                good.add(keyid)
        except (ValueError, TypeError):
            continue
    return len(good)


# ---------- durable state ----------
def _sync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_directory_chain(path):
    current = os.path.realpath(path, strict=True)
    while True:
        _sync_path(current)
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def create_exclusive_durable(path, contents):
    """O_CREAT|O_EXCL create, write, fsync file and directory. False if it exists."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as handle:
        handle.write(contents.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    _sync_directory_chain(os.path.dirname(path))
    return True


def enrolled(state_dir):
    return isinstance(state_dir, str) and state_dir != "" and os.path.exists(os.path.join(state_dir, "anchor.json"))


def read_state(state_dir):
    with open(os.path.join(state_dir, "anchor.json"), encoding="utf-8") as handle:
        anchor = json.load(handle)
    if not isinstance(anchor, dict) or anchor.get("type") != TRUST_ANCHOR_TYPE or not valid_root(anchor.get("root")):
        raise ValueError("AML_TRUST_ANCHOR_INVALID")
    versions = os.path.join(state_dir, "versions")
    names = os.listdir(versions) if os.path.exists(versions) else []
    if len(names) > MAX_STATE_RECORDS:
        raise ValueError("AML_TRUST_STATE_TOO_LARGE")
    records = []
    for name in names:
        m = RECORD_FILE.fullmatch(name)
        if not m:
            if name.startswith("."):
                continue
            raise ValueError("AML_TRUST_STATE_UNEXPECTED_FILE")
        with open(os.path.join(versions, name), encoding="utf-8") as handle:
            record = json.load(handle)
        if (not isinstance(record, dict) or record.get("type") != TRUST_STATE_RECORD_TYPE
                or as_int(record.get("version")) != int(m.group(1)) or not is_hex64(record.get("config_sha256") or "")
                or not valid_root(record.get("root")) or not unique_hex_list(record.get("revoked_keys"))
                or iso_ms(record.get("issued_at")) is None or iso_ms(record.get("accepted_at")) is None):
            raise ValueError("AML_TRUST_STATE_RECORD_INVALID")
        records.append(dict(record, version=int(m.group(1))))
    records.sort(key=lambda r: r["version"])
    latest = records[-1] if records else None
    revoked = set()
    for r in records:
        revoked.update(r["revoked_keys"])
    floor = max([max(iso_ms(r["issued_at"]), iso_ms(r["accepted_at"])) for r in records], default=None)
    root = latest["root"] if latest else anchor["root"]
    return {"anchor": anchor, "records": records, "latest": latest, "root": root, "revoked": revoked, "floor": floor}


def init_state(state_dir, threshold, root_keyids):
    root = {"keyids": list(root_keyids), "threshold": threshold}
    if not valid_root(root):
        raise ValueError("AML_TRUST_ANCHOR_INVALID_ROOT")
    os.makedirs(os.path.join(state_dir, "versions"), mode=0o700, exist_ok=True)
    if not create_exclusive_durable(os.path.join(state_dir, "anchor.json"),
                                    json.dumps({"type": TRUST_ANCHOR_TYPE, "root": root}, indent=2) + "\n"):
        raise ValueError("AML_TRUST_ANCHOR_EXISTS")
    return root


def _same_root(a, b):
    return as_int(a["threshold"]) == as_int(b["threshold"]) and sorted(a["keyids"]) == sorted(b["keyids"])


def _result(checks, **extra):
    reasons = [name for name in CHECKS if checks.get(name) is not True]
    out = {"schema": "aml-trust-config-decision/1", "trusted": not reasons, "reasons": reasons, "checks": dict(checks)}
    out.update(extra)
    return out


def _now_ms():
    return int(time.time() * 1000)


def evaluate(envelope, state_dir, caller_time=None, on_before_persist=None):
    """Mirror of evaluateTrustConfig. on_before_persist is a test seam only."""
    checks = {name: False for name in CHECKS}
    checks["anchor_present"] = enrolled(state_dir)
    if not checks["anchor_present"]:
        return _result(checks)
    try:
        state = read_state(state_dir)
        checks["state_readable"] = True
    except (OSError, ValueError, TypeError, KeyError):
        return _result(checks)
    body_error, body = "envelope", None
    if (isinstance(envelope, dict) and sorted(envelope.keys()) == ["signatures", "signed"]
            and isinstance(envelope["signatures"], list) and len(envelope["signatures"]) <= MAX_KEYS):
        body_error, body = validate_body(envelope["signed"])
    checks["envelope_well_formed"] = body_error is None
    if body_error is not None:
        return _result(checks, body_error=body_error)
    config_sha = sha256_canonical(body)
    checks["root_threshold_met"] = count_threshold(envelope, body, state["root"]) >= as_int(state["root"]["threshold"])
    checks["new_root_threshold_met"] = (_same_root(body["root"], state["root"])
                                        or count_threshold(envelope, body, body["root"]) >= body["root"]["threshold"])
    latest_version = state["latest"]["version"] if state["latest"] else 0
    checks["not_rolled_back"] = body["version"] >= latest_version
    existing = next((r for r in state["records"] if r["version"] == body["version"]), None)
    checks["no_version_fork"] = existing is None or existing["config_sha256"] == config_sha
    now = _now_ms()
    checks["caller_time_absent"] = caller_time is None or caller_time == ""
    checks["trusted_time"] = state["floor"] is None or now >= state["floor"]
    checks["issued_not_in_future"] = now >= iso_ms(body["issued_at"])
    checks["not_expired"] = now < iso_ms(body["expires_at"])
    if any(checks[n] is not True for n in CHECKS if n != "state_persisted"):
        return _result(checks, config_sha256=config_sha, version=body["version"])
    try:
        if on_before_persist is not None:
            on_before_persist()
        path = os.path.join(state_dir, "versions", "v%012d.json" % body["version"])
        created = False
        if existing is None:
            record = {"type": TRUST_STATE_RECORD_TYPE, "version": body["version"], "config_sha256": config_sha,
                      "root": body["root"], "revoked_keys": sorted(state["revoked"] | set(body["revoked_keys"])),
                      "issued_at": body["issued_at"], "accepted_at": iso_from_ms(now)}
            created = create_exclusive_durable(path, json.dumps(record, separators=(",", ":")) + "\n")
            if not created:
                with open(path, encoding="utf-8") as handle:
                    if json.load(handle).get("config_sha256") != config_sha:
                        checks["no_version_fork"] = False
                        return _result(checks, config_sha256=config_sha)
        if not created:
            _sync_path(path)
            _sync_directory_chain(os.path.dirname(path))
        after = read_state(state_dir)
        checks["not_rolled_back"] = after["latest"]["version"] == body["version"]
        state = after
        checks["state_persisted"] = checks["not_rolled_back"]
    except (OSError, ValueError, TypeError, KeyError):
        checks["state_persisted"] = False
    revoked = state["revoked"]
    trusted_keys = [{"keyid": k["keyid"], "roles": list(k["roles"])} for k in body["trusted_keys"]
                    if k["keyid"] not in revoked and k["keyid"] not in body["revoked_keys"]]
    return _result(checks, config_sha256=config_sha, version=body["version"], expires_at=body["expires_at"], effective={
        "trusted_keys": trusted_keys, "revoked_keys": sorted(revoked), "policy_sha256": body["policy_sha256"],
        "registry_sha256": body["registry_sha256"], "profile_sha256": body["profile_sha256"],
        "require_single_use": body["require_single_use"]})


def enrolled_dirs(extra_dirs, system_dir=SYSTEM_TRUST_STATE_DIR):
    out = []
    for d in [system_dir] + list(extra_dirs):
        if isinstance(d, str) and d:
            full = os.path.abspath(d)
            if full not in out and enrolled(full):
                out.append(full)
    return out


def evaluate_all(envelope, state_dirs, caller_time=None):
    if not state_dirs:
        return {"schema": "aml-trust-config-decision/1", "trusted": False, "reasons": ["anchor_present"],
                "checks": {"anchor_present": False}}
    decisions = [evaluate(envelope, d, caller_time) for d in state_dirs]
    for d in decisions:
        if d["trusted"] is not True:
            return d
    first = decisions[0]
    revoked = sorted({k for d in decisions for k in d["effective"]["revoked_keys"]})
    effective = dict(first["effective"], trusted_keys=[k for k in first["effective"]["trusted_keys"] if k["keyid"] not in revoked],
                     revoked_keys=revoked)
    return dict(first, effective=effective)


def _still_unexpired(decision):
    expires = iso_ms(decision.get("expires_at"))
    return expires is not None and _now_ms() < expires


def trusts_key(decision, keyid, role):
    return (isinstance(decision, dict) and decision.get("trusted") is True and decision.get("reasons") == []
            and _still_unexpired(decision) and is_hex64(keyid) and role in TRUST_ROLES
            and keyid not in decision["effective"]["revoked_keys"]
            and any(k["keyid"] == keyid and role in k["roles"] for k in decision["effective"]["trusted_keys"]))


def pin_matches(decision, field, actual):
    if (not isinstance(decision, dict) or decision.get("trusted") is not True or not _still_unexpired(decision)
            or field not in ("policy_sha256", "registry_sha256", "profile_sha256")):
        return False
    pin = decision["effective"][field]
    return is_hex64(pin) and actual == pin


def requires_single_use(decision):
    """Fail closed: anything but a trusted config with require_single_use false requires it."""
    return not (isinstance(decision, dict) and decision.get("trusted") is True
                and decision.get("effective", {}).get("require_single_use") is False)


# ---------- durable single-use store ----------
def consumption_key(parts):
    if not isinstance(parts, list) or not parts or not all(isinstance(p, str) and p and "\0" not in p for p in parts):
        raise ValueError("AML_CONSUMPTION_KEY_INVALID")
    return hashlib.sha256(("aml-consumption/1\0" + "\0".join(parts)).encode("utf-8")).hexdigest()


def consume(store_dir, key, record=None):
    """True exactly once per key across every process (and language) sharing store_dir."""
    if not is_hex64(key):
        raise ValueError("AML_CONSUMPTION_KEY_INVALID")
    consumed = os.path.join(os.path.abspath(store_dir), "consumed")
    os.makedirs(consumed, mode=0o700, exist_ok=True)
    body = dict(record or {}, type="aml-consumption-record/1", key=key, consumed_at=iso_from_ms(_now_ms()), pid=os.getpid())
    return create_exclusive_durable(os.path.join(consumed, key + ".json"), json.dumps(body) + "\n")


# ---------- verifier integration ----------
TRUST_FLAGS = ("--trust-config", "--trust-state", "--single-use-store")


def take_trust_flags(argv):
    """Remove the trust flags from argv; return (rest, options)."""
    rest, options, index = [], {}, 0
    while index < len(argv):
        arg = argv[index]
        if arg in TRUST_FLAGS:
            if arg in options or index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                raise ValueError(f"{arg} requires exactly one value")
            options[arg] = argv[index + 1]
            index += 2
            continue
        rest.append(arg)
        index += 1
    return rest, options


def trust_mode(options, caller_time=None, system_dir=SYSTEM_TRUST_STATE_DIR):
    """None (explicit-pin path) or {'decision', 'dirs'}; mirrors bin/aml.js trustMode()."""
    config_path = options.get("--trust-config")
    dirs = enrolled_dirs([options.get("--trust-state"), os.environ.get("AML_TRUST_STATE_DIR")], system_dir)
    if config_path is None and not dirs:
        return None
    if config_path is None:
        return {"decision": None, "dirs": dirs}
    with open(config_path, encoding="utf-8") as handle:
        envelope = strict_json(handle.read())
    if caller_time is None:
        caller_time = os.environ.get("AML_VERIFY_AT") or None
    return {"decision": evaluate_all(envelope, dirs, caller_time), "dirs": dirs}


def trust_summary(trust):
    if trust is None:
        return {"mode": "explicit-pins"}
    d = trust["decision"]
    return {"mode": "trust-config", "trusted": bool(d and d.get("trusted") is True),
            "reasons": list(d["reasons"]) if d else ["trust_config_missing"],
            "version": d.get("version") if d else None, "config_sha256": d.get("config_sha256") if d else None,
            "expires_at": d.get("expires_at") if d else None}


def single_use_stores(trust, options):
    """Mirror of bin/aml.js singleUseStores(): enrolled `single-use/` stores are
    always used with a trusted config; --single-use-store only adds one."""
    store = options.get("--single-use-store")
    trusted = trust is not None and isinstance(trust.get("decision"), dict) and trust["decision"].get("trusted") is True
    config_requires = trusted and requires_single_use(trust["decision"])
    enrolled = [os.path.join(d, "single-use") for d in trust["dirs"]] if trusted and (config_requires or store is not None) else []
    return enrolled + ([store] if store is not None else []), config_requires


def single_use(trust, options, conditions, command, artifact_id):
    """(name, ok) to add to the required conditions, or None. Consumes only when all else is true."""
    stores, config_requires = single_use_stores(trust, options)
    if not stores:
        return ("single_use_store_present", False) if config_requires else None
    ok = False
    if all(v is True for v in conditions.values()) and is_hex64(artifact_id):
        results = []
        for store in stores:
            try:
                key = consumption_key(["cli-verifier", command, artifact_id])
                results.append(consume(store, key, {"purpose": "cli-verifier", "command": command,
                                                    "artifact_sha256": artifact_id}) is True)
            except (OSError, ValueError):
                results.append(False)
        ok = bool(results) and all(results)
    return ("single_use_consumed", ok)


TRUST_DENIALS = {
    "trust_config_trusted": "AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED",
    "single_use_consumed": "AML_AUTHZ_ALREADY_CONSUMED",
    "single_use_store_present": "AML_AUTHZ_SINGLE_USE_STORE_REQUIRED",
}


def load_trust(options, caller_time=None):
    """trust_mode() that never raises: an unreadable config is an untrusted config."""
    try:
        return trust_mode(options, caller_time)
    except (OSError, ValueError, TypeError, RecursionError):
        return {"decision": {"trusted": False, "reasons": ["trust_config_unreadable"]}, "dirs": []}


def config_trusted(trust):
    d = trust["decision"] if trust else None
    return bool(isinstance(d, dict) and d.get("trusted") is True and d.get("reasons") == [] and _still_unexpired(d))


def _artifact_canonical(value):
    """Canonical JSON identical to bin/aml.js artifactSha256(): sorted keys,
    compact, safe integers only (integral floats such as 1.0 count as integers),
    BMP-only keys. Anything else raises, so single use fails closed."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError("AML_ARTIFACT_NOT_CANONICAL")
        value = int(value)
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("AML_ARTIFACT_NOT_CANONICAL")
        return str(value)
    if isinstance(value, str):
        value.encode("utf-8")  # lone surrogates raise
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_artifact_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(k, str) or any(ord(c) > 0xFFFF for c in k) for k in value):
            raise ValueError("AML_ARTIFACT_NOT_CANONICAL")
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _artifact_canonical(value[k])
                              for k in sorted(value)) + "}"
    raise ValueError("AML_ARTIFACT_NOT_CANONICAL")


def artifact_sha256(value):
    """SHA-256 of the canonical JSON of a parsed artifact (re-serializing the
    same JSON does not produce a new single-use identity)."""
    return hashlib.sha256(_artifact_canonical(value).encode("utf-8")).hexdigest()


def file_artifact_sha256(path):
    with open(path, encoding="utf-8") as handle:
        return artifact_sha256(strict_json(handle.read()))


def gate(result, options, command, artifact_id, diagnostic, caller_time=None):
    """Mirror of bin/aml.js trustGate(): AND the verifier's own decision with
    trust_config_trusted and single use. Returns (result, authorized)."""
    base = (isinstance(result, dict) and result.get("authorized") is True
            and isinstance(result.get("authorization"), dict) and result["authorization"].get("authorized") is True)
    trust = load_trust(options, caller_time)
    if trust is None and not single_use_stores(trust, options)[0]:
        return result, base
    conditions = {"verifier_decision_allowed": base}
    if trust is not None:
        conditions["trust_config_trusted"] = config_trusted(trust)
        if (command == "verify-signed-quorum" and conditions["trust_config_trusted"]
                and trust["decision"]["effective"]["policy_sha256"] is not None):
            conditions["policy_pinned"] = pin_matches(
                trust["decision"], "policy_sha256", result.get("input_fingerprints", {}).get("policy_sha256"))
    once = None if diagnostic else single_use(trust, options, conditions, command, artifact_id)
    if once is not None:
        conditions[once[0]] = once[1] is True
    authorized = not diagnostic and all(v is True for v in conditions.values())
    out = dict(result)
    if not authorized:
        prior = result.get("authorization", {}) if isinstance(result.get("authorization"), dict) else {}
        reasons = [r for r in prior.get("reasons", []) if r != "AML_AUTHZ_ALLOW"]
        reasons += [TRUST_DENIALS[n] for n in conditions if conditions[n] is not True and n in TRUST_DENIALS]
        if conditions.get("policy_pinned") is False:
            reasons.append("AML_AUTHZ_POLICY_NOT_PINNED")
        required = list(prior.get("required", [])) + [n for n in conditions if n != "verifier_decision_allowed"]
        out["authorization"] = dict(prior, authorized=False, decision="deny", reasons=list(dict.fromkeys(reasons)),
                                    required=list(dict.fromkeys(required)))
    out["authorized"] = authorized
    if trust is not None:
        out["trust"] = trust_summary(trust)
    if once is not None:
        out["single_use"] = {"consumed": conditions[once[0]] is True}
    return out, authorized


# ---------- CLI ----------
def _conformance(path):
    """Run shared vectors; print one result per step (see conformance/trust-config/)."""
    import shutil
    import tempfile
    with open(path, encoding="utf-8") as handle:
        vectors = json.load(handle)
    out = []
    for case in vectors["cases"]:
        work = tempfile.mkdtemp(prefix="aml-tc-py-")
        try:
            out.append({"name": case["name"], "steps": run_case(case, work)})
        finally:
            shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"implementation": "python", "results": out}, sort_keys=True))
    return 0


def run_case(case, work):
    state_dir = os.path.join(work, "state")
    init_state(state_dir, case["anchor"]["threshold"], case["anchor"]["keyids"])
    results = []
    for step in case["steps"]:
        action = step.get("before")
        if action:
            apply_before(action, state_dir, work)
        if "consume" in step:
            key = consumption_key(step["consume"]["parts"])
            results.append({"key": key, "consumed": consume(os.path.join(work, "store"), key)})
            continue
        envelope = step.get("envelope")
        if "envelope_text" in step:
            try:
                envelope = strict_json(step["envelope_text"])
            except (ValueError, TypeError, RecursionError):
                results.append({"parse_error": True})
                continue
        hook = None
        if "race_envelope" in step:
            def hook(race=step["race_envelope"]):
                evaluate(race, state_dir)
        decision = evaluate(envelope, state_dir, step.get("caller_time"), on_before_persist=hook)
        results.append(project(decision, step.get("queries", [])))
    return results


def apply_before(action, state_dir, work):
    kind = action["kind"]
    if kind == "floor_future":
        path = os.path.join(state_dir, "versions", "v%012d.json" % action["version"])
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
        record["accepted_at"] = iso_from_ms(_now_ms() + 86400000)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record))
    elif kind == "write_state_file":
        with open(os.path.join(state_dir, "versions", action["name"]), "w", encoding="utf-8") as handle:
            handle.write(action["contents"])
    elif kind == "remove_state_file":
        os.remove(os.path.join(state_dir, "versions", action["name"]))
    else:
        raise ValueError("unknown before action " + kind)


def project(decision, queries):
    trusted = decision["trusted"] is True
    out = {"trusted": trusted, "reasons": decision["reasons"], "version": decision.get("version"),
           "config_sha256": decision.get("config_sha256") if trusted else None,
           "effective": decision.get("effective") if trusted else None}
    answers = []
    for q in queries:
        if q["kind"] == "key":
            answers.append(trusts_key(decision, q["keyid"], q["role"]))
        elif q["kind"] == "pin":
            answers.append(pin_matches(decision, q["field"], q["actual"]))
        elif q["kind"] == "single_use":
            answers.append(requires_single_use(decision))
    out["answers"] = answers
    return out


def main(argv):
    if len(argv) == 2 and argv[0] == "conformance":
        return _conformance(argv[1])
    if argv and argv[0] == "trust-verify":
        try:
            rest, options = take_trust_flags(argv[1:])
            if rest:
                raise ValueError("unexpected arguments")
            trust = trust_mode(options)
        except (OSError, ValueError) as error:
            print(json.dumps({"authorized": False, "error": str(error)}))
            return 2
        decision = trust["decision"] if trust else None
        trusted = bool(decision and decision.get("trusted") is True and decision.get("reasons") == [])
        print(json.dumps(dict(trust_summary(trust), authorized=trusted,
                              effective=decision["effective"] if trusted else None,
                              decision_use="trust-config" if trusted else "NOT AN AUTHORIZATION DECISION"), indent=2))
        return EXIT_AUTHORIZED if trusted else EXIT_NOT_AUTHORIZED
    print(__doc__.strip().splitlines()[-2].strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
