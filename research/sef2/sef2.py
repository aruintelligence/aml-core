"""SEF/2 experimental independent-authority synthetic execution fixture.

Agent controls requests, not the authority/provider services or their shared secret.
Not a remote trust domain, real payment provider, or independently witnessed evidence.
"""
import hashlib
import hmac
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

MAX_BODY = 8192

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

@contextmanager
def db(path):
    con = sqlite3.connect(path, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=10000")
        yield con
    finally:
        con.close()

def initialize(authority, provider):
    with db(authority) as con:
        con.execute("CREATE TABLE IF NOT EXISTS approvals(op TEXT PRIMARY KEY, digest TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)")
    with db(provider) as con:
        con.execute("CREATE TABLE IF NOT EXISTS effects(op TEXT PRIMARY KEY, digest TEXT NOT NULL, effect_id TEXT NOT NULL)")

def approve(path, op, request_digest):
    # Administrative operation only: never exposed over the agent-facing API.
    with db(path) as con:
        con.execute("INSERT INTO approvals(op,digest) VALUES (?,?)", (op, request_digest))

def valid_request(r):
    return (type(r) is dict and set(r) == {"operation_id", "destination", "effect", "body"}
        and type(r["operation_id"]) is str and len(r["operation_id"]) == 36
        and str(uuid.UUID(r["operation_id"])) == r["operation_id"]
        and r["destination"] == "fixture:merchant-a" and r["effect"] == "payment:simulate"
        and type(r["body"]) is dict and set(r["body"]) == {"amount_minor", "currency"}
        and type(r["body"]["amount_minor"]) is int
        and 1 <= r["body"]["amount_minor"] <= 10000 and r["body"]["currency"] == "USD")

def post(url, data, secret=None):
    body = canonical(data)
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["X-SEF2-MAC"] = hmac.new(secret, body, hashlib.sha256).hexdigest()
    try:
        with urlopen(Request(url, body, headers, method="POST"), timeout=3) as res:
            return json.load(res)
    except HTTPError as error:
        return json.load(error)

def handler(kind, path, authority_url=None, secret=None, fault=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, payload):
            data = canonical(payload)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            size = self.headers.get("Content-Length", "")
            if not size.isdecimal() or int(size) > MAX_BODY:
                return self.reply(413, {"state": "DENIED", "reason": "size"})
            try:
                raw = self.rfile.read(int(size))
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError("duplicate key")
                        result[key] = value
                    return result
                payload = json.loads(raw, object_pairs_hook=pairs,
                    parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")))
                if kind == "authority":
                    mac = hmac.new(secret, raw, hashlib.sha256).hexdigest()
                    if self.path not in ("/consume", "/status") or not hmac.compare_digest(
                        self.headers.get("X-SEF2-MAC", ""), mac):
                        return self.reply(403, {"state": "DENIED", "reason": "service_auth"})
                    if type(payload) is not dict or set(payload) != {"operation_id", "request_sha256"}:
                        return self.reply(400, {"state": "DENIED"})
                    if self.path == "/status":
                        with db(path) as con:
                            row = con.execute("SELECT digest,consumed FROM approvals WHERE op=?",
                                (payload["operation_id"],)).fetchone()
                        return self.reply(200, {"state": "CONSUMED" if row and row[0] == payload["request_sha256"] and row[1] else "INCOMPLETE" if not row else "DENIED"})
                    with db(path) as con:
                        con.execute("BEGIN IMMEDIATE")
                        result = con.execute(
                            "UPDATE approvals SET consumed=1 WHERE op=? AND digest=? AND consumed=0",
                            (payload["operation_id"], payload["request_sha256"]))
                        allowed = result.rowcount == 1
                        con.execute("COMMIT")
                    return self.reply(200, {"state": "CONSUMED" if allowed else "DENIED"})
                if self.path not in ("/execute", "/status") or not valid_request(payload):
                    return self.reply(400, {"state": "DENIED", "reason": "request"})
                op = payload["operation_id"]
                request_digest = digest(payload)
                if self.path == "/status":
                    authority_state = post(authority_url + "/status",
                        {"operation_id": op, "request_sha256": request_digest}, secret)["state"]
                    with db(path) as con:
                        row = con.execute("SELECT digest,effect_id FROM effects WHERE op=?", (op,)).fetchone()
                    if row and row[0] != request_digest:
                        return self.reply(409, {"state": "UNCERTAIN", "reason": "evidence_conflict"})
                    if row and authority_state != "CONSUMED":
                        return self.reply(409, {"state": "UNCERTAIN", "reason": "authority_conflict"})
                    return self.reply(200, {"state": "PROVIDER_REPORTED" if row else "UNCERTAIN" if authority_state == "CONSUMED" else "INCOMPLETE",
                        "effect_id": row[1] if row else None, "independent_confirmation": False})
                decision = post(authority_url + "/consume",
                    {"operation_id": op, "request_sha256": request_digest}, secret)
                if decision.get("state") != "CONSUMED":
                    return self.reply(403, {"state": "DENIED"})
                try:
                    if fault == "after_claim":
                        raise RuntimeError("injected_after_claim")
                    with db(path) as con:
                        con.execute("BEGIN IMMEDIATE")
                        effect_id = str(uuid.uuid4())
                        con.execute("INSERT INTO effects VALUES (?,?,?)",
                            (op, request_digest, effect_id))
                        con.execute("COMMIT")
                    if fault == "after_effect":
                        raise RuntimeError("injected_after_effect")
                    return self.reply(200, {"state": "PROVIDER_REPORTED",
                        "effect_id": effect_id, "independent_confirmation": False})
                except sqlite3.Error:
                    return self.reply(503, {"state": "UNCERTAIN"})
            except (ValueError, TypeError, KeyError, OverflowError, sqlite3.Error):
                return self.reply(400, {"state": "DENIED"})
            except Exception:
                return self.reply(503, {"state": "UNCERTAIN"})
    return Handler

def start(kind, path, authority_url=None, secret=None, fault=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0),
        handler(kind, path, authority_url, secret, fault))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:" + str(server.server_port)
