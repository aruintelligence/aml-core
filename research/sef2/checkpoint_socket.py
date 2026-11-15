"""Minimal local Unix socket checkpoint reader, research only.

Run under an independently controlled UID with a separately protected signing
key and database. This service does not itself prove independent administration.
"""
import json

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result

import os
import socket
import socketserver
import struct
from pinned_checkpoint import issue_checkpoint

MAX_REQUEST = 512

class CheckpointHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Linux SO_PEERCRED: pid, uid, gid. Peer authentication is mandatory.
        try:
            self.request.settimeout(3)
            raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", raw)
            if uid != self.server.allowed_uid:
                return
            line = self.rfile.readline(MAX_REQUEST + 1)
            if not line.endswith(b"\n") or len(line) > MAX_REQUEST:
                return
            req = json.loads(line, object_pairs_hook=_unique_pairs)
            if type(req) is not dict or set(req) != {"authority_id"}:
                return
            if req["authority_id"] != self.server.authority_id:
                return
            generation, sequence = self.server.read_state()
            envelope = issue_checkpoint(self.server.signing_key, self.server.authority_id,
                                        generation, sequence)
            self.wfile.write(json.dumps(envelope, sort_keys=True).encode() + b"\n")
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return

class CheckpointServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, path, *, allowed_uid, authority_id, signing_key, read_state):
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("Linux SO_PEERCRED required")
        if type(allowed_uid) is not int or allowed_uid < 0:
            raise ValueError("invalid peer UID")
        if type(authority_id) is not str or not authority_id:
            raise ValueError("invalid authority identity")
        if not callable(read_state):
            raise TypeError("trusted state reader required")
        self.allowed_uid = allowed_uid
        self.authority_id = authority_id
        self.signing_key = signing_key
        self.read_state = read_state
        super().__init__(str(path), CheckpointHandler)

def fetch_checkpoint(path, authority_id, timeout=2):
    if type(authority_id) is not str or not authority_id:
        raise ValueError("invalid authority identity")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(json.dumps({"authority_id": authority_id}).encode() + b"\n")
        response = bytearray()
        while len(response) <= 4096:
            chunk = sock.recv(1)
            if not chunk:
                break
            response.extend(chunk)
            if chunk == b"\n":
                return json.loads(response, object_pairs_hook=_unique_pairs)
        raise ValueError("missing or oversized checkpoint response")
