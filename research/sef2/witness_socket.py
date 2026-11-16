"""Linux SO_PEERCRED-protected witness service (synthetic SEF2 research).

Run as a distinct UID from the authorized reservation authority. The Unix
socket directory and witness database must be protected from that caller.
No remote access or self-declared caller identity is accepted.
"""
import json
import socket
import socketserver
import struct
import threading

from witness_protocol import validate_witness_advance

MAX_REQUEST = 1024
MAX_RESPONSE = 64

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

class WitnessHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(3)
            raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", raw)
            if uid != self.server.allowed_uid:
                return
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
                return
            request = json.loads(line, object_pairs_hook=_unique_pairs)
            args = validate_witness_advance(request, self.server.store.authority_id)
            if args is None:
                accepted = False
            else:
                if self.server.committed_bridge is None:
                    accepted = (False if self.server.require_committed_evidence
                                else self.server.store.observe(*args) is True)
                else:
                    # Verify the requested next checkpoint against independently
                    # opened committed evidence; do not trust a caller entry.
                    bridge = self.server.committed_bridge
                    accepted = False
                    if bridge.source_is_current() and self.server.store.inspect() == (args[2], args[3]):
                        try:
                            evidence_head, evidence_entries = bridge.ledger.evidence()
                            if (evidence_head == (args[0], args[1])
                                and len(evidence_entries) == args[0]
                                and tuple(evidence_entries[-1]) == args[4]):
                                # Recheck both sources after the request-specific snapshot.
                                if (bridge.source_is_current() is not True
                                    or self.server.store.inspect() != (args[2], args[3])):
                                    accepted = False
                                else:
                                    accepted = bridge.advance(self.server.store) is True
                                if accepted:
                                    accepted = self.server.store.inspect() == (args[0], args[1])
                        except (OSError, ValueError, TypeError, IndexError):
                            accepted = False
            self.wfile.write(json.dumps({"accepted": accepted}).encode() + b"\n")
        except (OSError, ValueError, TypeError, OverflowError):
            return

class WitnessServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False
    request_queue_size = 16
    MAX_ACTIVE = 32

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def __init__(self, path, *, allowed_uid, store, committed_bridge=None, require_committed_evidence=False):
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("Linux SO_PEERCRED required")
        if type(allowed_uid) is not int or allowed_uid < 0:
            raise ValueError("invalid allowed UID")
        if not callable(getattr(store, "observe", None)):
            raise TypeError("witness store required")
        if committed_bridge is not None and (not callable(getattr(committed_bridge, "advance", None))
            or committed_bridge.authority_id != store.authority_id):
            raise ValueError("invalid committed evidence bridge")
        if type(require_committed_evidence) is not bool:
            raise ValueError("invalid evidence requirement")
        if require_committed_evidence and committed_bridge is None:
            raise ValueError("committed evidence required")
        if require_committed_evidence and allowed_uid == __import__("os").getuid():
            raise ValueError("strict witness requires a separate caller UID")
        if require_committed_evidence and (not callable(getattr(committed_bridge, "source_is_current", None))
            or committed_bridge.source_is_current() is not True):
            raise ValueError("committed ledger unavailable or replaced")
        if require_committed_evidence:
            checkpoint = store.inspect()
            if checkpoint is None:
                raise ValueError("witness checkpoint unavailable")
            from witnessed_receipt_history import classify_witnessed_history
            try:
                ledger_head, ledger_entries = committed_bridge.ledger.evidence()
                status = classify_witnessed_history(ledger_entries, ledger_head, checkpoint)
            except (OSError, ValueError, TypeError, IndexError):
                raise ValueError("committed ledger evidence unavailable") from None
            if (committed_bridge.source_is_current() is not True
                or store.inspect() != checkpoint or status != "MATCH"):
                raise ValueError("ledger and witness checkpoint disagree")
        self.require_committed_evidence = require_committed_evidence
        self.committed_bridge = committed_bridge
        self.allowed_uid = allowed_uid
        self.store = store
        self._slots = threading.BoundedSemaphore(self.MAX_ACTIVE)
        super().__init__(str(path), WitnessHandler)

def advance_via_socket(path, request, timeout=2):
    """Fail closed on any transport, schema or acknowledgement failure."""
    try:
        encoded = json.dumps(request, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(encoded) > MAX_REQUEST:
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(encoded)
            response = bytearray()
            while len(response) <= MAX_RESPONSE:
                chunk = sock.recv(1)
                if not chunk:
                    return False
                response.extend(chunk)
                if chunk == b"\n":
                    obj = json.loads(response, object_pairs_hook=_unique_pairs)
                    return (type(obj) is dict and set(obj) == {"accepted"}
                            and obj["accepted"] is True)
        return False
    except (OSError, ValueError, TypeError, OverflowError):
        return False
