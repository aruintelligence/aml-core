"""Linux peer-authenticated reservation service for the SEF2 research fixture.

The service owner must be independent of the effect-authority UID. The
reservation store must not be readable or writable by the calling UID.
"""
import json
import threading
import socket
import socketserver
import struct

MAX_REQUEST = 512
MAX_RESPONSE = 128

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result

class ReservationHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(3)
            peer = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", peer)
            if uid != self.server.allowed_uid:
                return
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST or not line.endswith(bytes([10])):
                return
            req = json.loads(line, object_pairs_hook=_unique_pairs)
            if type(req) is not dict or set(req) != {"operation_id", "digest", "generation"}:
                return
            accepted = self.server.store.reserve(req["operation_id"], req["digest"],
                                                 req["generation"]) is True
            self.wfile.write(json.dumps({"reserved": accepted}).encode() + bytes([10]))
        except (OSError, ValueError, TypeError, OverflowError):
            return

class ReservationServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
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

    def __init__(self, path, *, allowed_uid, store):
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("Linux SO_PEERCRED required")
        if type(allowed_uid) is not int or allowed_uid < 0:
            raise ValueError("invalid allowed UID")
        if not callable(getattr(store, "reserve", None)):
            raise TypeError("reservation store required")
        self.allowed_uid = allowed_uid
        self.store = store
        self._slots = threading.BoundedSemaphore(self.MAX_ACTIVE)
        super().__init__(str(path), ReservationHandler)

def reserve_via_socket(path, operation_id, digest, generation, timeout=2):
    """Fail closed on network, peer, parse, timeout, or protocol errors."""
    try:
        request = json.dumps({"operation_id": operation_id, "digest": digest,
                              "generation": generation}, separators=(",", ":"),
                             allow_nan=False).encode() + bytes([10])
        if len(request) > MAX_REQUEST:
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(request)
            response = bytearray()
            while len(response) <= MAX_RESPONSE:
                chunk = sock.recv(1)
                if not chunk:
                    return False
                response.extend(chunk)
                if chunk == bytes([10]):
                    obj = json.loads(response, object_pairs_hook=_unique_pairs)
                    return (type(obj) is dict and set(obj) == {"reserved"}
                            and obj["reserved"] is True)
        return False
    except (OSError, ValueError, TypeError, OverflowError):
        return False
