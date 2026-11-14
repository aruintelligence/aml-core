"""Unix-domain process boundary for the synthetic capability broker.

Only the broker process opens the effect DB. A production deployment must
run this process under a separate OS identity with a protected directory,
socket ACL, pinned configuration, and isolated signing services. A same-UID
attacker or direct access to the DB remains able to bypass this prototype.
"""
import json
import os
import socket
import socketserver
import struct

MAX_REQUEST=65536

def reject_duplicate_keys(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key]=value
    return result

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            # Linux kernel-provided peer credentials, not caller JSON.
            if not hasattr(socket,"SO_PEERCRED"):
                return
            raw=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            _,uid,_=struct.unpack("3i",raw)
            if uid not in self.server.allowed_uids:
                self.wfile.write(b'{"status":"DENIED"}\n')
                return
        except (OSError,ValueError,struct.error):
            return
        line=self.rfile.readline(MAX_REQUEST+1)
        if len(line)>MAX_REQUEST or not line.endswith(b"\n"):
            self.wfile.write(b'{"status":"DENIED"}\n')
            return
        try:
            envelope=json.loads(line,object_pairs_hook=reject_duplicate_keys)
            if type(envelope) is not dict or set(envelope)!={"request","attestations","capability"}:
                raise ValueError("invalid envelope")
            status=self.server.broker.execute(envelope["request"],envelope["attestations"],envelope["capability"])
            if status not in {"APPLIED","ALREADY_APPLIED","DENIED"}:
                status="DENIED"
        except (ValueError,TypeError,KeyError,UnicodeError):
            status="DENIED"
        self.wfile.write(json.dumps({"status":status},separators=(",",":")).encode()+b"\n")

class BrokerServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    def __init__(self,socket_path,broker,allowed_uids):
        if (type(allowed_uids) is not frozenset or not allowed_uids
            or any(type(uid) is not int or uid<0 for uid in allowed_uids)):
            raise ValueError("explicit allowed client UIDs required")
        self.allowed_uids=allowed_uids
        self.broker=broker
        super().__init__(str(socket_path),_Handler)
        os.chmod(socket_path,0o600)

def request_action(socket_path,envelope,timeout=3):
    payload=json.dumps(envelope,separators=(",",":"),ensure_ascii=False).encode()+b"\n"
    if len(payload)>MAX_REQUEST:
        return "DENIED"
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(socket_path))
            connection.sendall(payload)
            data=b""
            while not data.endswith(b"\n") and len(data)<=MAX_REQUEST:
                chunk=connection.recv(4096)
                if not chunk:
                    break
                data+=chunk
        response=json.loads(data)
        return response["status"] if (type(response) is dict and set(response)=={"status"}
            and response["status"] in {"APPLIED","ALREADY_APPLIED","DENIED"}) else "DENIED"
    except (OSError,ValueError,TypeError,KeyError):
        return "DENIED"

class IsolatedBrokerServer(BrokerServer):
    """Strict launch profile; refuse unsafe broker/client UID or DB ownership."""
    def __init__(self,socket_path,broker,allowed_uids):
        from broker_isolation_guard import validate_isolation
        if not validate_isolation(broker.path,os.geteuid(),allowed_uids):
            raise ValueError("unsafe broker isolation configuration")
        super().__init__(socket_path,broker,allowed_uids)
