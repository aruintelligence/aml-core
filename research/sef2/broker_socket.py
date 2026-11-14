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

MAX_REQUEST=65536

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line=self.rfile.readline(MAX_REQUEST+1)
        if len(line)>MAX_REQUEST or not line.endswith(b"\n"):
            self.wfile.write(b'{"status":"DENIED"}\n')
            return
        try:
            envelope=json.loads(line)
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
    def __init__(self,socket_path,broker):
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
