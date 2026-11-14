"""Loopback-only research witness HTTP service; one process and store per witness.

Signed responses authenticate identity, not TLS or network operator independence.
"""
import argparse
import json
import pathlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from witness_freshness import WitnessEndpoint
from authenticated_publication import verify_checkpoint_publication

def make_handler(store,approver_public=None):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path not in ("/latest","/publish"):
                self.send_error(404)
                return
            try:
                length=int(self.headers.get("Content-Length","-1"))
                if length<0 or length>512:
                    self.send_error(413)
                    return
                raw=self.rfile.read(length)
                request=json.loads(raw)
                if type(request) is not dict or set(request)!={"challenge"}:
                    raise ValueError("invalid request")
                if self.path=="/publish":
                    if approver_public is None or not verify_checkpoint_publication(request,approver_public):
                        self.send_error(403)
                        return
                    status,receipt=store.publish(request["checkpoint"])
                    if status not in ("PUBLISHED","REPLAY"):
                        self.send_error(409)
                        return
                    result={"status":status,"receipt":receipt}
                else:
                    if set(request)!={"challenge"}:
                        raise ValueError("invalid challenge request")
                    result=WitnessEndpoint(store).latest(request["challenge"])
                body=json.dumps(result,sort_keys=True).encode()
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ValueError,TypeError,KeyError):
                self.send_error(400)
        def log_message(self,*args):
            pass
    return Handler

def serve(store,host="127.0.0.1",port=0,approver_public=None):
    if host not in ("127.0.0.1","::1"):
        raise ValueError("research server is loopback-only")
    return ThreadingHTTPServer((host,port),make_handler(store,approver_public))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    p.add_argument("--witness-id",required=True)
    p.add_argument("--private-key-file",required=True)
    p.add_argument("--port",type=int,required=True)
    p.add_argument("--approver-public-file")
    a=p.parse_args()
    key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(a.private_key_file).read().strip()))
    approver=None
    if a.approver_public_file:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        approver=Ed25519PublicKey.from_public_bytes(bytes.fromhex(pathlib.Path(a.approver_public_file).read_text().strip()))
    server=serve(DurableWitness(a.db,a.witness_id,key),port=a.port,approver_public=approver)
    print("WITNESS_READY",server.server_address[1],flush=True)
    server.serve_forever()
