"""Disposable Linux separate-UID integration test. Run as root in isolated CI.

Proves OS file denial plus permitted socket IPC, NOT security against root,
kernel compromise, compromised broker UID, or other effect APIs.
"""
import json
import os
import pathlib
import pwd
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE=pathlib.Path(__file__).resolve().parent

def drop(uid,gid):
    def apply():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    return apply

SERVER=r'''
import os,sys
from broker_socket import IsolatedBrokerServer,grant_client_socket_access
class SyntheticBroker:
    def __init__(self,path): self.path=path
    def execute(self,request,attestations,capability):
        return "APPLIED" if request=={"probe":"authorized"} and capability=="fixture" else "DENIED"
socket_path,db_path,client_uid,client_gid=sys.argv[1:]
with IsolatedBrokerServer(socket_path,SyntheticBroker(db_path),frozenset({int(client_uid)})) as server:
    grant_client_socket_access(socket_path,int(client_gid))
    server.serve_forever(poll_interval=0.05)
'''
CLIENT=r'''
import json,sqlite3,sys
from broker_socket import request_action
socket_path,db_path=sys.argv[1:]
status=request_action(socket_path,{"request":{"probe":"authorized"},"attestations":[],"capability":"fixture"})
assert status=="APPLIED",("authorized socket denied",status)
status=request_action(socket_path,{"request":{"probe":"unauthorized"},"attestations":[],"capability":None})
assert status=="DENIED",("unauthorized socket accepted",status)
try:
    sqlite3.connect("file:"+db_path+"?mode=rw",uri=True).execute("CREATE TABLE bypass (id INTEGER)")
except sqlite3.OperationalError:
    pass
else:
    raise AssertionError("client modified broker-owned SQLite database")
print("KERNEL_BOUNDARY_OK: authorized socket, denied unauthorized request, denied direct SQLite write")
'''

def main():
    if sys.platform!="linux" or os.geteuid()!=0:
        raise SystemExit("requires disposable Linux root CI environment")
    broker=pwd.getpwnam("aml_broker_test")
    client=pwd.getpwnam("aml_client_test")
    assert broker.pw_uid!=client.pw_uid and broker.pw_uid!=0 and client.pw_uid!=0
    with tempfile.TemporaryDirectory(prefix="aml-sef2-uid-") as tmp:
        root=pathlib.Path(tmp)
        root.chmod(0o755)
        private=root/"private"
        private.mkdir(mode=0o700)
        os.chown(private,broker.pw_uid,broker.pw_gid)
        db=private/"effects.sqlite"
        db.touch(mode=0o600)
        os.chown(db,broker.pw_uid,broker.pw_gid)
        db.chmod(0o600)
        ipc=root/"ipc"
        ipc.mkdir(mode=0o711)
        os.chown(ipc,broker.pw_uid,broker.pw_gid)
        ipc.chmod(0o711)
        sock=ipc/"broker.sock"
        env=dict(os.environ,PYTHONPATH=str(HERE))
        proc=subprocess.Popen([sys.executable,"-c",SERVER,str(sock),str(db),
                               str(client.pw_uid),str(client.pw_gid)],
                              preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(150):
                if sock.exists():
                    break
                if proc.poll() is not None:
                    raise AssertionError("broker died: "+proc.stderr.read())
                time.sleep(0.02)
            assert sock.exists(),"broker socket not created"
            outcome=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(db)],
                                   preexec_fn=drop(client.pw_uid,client.pw_gid),
                                   env=env,capture_output=True,text=True,timeout=10)
            assert outcome.returncode==0,(outcome.stdout,outcome.stderr)
            print(outcome.stdout.strip())
            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT name FROM sqlite_master WHERE name='bypass'").fetchone() is None
        finally:
            proc.terminate()
            try: proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)

if __name__=="__main__":
    main()
