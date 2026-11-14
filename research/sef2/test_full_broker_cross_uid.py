"""Full cryptographic broker across two real Linux UIDs in disposable CI.

Synthetic-only. Authority keys are generated in the broker process and never
exported; signed request fixture is public, private effects stay broker-owned.
"""
import os,pathlib,pwd,shutil,sqlite3,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

SERVER=r'''
import json,os,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from action_capability import issue_capability
from capability_broker import CapabilityBroker
from broker_socket import IsolatedBrokerServer,grant_client_socket_access
socket_path,private,public,client_uid,client_gid=sys.argv[1:]
root=pathlib.Path(private)
os.umask(0o077)
registry=PinRegistry(root/"registry.sqlite")
registry.enroll("north","a"*64)
replicas=[PinReplica(root/("replica%d.sqlite"%i)) for i in range(3)]
keys=[Ed25519PrivateKey.generate() for _ in replicas]
for r in replicas:r.record("north",0,"a"*64)
enrolled={"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(keys)}
issuer=Ed25519PrivateKey.generate()
broker=CapabilityBroker(root/"effects.sqlite",registry,"north",replicas,2,enrolled,
    "authority",issuer.public_key().public_bytes_raw().hex(),"broker-a")
request={"operation_id":"full-uid-op","action":"payment:simulate",
         "target":"fixture:merchant-a","amount_cents":100}
attestations=[attest(r,"r%d"%i,"north",keys[i]) for i,r in enumerate(replicas)]
capability=issue_capability(issuer,"authority","broker-a",request,0)
envelope={"request":request,"attestations":attestations,"capability":capability}
with IsolatedBrokerServer(socket_path,broker,frozenset({int(client_uid)})) as server:
    grant_client_socket_access(socket_path,int(client_gid))
    pathlib.Path(public).write_text(json.dumps(envelope))
    pathlib.Path(public).chmod(0o644)
    server.serve_forever(poll_interval=0.05)
'''
CLIENT=r'''
import json,sqlite3,sys
from broker_socket import request_action
sock,db,public=sys.argv[1:]
envelope=json.loads(open(public).read())
assert request_action(sock,envelope)=="APPLIED"
assert request_action(sock,envelope)=="ALREADY_APPLIED"
forged=json.loads(json.dumps(envelope))
forged["capability"]["signature"]="00"*64
forged["request"]["operation_id"]="forged-op"
assert request_action(sock,forged)=="DENIED"
try:
    with open(db,"rb") as f:f.read(1)
except PermissionError:pass
else:raise AssertionError("cross-UID direct database read succeeded")
try:
    with sqlite3.connect("file:"+db+"?mode=rw",uri=True) as dbconn:
        dbconn.execute("INSERT INTO effects VALUES ('bypass','0')")
except sqlite3.OperationalError:pass
else:raise AssertionError("cross-UID direct database write succeeded")
print("FULL_BROKER_UID_OK: signed effect once, replay idempotent, forgery denied, direct storage denied")
'''

def main():
    if sys.platform!="linux" or os.geteuid()!=0:
        raise SystemExit("requires isolated Linux root CI runner")
    broker=pwd.getpwnam("aml_broker_test")
    client=pwd.getpwnam("aml_client_test")
    assert broker.pw_uid!=client.pw_uid and broker.pw_uid!=0 and client.pw_uid!=0
    with tempfile.TemporaryDirectory(prefix="aml-full-broker-") as tmp:
        root=pathlib.Path(tmp)
        root.chmod(0o755)
        private=root/"private"
        private.mkdir(mode=0o700)
        os.chown(private,broker.pw_uid,broker.pw_gid)
        ipc=root/"ipc"
        ipc.mkdir(mode=0o711)
        os.chown(ipc,broker.pw_uid,broker.pw_gid)
        ipc.chmod(0o711)
        lib=root/"lib"
        lib.mkdir(mode=0o755)
        for name in ("broker_socket","broker_isolation_guard","pin_registry",
                     "pin_replication","replica_attestation","signed_receipt",
                     "action_capability","capability_broker","gated_action_broker",
                     "strict_evaluator"):
            dest=lib/(name+".py")
            shutil.copyfile(HERE/(name+".py"),dest)
            dest.chmod(0o644)
        sock=ipc/"broker.sock"
        public=ipc/"signed_request.json"
        env=dict(os.environ,PYTHONPATH=str(lib))
        proc=subprocess.Popen([sys.executable,"-c",SERVER,str(sock),str(private),
             str(public),str(client.pw_uid),str(client.pw_gid)],
             preexec_fn=drop(broker.pw_uid,broker.pw_gid,(client.pw_gid,)),
             env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(200):
                if sock.exists() and public.exists():break
                if proc.poll() is not None:raise AssertionError("broker died: "+proc.stderr.read())
                time.sleep(0.02)
            assert sock.exists() and public.exists(),"full broker startup timed out"
            result=subprocess.run([sys.executable,"-c",CLIENT,str(sock),
                 str(private/"effects.sqlite"),str(public)],
                 preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,
                 capture_output=True,text=True,timeout=12)
            assert result.returncode==0,(result.stdout,result.stderr)
            print(result.stdout.strip())
            with sqlite3.connect(private/"effects.sqlite") as db:
                assert db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]==1
        finally:
            proc.terminate()
            try:proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)

if __name__=="__main__":main()
