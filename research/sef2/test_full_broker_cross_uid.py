"""Full cryptographic broker across two real Linux UIDs in disposable CI.

Synthetic-only. Authority private keys are generated in a separate short-lived
process; broker receives only public keys and signed evidence. This is process
separation, not yet a separate-UID or independently operated signer service.
"""
import os,pathlib,pwd,shutil,sqlite3,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

SERVER=r'''
import json,os,pathlib,sys
from pin_registry import PinRegistry
from pin_replication import PinReplica
from capability_broker import CapabilityBroker
from broker_socket import IsolatedBrokerServer,grant_client_socket_access
socket_path,private,public,client_uid,client_gid=sys.argv[1:]
root=pathlib.Path(private)
os.umask(0o077)
registry=PinRegistry(root/"registry.sqlite")
registry.enroll("north","a"*64)
replicas=[PinReplica(root/("replica%d.sqlite"%i)) for i in range(3)]
for r in replicas:r.record("north",0,"a"*64)
config=json.loads(pathlib.Path(public).read_text())
broker=CapabilityBroker(root/"effects.sqlite",registry,"north",replicas,2,
    config["enrolled"],"authority",config["issuer_public"],"broker-a")
with IsolatedBrokerServer(socket_path,broker,frozenset({int(client_uid)})) as server:
    grant_client_socket_access(socket_path,int(client_gid))
    server.serve_forever(poll_interval=0.05)
'''
AUTHORITY=r'''
import json,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from action_capability import issue_capability
from replica_attestation import DOMAIN
from signed_receipt import canonical
path=sys.argv[1]
issuer=Ed25519PrivateKey.generate()
keys=[Ed25519PrivateKey.generate() for _ in range(3)]
request={"operation_id":"full-uid-op","action":"payment:simulate",
         "target":"fixture:merchant-a","amount_cents":100}
attestations=[]
for i,key in enumerate(keys):
    payload={"schema":"AML-SEF2-PIN-REPLICA-ATTESTATION-V1",
             "replica_id":"r%d"%i,"witness_id":"north","generation":0,"pin":"a"*64}
    attestations.append({"payload":payload,"signature":key.sign(DOMAIN+canonical(payload)).hex()})
config={"issuer_public":issuer.public_key().public_bytes_raw().hex(),
        "enrolled":{"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(keys)},
        "request":request,"attestations":attestations,
        "capability":issue_capability(issuer,"authority","broker-a",request,0)}
with open(path,"w") as output:json.dump(config,output)
print("AUTHORITY_KEYS_HELD_OUTSIDE_BROKER")
'''
CLIENT=r'''
import json,sqlite3,sys
from broker_socket import request_action
sock,db,public=sys.argv[1:]
config=json.loads(open(public).read())
envelope={key:config[key] for key in ("request","attestations","capability")}
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
        authority=subprocess.run([sys.executable,"-c",AUTHORITY,str(public)],
            env=env,capture_output=True,text=True,timeout=10)
        assert authority.returncode==0,(authority.stdout,authority.stderr)
        assert "AUTHORITY_KEYS_HELD_OUTSIDE_BROKER" in authority.stdout
        public.chmod(0o644)
        assert all("private" not in key for key in __import__("json").loads(public.read_text()))
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
