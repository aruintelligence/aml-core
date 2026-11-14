"""Full cryptographic broker across two real Linux UIDs in disposable CI.

Synthetic-only. Authority private keys are generated in a separate short-lived
process; broker receives only public keys and signed evidence. The signer and broker run under distinct non-root Linux UIDs in disposable CI.
This is OS-separated test custody, not independently operated remote authority.
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
BROKER_ENROLL=r'''
import json,pathlib,secrets,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from broker_intent import create_intent
private_path,handoff=sys.argv[1:3]
key=Ed25519PrivateKey.generate()
pathlib.Path(private_path).write_bytes(key.private_bytes(
    serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(private_path).chmod(0o600)
request={"operation_id":"full-uid-op","action":"payment:simulate",
         "target":"fixture:merchant-a","amount_cents":100}
enrollment={"broker_public":key.public_key().public_bytes_raw().hex(),
            "request":request,
            "intent":create_intent(key,"broker-1","broker-a",request,secrets.token_hex(24))}
pathlib.Path(handoff).write_text(json.dumps(enrollment))
pathlib.Path(handoff).chmod(0o644)
print("BROKER_SIGNED_INTENT_CREATED")
'''

AUTHORITY=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signer_policy import SignerPolicy
from replica_attestation import DOMAIN
from signed_receipt import canonical
path,signer_db,handoff,broker_private,enrolled_path=sys.argv[1:6]
try:
    pathlib.Path(broker_private).read_bytes()
except PermissionError:
    pass
else:
    raise AssertionError("signer can read broker private key")
enrollment=json.loads(pathlib.Path(handoff).read_text())
trusted=json.loads(pathlib.Path(enrolled_path).read_text())
issuer=Ed25519PrivateKey.generate()
keys=[Ed25519PrivateKey.generate() for _ in range(3)]
request=enrollment["request"]
attestations=[]
for i,key in enumerate(keys):
    payload={"schema":"AML-SEF2-PIN-REPLICA-ATTESTATION-V1",
             "replica_id":"r%d"%i,"witness_id":"north","generation":0,"pin":"a"*64}
    attestations.append({"payload":payload,"signature":key.sign(DOMAIN+canonical(payload)).hex()})
policy=SignerPolicy(signer_db,issuer,"authority","broker-a","broker-1",trusted["broker_public"],0)
config={"issuer_public":issuer.public_key().public_bytes_raw().hex(),
        "enrolled":{"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(keys)},
        "request":request,"attestations":attestations,
        "capability":policy.authorize(request,enrollment["intent"])}
with open(path,"w") as output:json.dump(config,output)
print("SIGNER_VERIFIED_BROKER_INTENT_WITHOUT_PRIVATE_KEY_ACCESS")
'''
CLIENT=r'''
import json,sqlite3,sys
from broker_socket import request_action
sock,db,public,broker_private=sys.argv[1:]
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
    with open(broker_private,"rb") as f:f.read(1)
except PermissionError:pass
else:raise AssertionError("client read broker identity private key")
try:
    with sqlite3.connect("file:"+db+"?mode=rw",uri=True) as dbconn:
        dbconn.execute("INSERT INTO effects VALUES ('bypass','0')")
except sqlite3.OperationalError:pass
else:raise AssertionError("cross-UID direct database write succeeded")
print("FULL_BROKER_UID_OK: signer UID != broker UID != client UID; signed effect once, replay idempotent, forgery denied, direct storage denied")
'''

def main():
    if sys.platform!="linux" or os.geteuid()!=0:
        raise SystemExit("requires isolated Linux root CI runner")
    broker=pwd.getpwnam("aml_broker_test")
    client=pwd.getpwnam("aml_client_test")
    signer=pwd.getpwnam("aml_signer_test")
    # The authority signer, broker and untrusted client must be three distinct non-root OS identities.
    assert len({broker.pw_uid,client.pw_uid,signer.pw_uid})==3
    assert all(account.pw_uid!=0 for account in (broker,client,signer))
    with tempfile.TemporaryDirectory(prefix="aml-full-broker-") as tmp:
        root=pathlib.Path(tmp)
        root.chmod(0o755)
        private=root/"private"
        private.mkdir(mode=0o700)
        os.chown(private,broker.pw_uid,broker.pw_gid)
        authority_dir=root/"authority"
        authority_dir.mkdir(mode=0o755)
        os.chown(authority_dir,signer.pw_uid,broker.pw_gid)
        authority_dir.chmod(0o750)
        ipc=root/"ipc"
        ipc.mkdir(mode=0o711)
        os.chown(ipc,broker.pw_uid,broker.pw_gid)
        ipc.chmod(0o711)
        lib=root/"lib"
        lib.mkdir(mode=0o755)
        for name in ("broker_socket","broker_isolation_guard","pin_registry",
                     "pin_replication","replica_attestation","signed_receipt",
                     "action_capability","capability_broker","gated_action_broker",
                     "strict_evaluator","signer_policy","broker_intent"):
            dest=lib/(name+".py")
            shutil.copyfile(HERE/(name+".py"),dest)
            dest.chmod(0o644)
        sock=ipc/"broker.sock"
        public=authority_dir/"signed_request.json"
        signer_db=authority_dir/"signer.sqlite"
        client_public=ipc/"signed_request.json"
        broker_private=private/"broker_identity.pem"
        handoff_dir=root/"handoff"
        handoff_dir.mkdir(mode=0o1777)
        handoff_dir.chmod(0o1777)
        handoff=handoff_dir/"broker_intent.json"
        enrolled_path=root/"enrolled_broker.json"
        env=dict(os.environ,PYTHONPATH=str(lib))
        enrollment=subprocess.run([sys.executable,"-c",BROKER_ENROLL,str(broker_private),str(handoff)],
            preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
        assert enrollment.returncode==0,(enrollment.stdout,enrollment.stderr)
        assert "BROKER_SIGNED_INTENT_CREATED" in enrollment.stdout
        assert broker_private.exists() and broker_private.stat().st_uid==broker.pw_uid
        assert broker_private.stat().st_mode & 0o077 == 0
        broker_intent=json.loads(handoff.read_text())
        enrolled_path.write_text(__import__("json").dumps({"broker_public":broker_intent["broker_public"]}))
        enrolled_path.chmod(0o644)
        assert enrolled_path.stat().st_uid==0 and enrolled_path.stat().st_mode & 0o022 == 0
        authority=subprocess.run([sys.executable,"-c",AUTHORITY,str(public),str(signer_db),str(handoff),str(broker_private),str(enrolled_path)],
            preexec_fn=drop(signer.pw_uid,signer.pw_gid,(broker.pw_gid,)),
            env=env,capture_output=True,text=True,timeout=10)
        assert authority.returncode==0,(authority.stdout,authority.stderr)
        assert "SIGNER_VERIFIED_BROKER_INTENT_WITHOUT_PRIVATE_KEY_ACCESS" in authority.stdout
        assert signer_db.exists() and signer_db.stat().st_uid==signer.pw_uid
        os.chown(public,-1,broker.pw_gid)
        public.chmod(0o640)
        signer_db.chmod(0o600)
        assert public.stat().st_uid==signer.pw_uid and public.stat().st_gid==broker.pw_gid
        assert public.stat().st_mode & 0o007 == 0
        shutil.copyfile(public,client_public)
        client_public.chmod(0o644)
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
                 str(private/"effects.sqlite"),str(client_public),str(broker_private)],
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
