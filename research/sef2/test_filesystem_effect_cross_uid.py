"""Real cross-UID protected filesystem side-effect boundary.

The client owns the holder key and can call the broker socket, but cannot
traverse or mutate the broker-owned effect directory. A valid holder-bound
session authorization causes the broker UID to atomically create one durable
file. Disposable Linux root CI only; root/kernel compromise is out of scope.
"""
import grp,hashlib,json,os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

HOLDER=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
private_path,public_path=sys.argv[1:3]
key=Ed25519PrivateKey.generate()
pathlib.Path(private_path).write_bytes(key.private_bytes(
 serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(private_path).chmod(0o600)
pathlib.Path(public_path).write_text(json.dumps({"holder_public":key.public_key().public_bytes_raw().hex()}))
'''

AUTHORITY=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability
from replica_attestation import DOMAIN
from signed_receipt import canonical
holder_path,out=sys.argv[1:3]
holder=json.loads(pathlib.Path(holder_path).read_text())["holder_public"]
issuer=Ed25519PrivateKey.generate(); replicas=[Ed25519PrivateKey.generate() for _ in range(3)]
request={"operation_id":"real-fs-effect-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
att=[]
for i,key in enumerate(replicas):
 payload={"schema":"AML-SEF2-PIN-REPLICA-ATTESTATION-V1","replica_id":"r%d"%i,
  "witness_id":"north","generation":0,"pin":"a"*64}
 att.append({"payload":payload,"signature":key.sign(DOMAIN+canonical(payload)).hex()})
config={"issuer_public":issuer.public_key().public_bytes_raw().hex(),
 "enrolled":{"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(replicas)},
 "request":request,"attestations":att,
 "capability":issue_session_capability(issuer,"authority","broker-a",request,0,holder)}
pathlib.Path(out).write_text(json.dumps(config)); pathlib.Path(out).chmod(0o644)
'''

SERVER=r'''
import json,os,pathlib,sys
from pin_registry import PinRegistry
from pin_replication import PinReplica
from filesystem_effect_broker import DurableFilesystemEffectBroker
from session_broker_socket import SessionBrokerServer,grant_socket_group
sock,private_dir,config_path,client_uid,client_gid=sys.argv[1:6]
root=pathlib.Path(private_dir); os.umask(0o077)
registry=PinRegistry(root/"registry.sqlite"); registry.enroll("north","a"*64)
replicas=[PinReplica(root/("r%d.sqlite"%i)) for i in range(3)]
for replica in replicas: replica.record("north",0,"a"*64)
config=json.loads(pathlib.Path(config_path).read_text())
broker=DurableFilesystemEffectBroker(root/"broker.sqlite",root/"effects",registry,"north",
 replicas,2,config["enrolled"],"authority",config["issuer_public"],"broker-a")
with SessionBrokerServer(sock,broker,frozenset({int(client_uid)})) as server:
 grant_socket_group(sock,int(client_gid)); server.serve_forever(poll_interval=.05)
'''

CLIENT=r'''
import hashlib,json,pathlib,sys
from cryptography.hazmat.primitives import serialization
from session_capability import make_holder_proof
from session_broker_socket import request_challenge,request_execute
sock,config_path,holder_private,effect_dir=sys.argv[1:5]
config=json.loads(pathlib.Path(config_path).read_text())
operation=config["request"]["operation_id"]
name=hashlib.sha256(operation.encode()).hexdigest()+".effect.json"
target=pathlib.Path(effect_dir)/name
try:
 target.write_text("bypass")
except (PermissionError,OSError):
 pass
else:
 raise AssertionError("client directly created protected effect")
try:
 list(pathlib.Path(effect_dir).iterdir())
except (PermissionError,OSError):
 pass
else:
 raise AssertionError("client traversed protected effect directory")
key=serialization.load_pem_private_key(pathlib.Path(holder_private).read_bytes(),password=None)
challenge=request_challenge(sock,operation)
proof=make_holder_proof(key,config["capability"],config["request"],challenge)
assert request_execute(sock,config["request"],config["attestations"],
 config["capability"],proof,challenge)=="APPLIED"
try:
 target.write_text("tamper")
except (PermissionError,OSError):
 pass
else:
 raise AssertionError("client modified broker-created protected effect")
print("REAL_FILESYSTEM_EFFECT_BOUNDARY_OK")
'''

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 broker=pwd.getpwnam("aml_broker_test"); client=pwd.getpwnam("aml_client_test"); signer=pwd.getpwnam("aml_signer_test")
 shared=grp.getgrnam("aml_session_clients")
 assert len({broker.pw_uid,client.pw_uid,signer.pw_uid})==3
 with tempfile.TemporaryDirectory(prefix="aml-real-fs-effect-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  private=root/"broker-private"; private.mkdir(mode=0o700); os.chown(private,broker.pw_uid,broker.pw_gid)
  client_dir=root/"client-private"; client_dir.mkdir(mode=0o700); os.chown(client_dir,client.pw_uid,client.pw_gid)
  holder_private=client_dir/"holder.pem"; shared_dir=root/"shared"; shared_dir.mkdir(mode=0o770); os.chown(shared_dir,0,shared.gr_gid); shared_dir.chmod(0o770)
  holder_public=shared_dir/"holder.json"; config=shared_dir/"config.json"
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("filesystem_effect_broker","session_capability_broker","session_broker_socket",
    "broker_isolation_guard","pin_registry","pin_replication","replica_attestation",
    "signed_receipt","session_capability","gated_action_broker","strict_evaluator"):
   dest=lib/(name+".py"); shutil.copyfile(HERE/(name+".py"),dest); dest.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  result=subprocess.run([sys.executable,"-c",HOLDER,str(holder_private),str(holder_public)],
   preexec_fn=drop(client.pw_uid,client.pw_gid,(shared.gr_gid,)),env=env,capture_output=True,text=True,timeout=10)
  assert result.returncode==0,(result.stdout,result.stderr)
  result=subprocess.run([sys.executable,"-c",AUTHORITY,str(holder_public),str(config)],
   preexec_fn=drop(signer.pw_uid,signer.pw_gid,(shared.gr_gid,)),env=env,capture_output=True,text=True,timeout=10)
  assert result.returncode==0,(result.stdout,result.stderr)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,broker.pw_uid,broker.pw_gid)
  sock=ipc/"effect.sock"
  proc=subprocess.Popen([sys.executable,"-c",SERVER,str(sock),str(private),str(config),
    str(client.pw_uid),str(shared.gr_gid)],
    preexec_fn=drop(broker.pw_uid,broker.pw_gid,(shared.gr_gid,)),env=env,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(200):
    if sock.exists() and (private/"effects").exists(): break
    if proc.poll() is not None: raise AssertionError("effect broker died: "+proc.stderr.read())
    time.sleep(.02)
   assert sock.exists() and (private/"effects").exists()
   result=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(config),str(holder_private),
     str(private/"effects")],preexec_fn=drop(client.pw_uid,client.pw_gid,(shared.gr_gid,)),
     env=env,capture_output=True,text=True,timeout=12)
   assert result.returncode==0,(result.stdout,result.stderr)
   print(result.stdout.strip())
   operation=json.loads(config.read_text())["request"]["operation_id"]
   target=private/"effects"/(hashlib.sha256(operation.encode()).hexdigest()+".effect.json")
   assert target.is_file() and target.stat().st_uid==broker.pw_uid
   assert target.stat().st_mode & 0o077==0
   assert len(list((private/"effects").glob("*.effect.json")))==1
  finally:
   proc.terminate()
   try: proc.communicate(timeout=5)
   except subprocess.TimeoutExpired: proc.kill(); proc.communicate(timeout=5)

if __name__=="__main__": main()
