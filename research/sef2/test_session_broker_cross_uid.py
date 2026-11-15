"""Real cross-UID session-bound capability test.

Both the legitimate client and attacker can reach the broker socket and read the
same public capability/configuration. Only the legitimate client owns the
holder private key. The attacker may obtain the broker challenge but must not
execute without holder proof.

Disposable Linux root CI only. Same-host UID separation is not a claim against
root/kernel compromise or direct theft of the holder private key.
"""
import grp,json,os,pathlib,pwd,shutil,sqlite3,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

HOLDER_CREATE=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
private_path,public_path=sys.argv[1:3]
key=Ed25519PrivateKey.generate()
pathlib.Path(private_path).write_bytes(key.private_bytes(
 serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(private_path).chmod(0o600)
pathlib.Path(public_path).write_text(json.dumps({"holder_public":key.public_key().public_bytes_raw().hex()}))
pathlib.Path(public_path).chmod(0o644)
print("SESSION_HOLDER_CREATED")
'''

AUTHORITY=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability
from replica_attestation import DOMAIN
from signed_receipt import canonical
holder_public_path,output_path=sys.argv[1:3]
holder=json.loads(pathlib.Path(holder_public_path).read_text())["holder_public"]
issuer=Ed25519PrivateKey.generate()
replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
request={"operation_id":"session-cross-uid-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
attestations=[]
for i,key in enumerate(replica_keys):
 payload={"schema":"AML-SEF2-PIN-REPLICA-ATTESTATION-V1",
  "replica_id":"r%d"%i,"witness_id":"north","generation":0,"pin":"a"*64}
 attestations.append({"payload":payload,"signature":key.sign(DOMAIN+canonical(payload)).hex()})
config={"issuer_public":issuer.public_key().public_bytes_raw().hex(),
 "enrolled":{"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(replica_keys)},
 "request":request,"attestations":attestations,
 "capability":issue_session_capability(issuer,"authority","broker-a",request,0,holder)}
pathlib.Path(output_path).write_text(json.dumps(config))
pathlib.Path(output_path).chmod(0o644)
print("SESSION_CAPABILITY_ISSUED_FOR_PINNED_HOLDER")
'''

SERVER=r'''
import json,os,pathlib,sys
from pin_registry import PinRegistry
from pin_replication import PinReplica
from session_capability_broker import SessionCapabilityBroker
from session_broker_socket import SessionBrokerServer,grant_socket_group
socket_path,private_dir,public_config,allowed_uids,shared_gid=sys.argv[1:6]
root=pathlib.Path(private_dir)
os.umask(0o077)
registry=PinRegistry(root/"registry.sqlite"); registry.enroll("north","a"*64)
replicas=[PinReplica(root/("replica%d.sqlite"%i)) for i in range(3)]
for replica in replicas: replica.record("north",0,"a"*64)
config=json.loads(pathlib.Path(public_config).read_text())
broker=SessionCapabilityBroker(root/"session-effects.sqlite",registry,"north",replicas,2,
 config["enrolled"],"authority",config["issuer_public"],"broker-a")
uids=frozenset(int(x) for x in allowed_uids.split(","))
with SessionBrokerServer(socket_path,broker,uids) as server:
 grant_socket_group(socket_path,int(shared_gid))
 server.serve_forever(poll_interval=0.05)
'''

ATTACKER=r'''
import json,pathlib,sys
from session_broker_socket import request_challenge,request_execute
sock,public_config,holder_private=sys.argv[1:4]
config=json.loads(pathlib.Path(public_config).read_text())
challenge=request_challenge(sock,config["request"]["operation_id"])
# Public configuration and the challenge are intentionally obtainable.
assert config["capability"]["payload"]["holder_public_key_hex"]
assert len(challenge)>=32
try:
 pathlib.Path(holder_private).read_bytes()
except PermissionError:
 pass
else:
 raise AssertionError("attacker read holder private key")
for forged in (None,{"payload":{},"signature":"00"*64}):
 status=request_execute(sock,config["request"],config["attestations"],
  config["capability"],forged,challenge)
 assert status=="DENIED",status
pathlib.Path(sys.argv[4]).write_text(json.dumps({"challenge":challenge}))
print("COPIED_CAPABILITY_WITHOUT_HOLDER_KEY_DENIED")
'''

CLIENT=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives import serialization
from session_capability import make_holder_proof
from session_broker_socket import request_challenge,request_execute
sock,public_config,holder_private,attack_record=sys.argv[1:5]
config=json.loads(pathlib.Path(public_config).read_text())
key=serialization.load_pem_private_key(pathlib.Path(holder_private).read_bytes(),password=None)
attacker_challenge=json.loads(pathlib.Path(attack_record).read_text())["challenge"]
challenge=request_challenge(sock,config["request"]["operation_id"])
assert challenge==attacker_challenge
proof=make_holder_proof(key,config["capability"],config["request"],challenge)
status=request_execute(sock,config["request"],config["attestations"],
 config["capability"],proof,challenge)
assert status=="APPLIED",status
# The exact copied proof/challenge cannot execute again after atomic consumption.
assert request_execute(sock,config["request"],config["attestations"],
 config["capability"],proof,challenge)=="DENIED"
print("SESSION_HOLDER_PROOF_APPLIED_ONCE")
'''

ATTACKER_AFTER=r'''
import json,pathlib,sys
from session_broker_socket import request_execute
sock,public_config,attack_record=sys.argv[1:4]
config=json.loads(pathlib.Path(public_config).read_text())
challenge=json.loads(pathlib.Path(attack_record).read_text())["challenge"]
assert request_execute(sock,config["request"],config["attestations"],
 config["capability"],None,challenge)=="DENIED"
print("CONSUMED_CHALLENGE_REMAINS_DENIED_TO_REPLACEMENT_AGENT")
'''

def main():
 if sys.platform!="linux" or os.geteuid()!=0:
  raise SystemExit("requires disposable Linux root CI")
 broker=pwd.getpwnam("aml_broker_test")
 client=pwd.getpwnam("aml_client_test")
 signer=pwd.getpwnam("aml_signer_test")
 attacker=pwd.getpwnam("aml_session_attacker_test")
 shared=grp.getgrnam("aml_session_clients")
 assert len({broker.pw_uid,client.pw_uid,signer.pw_uid,attacker.pw_uid})==4
 assert all(a.pw_uid!=0 for a in (broker,client,signer,attacker))
 with tempfile.TemporaryDirectory(prefix="aml-session-cross-uid-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  private=root/"broker-private"; private.mkdir(mode=0o700)
  os.chown(private,broker.pw_uid,broker.pw_gid)
  client_private=root/"client-private"; client_private.mkdir(mode=0o700)
  os.chown(client_private,client.pw_uid,client.pw_gid)
  holder_private=client_private/"holder.pem"
  shared_dir=root/"shared"; shared_dir.mkdir(mode=0o755)
  holder_public=shared_dir/"holder.json"; public_config=shared_dir/"config.json"
  attack_record=shared_dir/"attack-record.json"
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("session_broker_socket","broker_isolation_guard","pin_registry","pin_replication",
      "replica_attestation","signed_receipt","session_capability","session_capability_broker",
      "gated_action_broker","strict_evaluator"):
   dest=lib/(name+".py"); shutil.copyfile(HERE/(name+".py"),dest); dest.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  created=subprocess.run([sys.executable,"-c",HOLDER_CREATE,str(holder_private),str(holder_public)],
   preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
  assert created.returncode==0,(created.stdout,created.stderr)
  assert holder_private.exists() and holder_private.stat().st_uid==client.pw_uid
  assert holder_private.stat().st_mode & 0o077==0
  authority=subprocess.run([sys.executable,"-c",AUTHORITY,str(holder_public),str(public_config)],
   preexec_fn=drop(signer.pw_uid,signer.pw_gid),env=env,capture_output=True,text=True,timeout=10)
  assert authority.returncode==0,(authority.stdout,authority.stderr)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,broker.pw_uid,broker.pw_gid)
  sock=ipc/"session.sock"
  allowed=f"{client.pw_uid},{attacker.pw_uid}"
  proc=subprocess.Popen([sys.executable,"-c",SERVER,str(sock),str(private),str(public_config),
   allowed,str(shared.gr_gid)],preexec_fn=drop(broker.pw_uid,broker.pw_gid,(shared.gr_gid,)),
   env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(200):
    if sock.exists(): break
    if proc.poll() is not None: raise AssertionError("session broker died: "+proc.stderr.read())
    time.sleep(.02)
   assert sock.exists(),"session broker startup timeout"
   attack=subprocess.run([sys.executable,"-c",ATTACKER,str(sock),str(public_config),
    str(holder_private),str(attack_record)],
    preexec_fn=drop(attacker.pw_uid,attacker.pw_gid,(shared.gr_gid,)),env=env,
    capture_output=True,text=True,timeout=12)
   assert attack.returncode==0,(attack.stdout,attack.stderr)
   legit=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(public_config),
    str(holder_private),str(attack_record)],
    preexec_fn=drop(client.pw_uid,client.pw_gid,(shared.gr_gid,)),env=env,
    capture_output=True,text=True,timeout=12)
   assert legit.returncode==0,(legit.stdout,legit.stderr)
   after=subprocess.run([sys.executable,"-c",ATTACKER_AFTER,str(sock),str(public_config),str(attack_record)],
    preexec_fn=drop(attacker.pw_uid,attacker.pw_gid,(shared.gr_gid,)),env=env,
    capture_output=True,text=True,timeout=12)
   assert after.returncode==0,(after.stdout,after.stderr)
   print(attack.stdout.strip()); print(legit.stdout.strip()); print(after.stdout.strip())
   with sqlite3.connect(private/"session-effects.sqlite") as db:
    assert db.execute("SELECT COUNT(*) FROM session_effects").fetchone()[0]==1
  finally:
   proc.terminate()
   try: proc.communicate(timeout=5)
   except subprocess.TimeoutExpired:
    proc.kill(); proc.communicate(timeout=5)
if __name__=="__main__": main()
