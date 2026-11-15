"""Four-UID end-to-end session authority chain.

Broker intent -> external signer with pinned holder -> holder-bound capability ->
broker-authenticated challenge -> holder proof. Synthetic Linux CI only.
"""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

BROKER_BOOTSTRAP=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from broker_intent import create_intent
private_path,public_path,intent_path=sys.argv[1:4]
key=Ed25519PrivateKey.generate()
pathlib.Path(private_path).write_bytes(key.private_bytes(
 serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(private_path).chmod(0o600)
pathlib.Path(public_path).write_text(key.public_key().public_bytes_raw().hex())
pathlib.Path(public_path).chmod(0o644)
request={"operation_id":"full-session-authority-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
intent=create_intent(key,"broker-session-process","broker-a",request,"i"*48)
pathlib.Path(intent_path).write_text(json.dumps({"request":request,"intent":intent}))
pathlib.Path(intent_path).chmod(0o644)
'''

SIGNER=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from session_signer_policy import SessionSignerPolicy
holder_path,broker_public_path,intent_path,db_path,authority_private,output=sys.argv[1:7]
holder=pathlib.Path(holder_path).read_text().strip()
broker_public=pathlib.Path(broker_public_path).read_text().strip()
bundle=json.loads(pathlib.Path(intent_path).read_text())
authority=Ed25519PrivateKey.generate()
pathlib.Path(authority_private).write_bytes(authority.private_bytes(
 serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(authority_private).chmod(0o600)
policy=SessionSignerPolicy(db_path,authority,"authority","broker-a","broker-session-process",
 broker_public,holder,0)
capability=policy.authorize(bundle["request"],bundle["intent"])
pathlib.Path(output).write_text(json.dumps({"request":bundle["request"],"capability":capability,
 "authority_public_hex":authority.public_key().public_bytes_raw().hex()}))
pathlib.Path(output).chmod(0o644)
'''

BROKER_CHALLENGE=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives import serialization
from authenticated_execution_challenge import make_execution_challenge
private_path,config_path,output=sys.argv[1:4]
key=serialization.load_pem_private_key(pathlib.Path(private_path).read_bytes(),password=None)
config=json.loads(pathlib.Path(config_path).read_text())
env=make_execution_challenge(key,"broker-session-process","broker-a",
 config["request"],config["capability"],0,"c"*64)
pathlib.Path(output).write_text(json.dumps(env)); pathlib.Path(output).chmod(0o644)
'''

CLIENT=r'''
import json,pathlib,sys
from broker_authenticated_holder_service import request_authenticated_holder_proof
from session_capability import verify_holder_proof,verify_session_capability
sock,config_path,challenge_path=sys.argv[1:4]
config=json.loads(pathlib.Path(config_path).read_text())
challenge=json.loads(pathlib.Path(challenge_path).read_text())
assert verify_session_capability(config["capability"],config["authority_public_hex"],
 "authority","broker-a",config["request"],0)
proof=request_authenticated_holder_proof(sock,challenge,config["capability"],config["request"])
assert verify_holder_proof(proof,config["capability"],config["request"],"c"*64)
print("FULL_SESSION_AUTHORITY_CHAIN_OK")
'''

FORGER=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from broker_authenticated_holder_service import request_authenticated_holder_proof
sock,config_path=sys.argv[1:3]
config=json.loads(pathlib.Path(config_path).read_text())
fake=Ed25519PrivateKey.generate()
forged=make_execution_challenge(fake,"broker-session-process","broker-a",
 config["request"],config["capability"],0,"d"*64)
try:
 request_authenticated_holder_proof(sock,forged,config["capability"],config["request"])
except PermissionError:
 print("FULL_SESSION_FORGED_BROKER_DENIED")
else:
 raise AssertionError("forged broker elicited holder proof")
'''

def start_holder(holder,client,sock,state,public_key,broker_public,lib,env):
 private_key=state/"holder.pem"
 proc=subprocess.Popen([sys.executable,str(lib/"broker_authenticated_holder_service.py"),
  str(sock),str(private_key),str(public_key),str(client.pw_uid),str(client.pw_gid),
  broker_public,"broker-session-process","broker-a"],
  preexec_fn=drop(holder.pw_uid,holder.pw_gid,(client.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("holder service died: "+proc.stderr.read())
  if sock.exists() and public_key.exists(): time.sleep(.03); return proc,private_key
  time.sleep(.02)
 proc.terminate(); raise AssertionError("holder startup timeout")

def stop(proc):
 proc.terminate()
 try: proc.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  proc.kill(); proc.communicate(timeout=5)

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 broker=pwd.getpwnam("aml_broker_test"); holder=pwd.getpwnam("aml_holder_test")
 client=pwd.getpwnam("aml_client_test"); signer=pwd.getpwnam("aml_signer_test")
 assert len({broker.pw_uid,holder.pw_uid,client.pw_uid,signer.pw_uid})==4
 with tempfile.TemporaryDirectory(prefix="aml-full-session-authority-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  broker_state=root/"broker"; broker_state.mkdir(mode=0o700); os.chown(broker_state,broker.pw_uid,broker.pw_gid)
  holder_state=root/"holder"; holder_state.mkdir(mode=0o700); os.chown(holder_state,holder.pw_uid,holder.pw_gid)
  signer_state=root/"signer"; signer_state.mkdir(mode=0o700); os.chown(signer_state,signer.pw_uid,signer.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,holder.pw_uid,holder.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o1777); shared.chmod(0o1777)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  names=("broker_authenticated_holder_service","broker_authenticated_holder","session_holder_service",
   "session_capability","authenticated_execution_challenge","session_signer_policy","signer_policy",
   "broker_intent","action_capability","signed_receipt","gated_action_broker","strict_evaluator",
   "pin_replication","pin_registry","replica_attestation")
  for name in names:
   source=HERE/(name+".py")
   if source.exists():
    target=lib/(name+".py"); shutil.copyfile(source,target); target.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  broker_private=broker_state/"broker.pem"; broker_public=shared/"broker.pub"; intent=shared/"intent.json"
  boot=subprocess.run([sys.executable,"-c",BROKER_BOOTSTRAP,str(broker_private),str(broker_public),str(intent)],
   preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
  assert boot.returncode==0,(boot.stdout,boot.stderr)
  holder_public=shared/"holder.pub"; sock=ipc/"holder.sock"
  proc,holder_private=start_holder(holder,client,sock,holder_state,holder_public,broker_public.read_text().strip(),lib,env)
  try:
   signer_db=signer_state/"signer.sqlite"; authority_private=signer_state/"authority.pem"; config=shared/"config.json"
   issued=subprocess.run([sys.executable,"-c",SIGNER,str(holder_public),str(broker_public),str(intent),
    str(signer_db),str(authority_private),str(config)],preexec_fn=drop(signer.pw_uid,signer.pw_gid),
    env=env,capture_output=True,text=True,timeout=10)
   assert issued.returncode==0,(issued.stdout,issued.stderr)
   challenge=shared/"challenge.json"
   challenged=subprocess.run([sys.executable,"-c",BROKER_CHALLENGE,str(broker_private),str(config),str(challenge)],
    preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert challenged.returncode==0,(challenged.stdout,challenged.stderr)
   valid=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(config),str(challenge)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert valid.returncode==0,(valid.stdout,valid.stderr)
   forged=subprocess.run([sys.executable,"-c",FORGER,str(sock),str(config)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert forged.returncode==0,(forged.stdout,forged.stderr)
   reader=r'''import pathlib,sys
for p in sys.argv[1:]:
 try: pathlib.Path(p).read_bytes()
 except PermissionError: continue
 raise AssertionError("client read protected authority state: "+p)
print("FULL_SESSION_PRIVATE_STATE_DENIED")
'''
   denied=subprocess.run([sys.executable,"-c",reader,str(broker_private),str(holder_private),
    str(authority_private),str(signer_db)],preexec_fn=drop(client.pw_uid,client.pw_gid),
    env=env,capture_output=True,text=True,timeout=10)
   assert denied.returncode==0,(denied.stdout,denied.stderr)
   print(valid.stdout.strip()); print(forged.stdout.strip()); print(denied.stdout.strip())
  finally: stop(proc)
if __name__=="__main__": main()
