"""Separate-UID authenticated broker -> holder proof integration."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

BROKER_KEY=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
private_path,public_path=sys.argv[1:3]
key=Ed25519PrivateKey.generate()
pathlib.Path(private_path).write_bytes(key.private_bytes(
 serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
pathlib.Path(private_path).chmod(0o600)
pathlib.Path(public_path).write_text(key.public_key().public_bytes_raw().hex())
pathlib.Path(public_path).chmod(0o644)
print("BROKER_CHALLENGE_KEY_CREATED")
'''

AUTHORITY=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability
holder_public_path,output=sys.argv[1:3]
holder=pathlib.Path(holder_public_path).read_text().strip()
authority=Ed25519PrivateKey.generate()
request={"operation_id":"broker-auth-holder-process-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,2,holder)
pathlib.Path(output).write_text(json.dumps({"request":request,"capability":cap}))
pathlib.Path(output).chmod(0o644)
'''

BROKER_CHALLENGE=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives import serialization
from authenticated_execution_challenge import make_execution_challenge
private_path,config_path,output=sys.argv[1:4]
key=serialization.load_pem_private_key(pathlib.Path(private_path).read_bytes(),password=None)
config=json.loads(pathlib.Path(config_path).read_text())
env=make_execution_challenge(key,"broker-instance-process","broker-a",
 config["request"],config["capability"],2,"c"*64)
pathlib.Path(output).write_text(json.dumps(env)); pathlib.Path(output).chmod(0o644)
'''

CLIENT=r'''
import json,pathlib,sys
from broker_authenticated_holder_service import request_authenticated_holder_proof
from session_capability import verify_holder_proof
sock,config_path,challenge_path=sys.argv[1:4]
config=json.loads(pathlib.Path(config_path).read_text())
challenge=json.loads(pathlib.Path(challenge_path).read_text())
proof=request_authenticated_holder_proof(sock,challenge,config["capability"],config["request"])
assert verify_holder_proof(proof,config["capability"],config["request"],"c"*64)
print("AUTHENTICATED_HOLDER_SERVICE_PROOF_OK")
'''

FORGER=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from broker_authenticated_holder_service import request_authenticated_holder_proof
sock,config_path=sys.argv[1:3]
config=json.loads(pathlib.Path(config_path).read_text())
fake=Ed25519PrivateKey.generate()
forged=make_execution_challenge(fake,"broker-instance-process","broker-a",
 config["request"],config["capability"],2,"d"*64)
try:
 request_authenticated_holder_proof(sock,forged,config["capability"],config["request"])
except PermissionError:
 print("FORGED_BROKER_CHALLENGE_DENIED_BY_HOLDER_SERVICE")
else:
 raise AssertionError("holder service signed forged broker challenge")
'''

def start_holder(holder,client,sock,state,public_key,broker_public,lib,env):
 private_key=state/"holder.pem"
 proc=subprocess.Popen([sys.executable,str(lib/"broker_authenticated_holder_service.py"),
  str(sock),str(private_key),str(public_key),str(client.pw_uid),str(client.pw_gid),
  broker_public,"broker-instance-process","broker-a"],
  preexec_fn=drop(holder.pw_uid,holder.pw_gid,(client.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("holder service died: "+proc.stderr.read())
  if sock.exists() and public_key.exists():
   time.sleep(.03); return proc,private_key
  time.sleep(.02)
 proc.terminate(); raise AssertionError("holder service startup timeout")

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
 with tempfile.TemporaryDirectory(prefix="aml-auth-holder-process-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  broker_state=root/"broker-state"; broker_state.mkdir(mode=0o700); os.chown(broker_state,broker.pw_uid,broker.pw_gid)
  holder_state=root/"holder-state"; holder_state.mkdir(mode=0o700); os.chown(holder_state,holder.pw_uid,holder.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,holder.pw_uid,holder.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o1777); shared.chmod(0o1777)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("broker_authenticated_holder_service","broker_authenticated_holder","session_holder_service",
      "session_capability","authenticated_execution_challenge","signed_receipt","gated_action_broker",
      "strict_evaluator","pin_replication","pin_registry","replica_attestation"):
   source=HERE/(name+".py")
   if source.exists():
    target=lib/(name+".py"); shutil.copyfile(source,target); target.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  broker_private=broker_state/"challenge.pem"; broker_public_path=shared/"broker.pub"
  created=subprocess.run([sys.executable,"-c",BROKER_KEY,str(broker_private),str(broker_public_path)],
   preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
  assert created.returncode==0,(created.stdout,created.stderr)
  broker_public=broker_public_path.read_text().strip()
  holder_public=shared/"holder.pub"; sock=ipc/"holder.sock"
  proc,holder_private=start_holder(holder,client,sock,holder_state,holder_public,broker_public,lib,env)
  try:
   config=shared/"config.json"
   authority=subprocess.run([sys.executable,"-c",AUTHORITY,str(holder_public),str(config)],
    preexec_fn=drop(signer.pw_uid,signer.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert authority.returncode==0,(authority.stdout,authority.stderr)
   challenge=shared/"challenge.json"
   signed=subprocess.run([sys.executable,"-c",BROKER_CHALLENGE,str(broker_private),str(config),str(challenge)],
    preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert signed.returncode==0,(signed.stdout,signed.stderr)
   legitimate=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(config),str(challenge)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert legitimate.returncode==0,(legitimate.stdout,legitimate.stderr)
   forged=subprocess.run([sys.executable,"-c",FORGER,str(sock),str(config)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert forged.returncode==0,(forged.stdout,forged.stderr)
   # Client still cannot read either private signing key.
   reader=r'''import pathlib,sys
for p in sys.argv[1:]:
 try: pathlib.Path(p).read_bytes()
 except PermissionError: continue
 raise AssertionError("client read protected signing key: "+p)
print("BROKER_AND_HOLDER_PRIVATE_KEYS_INACCESSIBLE")
'''
   denied=subprocess.run([sys.executable,"-c",reader,str(broker_private),str(holder_private)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert denied.returncode==0,(denied.stdout,denied.stderr)
   print(legitimate.stdout.strip()); print(forged.stdout.strip()); print(denied.stdout.strip())
  finally:
   stop(proc)
if __name__=="__main__": main()
