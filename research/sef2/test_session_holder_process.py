"""Real separate-UID session holder key service test; disposable Linux root CI."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

CLIENT=r'''
import json,pathlib,sys
from session_capability import issue_session_capability,verify_holder_proof
from session_holder_service import request_holder_proof
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sock,public_path,private_path=sys.argv[1:4]
holder_public=pathlib.Path(public_path).read_text().strip()
authority=Ed25519PrivateKey.generate()
request={"operation_id":"holder-service-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder_public)
challenge="c"*64
proof=request_holder_proof(sock,cap,request,challenge)
assert verify_holder_proof(proof,cap,request,challenge)
try:
 pathlib.Path(private_path).read_bytes()
except PermissionError:
 pass
else:
 raise AssertionError("client read holder private key")
# Service refuses a capability pinned to a different holder key.
wrong=issue_session_capability(authority,"authority","broker-a",request,0,
 Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
try:
 request_holder_proof(sock,wrong,request,challenge)
except PermissionError:
 pass
else:
 raise AssertionError("holder service signed capability for another holder key")
print("HOLDER_SERVICE_PROOF_OK: proof valid; private key inaccessible to client")
'''

ATTACKER=r'''
import json,pathlib,sys
from session_holder_service import request_holder_proof
sock,public_path=sys.argv[1:3]
# Attacker is deliberately given socket group access in the harness; SO_PEERCRED
# must still reject the wrong UID before any signing request can succeed.
try:
 request_holder_proof(sock,{"payload":{},"signature":"00"*64},
  {"operation_id":"x","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":1},"x"*64)
except PermissionError:
 print("HOLDER_SERVICE_ATTACKER_UID_DENIED")
else:
 raise AssertionError("attacker UID obtained holder proof")
'''

def start(holder,client,sock,private_key,public_key,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"session_holder_service.py"),str(sock),
   str(private_key),str(public_key),str(client.pw_uid),str(client.pw_gid)],
  preexec_fn=drop(holder.pw_uid,holder.pw_gid,(client.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("holder service died: "+proc.stderr.read())
  if sock.exists() and public_key.exists():
   time.sleep(.03); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError("holder service startup timeout")

def stop(proc):
 proc.terminate()
 try: proc.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  proc.kill(); proc.communicate(timeout=5)

def main():
 if sys.platform!="linux" or os.geteuid()!=0:
  raise SystemExit("requires disposable Linux root CI")
 holder=pwd.getpwnam("aml_holder_test")
 client=pwd.getpwnam("aml_client_test")
 attacker=pwd.getpwnam("aml_session_attacker_test")
 assert len({holder.pw_uid,client.pw_uid,attacker.pw_uid})==3
 with tempfile.TemporaryDirectory(prefix="aml-holder-service-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  state=root/"holder-state"; state.mkdir(mode=0o700); os.chown(state,holder.pw_uid,holder.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,holder.pw_uid,holder.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o1777); shared.chmod(0o1777)
  private_key=state/"holder.pem"; public_key=shared/"holder.pub"; sock=ipc/"holder.sock"
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("session_holder_service","session_capability","signed_receipt","gated_action_broker",
      "strict_evaluator","pin_replication","pin_registry","replica_attestation"):
   source=HERE/(name+".py")
   if source.exists():
    target=lib/(name+".py"); shutil.copyfile(source,target); target.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  proc=start(holder,client,sock,private_key,public_key,lib,env)
  first_public=public_key.read_text().strip()
  try:
   legitimate=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(public_key),str(private_key)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert legitimate.returncode==0,(legitimate.stdout,legitimate.stderr)
   # Give attacker the socket group deliberately: UID check remains independent.
   attack=subprocess.run([sys.executable,"-c",ATTACKER,str(sock),str(public_key)],
    preexec_fn=drop(attacker.pw_uid,attacker.pw_gid,(client.pw_gid,)),env=env,
    capture_output=True,text=True,timeout=10)
   assert attack.returncode==0,(attack.stdout,attack.stderr)
   print(legitimate.stdout.strip()); print(attack.stdout.strip())
  finally:
   stop(proc)
  # Restart must retain the same private key / public identity.
  proc=start(holder,client,sock,private_key,public_key,lib,env)
  try:
   assert public_key.read_text().strip()==first_public
   restarted=subprocess.run([sys.executable,"-c",CLIENT,str(sock),str(public_key),str(private_key)],
    preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert restarted.returncode==0,(restarted.stdout,restarted.stderr)
   print("HOLDER_SERVICE_RESTART_IDENTITY_STABLE")
  finally:
   stop(proc)
if __name__=="__main__": main()
