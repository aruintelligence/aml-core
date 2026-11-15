"""Same-UID replacement-process attack against the session holder service."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

LEGITIMATE=r'''
import json,os,pathlib,sys,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability,verify_holder_proof
from session_holder_service import request_holder_proof
pid_file,sock,public_path,result_path=sys.argv[1:5]
pathlib.Path(pid_file).write_text(str(os.getpid()))
for _ in range(400):
 if pathlib.Path(sock).exists() and pathlib.Path(public_path).exists(): break
 time.sleep(.02)
else: raise SystemExit("holder service unavailable")
holder_public=pathlib.Path(public_path).read_text().strip()
authority=Ed25519PrivateKey.generate()
request={"operation_id":"pid-bound-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder_public)
challenge="c"*64
proof=request_holder_proof(sock,cap,request,challenge)
assert verify_holder_proof(proof,cap,request,challenge)
pathlib.Path(result_path).write_text("PID_BOUND_PROOF_OK")
'''

REPLACEMENT=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability
from session_holder_service import request_holder_proof
sock,public_path=sys.argv[1:3]
holder_public=pathlib.Path(public_path).read_text().strip()
authority=Ed25519PrivateKey.generate()
request={"operation_id":"replacement-op","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder_public)
try:
 request_holder_proof(sock,cap,request,"d"*64)
except PermissionError:
 print("SAME_UID_REPLACEMENT_PROCESS_DENIED")
else:
 raise AssertionError("replacement process under same UID inherited holder access")
'''

def start_holder(holder,client,sock,private_key,public_key,allowed_pid,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"session_holder_service.py"),str(sock),
   str(private_key),str(public_key),str(client.pw_uid),str(client.pw_gid),str(allowed_pid)],
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
 holder=pwd.getpwnam("aml_holder_test"); client=pwd.getpwnam("aml_client_test")
 assert holder.pw_uid!=client.pw_uid and holder.pw_uid!=0 and client.pw_uid!=0
 with tempfile.TemporaryDirectory(prefix="aml-holder-pid-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  state=root/"state"; state.mkdir(mode=0o700); os.chown(state,holder.pw_uid,holder.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,holder.pw_uid,holder.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o1777); shared.chmod(0o1777)
  private_key=state/"holder.pem"; public_key=shared/"holder.pub"; sock=ipc/"holder.sock"
  pid_file=shared/"client.pid"; result=shared/"result.txt"
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("session_holder_service","session_capability","signed_receipt","gated_action_broker",
      "strict_evaluator","pin_replication","pin_registry","replica_attestation"):
   source=HERE/(name+".py")
   if source.exists():
    target=lib/(name+".py"); shutil.copyfile(source,target); target.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  legitimate=subprocess.Popen([sys.executable,"-c",LEGITIMATE,str(pid_file),str(sock),
    str(public_key),str(result)],preexec_fn=drop(client.pw_uid,client.pw_gid),
    env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(200):
    if pid_file.exists(): break
    if legitimate.poll() is not None:
     out,err=legitimate.communicate(); raise AssertionError(("client exited",out,err))
    time.sleep(.02)
   assert pid_file.exists(),"legitimate client PID not published"
   allowed_pid=int(pid_file.read_text())
   assert allowed_pid==legitimate.pid
   holder_proc=start_holder(holder,client,sock,private_key,public_key,allowed_pid,lib,env)
   try:
    # A different process under the same client UID has identical socket
    # filesystem permissions, but the kernel PID/start-time pin must deny it.
    replacement=subprocess.run([sys.executable,"-c",REPLACEMENT,str(sock),str(public_key)],
      preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,
      capture_output=True,text=True,timeout=10)
    assert replacement.returncode==0,(replacement.stdout,replacement.stderr)
    assert "SAME_UID_REPLACEMENT_PROCESS_DENIED" in replacement.stdout
    out,err=legitimate.communicate(timeout=10)
    assert legitimate.returncode==0,(out,err)
    assert result.read_text()=="PID_BOUND_PROOF_OK"
    # After the enrolled process exits, another process remains denied.
    after=subprocess.run([sys.executable,"-c",REPLACEMENT,str(sock),str(public_key)],
      preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,
      capture_output=True,text=True,timeout=10)
    assert after.returncode==0,(after.stdout,after.stderr)
    print(replacement.stdout.strip())
    print("PID_BOUND_LEGITIMATE_PROCESS_OK")
    print("POST_EXIT_REPLACEMENT_PROCESS_DENIED")
   finally:
    stop(holder_proc)
  finally:
   if legitimate.poll() is None:
    legitimate.terminate(); legitimate.communicate(timeout=5)
if __name__=="__main__": main()
