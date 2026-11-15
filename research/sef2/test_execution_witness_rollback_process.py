"""Detect rollback of signed execution witness using broker-retained receipt head."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

CLIENT_ONE=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import SignedRemoteExecutionConsumptionWitness
from session_capability import issue_session_capability
sock,pub,checkpoint=sys.argv[1:4]
authority=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
request={"operation_id":"witness-rollback-a","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder.public_key().public_bytes_raw().hex())
w=SignedRemoteExecutionConsumptionWitness(sock,"execution-witness-rollback",pathlib.Path(pub).read_text().strip(),checkpoint)
receipt=w.consume(request,cap,"a"*64)
assert receipt["payload"]["sequence"]==1
assert w.checkpoint()["sequence"]==1
print("EXECUTION_WITNESS_CHECKPOINT_ONE")
'''

CLIENT_AFTER_ROLLBACK=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import SignedRemoteExecutionConsumptionWitness
from session_capability import issue_session_capability
sock,pub,checkpoint=sys.argv[1:4]
authority=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
request={"operation_id":"witness-rollback-b","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder.public_key().public_bytes_raw().hex())
w=SignedRemoteExecutionConsumptionWitness(sock,"execution-witness-rollback",pathlib.Path(pub).read_text().strip(),checkpoint)
try:
 w.consume(request,cap,"b"*64)
except PermissionError:
 print("EXECUTION_WITNESS_ROLLBACK_DETECTED")
else:
 raise AssertionError("rolled-back witness branch accepted")
assert w.checkpoint()["sequence"]==1
'''

def start(witness,broker,sock,db,key,pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_consumption_witness_service.py"),
  str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),
  "execution-witness-rollback",str(key),str(pub)],
  preexec_fn=drop(witness.pw_uid,witness.pw_gid,(broker.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("witness service exited: "+proc.stderr.read())
  if sock.exists() and pub.exists(): time.sleep(.05); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError("witness startup timeout")

def stop(proc):
 proc.terminate()
 try: proc.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  proc.kill(); proc.communicate(timeout=5)

def run(script,args,account,env):
 result=subprocess.run([sys.executable,"-c",script,*map(str,args)],
  preexec_fn=drop(account.pw_uid,account.pw_gid),env=env,capture_output=True,text=True,timeout=10)
 assert result.returncode==0,(result.stdout,result.stderr)
 return result.stdout.strip()

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 witness=pwd.getpwnam("aml_execution_witness_test"); broker=pwd.getpwnam("aml_broker_test")
 assert witness.pw_uid!=broker.pw_uid
 with tempfile.TemporaryDirectory(prefix="aml-exec-witness-rollback-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  wstate=root/"witness"; wstate.mkdir(mode=0o700); os.chown(wstate,witness.pw_uid,witness.pw_gid)
  bstate=root/"broker"; bstate.mkdir(mode=0o700); os.chown(bstate,broker.pw_uid,broker.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,witness.pw_uid,witness.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o755)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("execution_consumption_witness.py","execution_consumption_witness_service.py",
      "session_capability.py","gated_action_broker.py","signed_receipt.py","strict_evaluator.py",
      "pin_replication.py","pin_registry.py","replica_attestation.py"):
   src=HERE/name
   if not src.exists(): src=HERE/(name if name.endswith(".py") else name+".py")
   dst=lib/src.name; shutil.copyfile(src,dst); dst.chmod(0o644)
  sock=ipc/"witness.sock"; db=wstate/"witness.sqlite"; key=wstate/"witness.pem"; pub=shared/"witness.pub"
  checkpoint=bstate/"accepted-head.sqlite"
  env=dict(os.environ,PYTHONPATH=str(lib))
  # Initialize empty DB/key, then snapshot only DB. Key and broker checkpoint survive rollback.
  proc=start(witness,broker,sock,db,key,pub,lib,env); stop(proc)
  empty=shared/"empty-witness.sqlite"; shutil.copy2(db,empty)
  proc=start(witness,broker,sock,db,key,pub,lib,env)
  try:
   first=run(CLIENT_ONE,[sock,pub,checkpoint],broker,env)
   assert "EXECUTION_WITNESS_CHECKPOINT_ONE" in first
  finally: stop(proc)
  shutil.copy2(empty,db); os.chown(db,witness.pw_uid,witness.pw_gid); db.chmod(0o600)
  proc=start(witness,broker,sock,db,key,pub,lib,env)
  try:
   detected=run(CLIENT_AFTER_ROLLBACK,[sock,pub,checkpoint],broker,env)
   assert "EXECUTION_WITNESS_ROLLBACK_DETECTED" in detected
   print(first); print(detected)
  finally: stop(proc)
if __name__=="__main__": main()
