"""Real separate-UID execution consumption witness integration."""
import json,os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

BROKER=r'''
import json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import SignedRemoteExecutionConsumptionWitness
from session_capability import issue_session_capability
sock,record_path,public_path=sys.argv[1:4]
authority=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
request={"operation_id":"remote-exec-once","action":"payment:simulate",
 "target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,
 holder.public_key().public_bytes_raw().hex())
w=SignedRemoteExecutionConsumptionWitness(sock,"execution-witness-1",pathlib.Path(public_path).read_text().strip())
receipt=w.consume(request,cap,"c"*64)
assert receipt["payload"]["witness_id"]=="execution-witness-1"
try:
 w.consume(request,cap,"c"*64)
except PermissionError:
 pass
else:
 raise AssertionError("execution witness accepted duplicate operation")
pathlib.Path(record_path).write_text(json.dumps({"request":request,"capability":cap,"challenge":"c"*64,"receipt":receipt}))
print("REMOTE_EXECUTION_CONSUMPTION_OK")
'''

ATTACKER=r'''
from execution_consumption_witness import RemoteExecutionConsumptionWitness
import sys
try:
 RemoteExecutionConsumptionWitness(sys.argv[1]).consume(
  {"operation_id":"attacker-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":1},
  {"payload":{},"signature":"00"*64},"x"*64)
except (PermissionError,OSError):
 print("UNTRUSTED_EXECUTION_WITNESS_DENIED")
else:
 raise AssertionError("untrusted UID consumed execution operation")
'''

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 witness=pwd.getpwnam("aml_execution_witness_test")
 broker=pwd.getpwnam("aml_broker_test")
 attacker=pwd.getpwnam("aml_client_test")
 assert len({witness.pw_uid,broker.pw_uid,attacker.pw_uid})==3
 with tempfile.TemporaryDirectory(prefix="aml-execution-witness-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  state=root/"state"; state.mkdir(mode=0o700); os.chown(state,witness.pw_uid,witness.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,witness.pw_uid,witness.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o1777); shared.chmod(0o1777)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  for name in ("execution_consumption_witness.py","execution_consumption_witness_service.py",
      "session_capability.py","gated_action_broker.py","signed_receipt.py","strict_evaluator.py",
      "pin_replication.py","pin_registry.py","replica_attestation.py"):
   source=HERE/name
   if not source.exists(): source=HERE/(name if name.endswith(".py") else name+".py")
   target=lib/source.name; shutil.copyfile(source,target); target.chmod(0o644)
  sock=ipc/"execution.sock"; db=state/"execution.sqlite"; private_key=state/"execution.pem"; public_key=shared/"execution.pub"
  env=dict(os.environ,PYTHONPATH=str(lib))
  proc=subprocess.Popen([sys.executable,str(lib/"execution_consumption_witness_service.py"),
   str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),
   "execution-witness-1",str(private_key),str(public_key)],
   preexec_fn=drop(witness.pw_uid,witness.pw_gid,(broker.pw_gid,)),env=env,
   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(200):
    if proc.poll() is not None: raise AssertionError("execution witness died: "+proc.stderr.read())
    if sock.exists() and public_key.exists(): time.sleep(.05); break
    time.sleep(.02)
   else: raise AssertionError("execution witness startup timeout")
   record=shared/"record.json"
   good=subprocess.run([sys.executable,"-c",BROKER,str(sock),str(record),str(public_key)],
    preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
   assert good.returncode==0,(good.stdout,good.stderr)
   bad=subprocess.run([sys.executable,"-c",ATTACKER,str(sock)],
    preexec_fn=drop(attacker.pw_uid,attacker.pw_gid,(broker.pw_gid,)),env=env,
    capture_output=True,text=True,timeout=10)
   assert bad.returncode==0,(bad.stdout,bad.stderr)
   reader=r'''import pathlib,sys
for value in sys.argv[1:]:
 try:
  pathlib.Path(value).read_bytes()
 except PermissionError:
  continue
 raise AssertionError("non-witness UID read execution witness private state")
print("EXECUTION_WITNESS_PRIVATE_STATE")
'''
   for account in (broker,attacker):
    check=subprocess.run([sys.executable,"-c",reader,str(db),str(private_key)],
     preexec_fn=drop(account.pw_uid,account.pw_gid),env=env,capture_output=True,text=True,timeout=10)
    assert check.returncode==0,(check.stdout,check.stderr)
   print(good.stdout.strip()); print(bad.stdout.strip()); print("EXECUTION_WITNESS_UID_OK")
  finally:
   proc.terminate()
   try: proc.communicate(timeout=5)
   except subprocess.TimeoutExpired:
    proc.kill(); proc.communicate(timeout=5)
if __name__=="__main__": main()
