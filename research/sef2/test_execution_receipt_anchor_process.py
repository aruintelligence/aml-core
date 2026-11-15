"""Two-independent-UID execution witness + receipt-anchor rollback experiment."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

CLIENT_FIRST=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_receipt_anchor import AnchoredRemoteExecutionConsumptionWitness
from session_capability import issue_session_capability
witness_sock,anchor_sock,pub=sys.argv[1:4]
authority=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
request={"operation_id":"anchored-exec-a","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder.public_key().public_bytes_raw().hex())
w=AnchoredRemoteExecutionConsumptionWitness(witness_sock,"execution-witness-anchored",
 pathlib.Path(pub).read_text().strip(),anchor_sock)
receipt=w.consume(request,cap,"a"*64)
assert receipt["payload"]["sequence"]==1
print("ANCHORED_EXECUTION_CONSUMPTION_ONE")
'''

CLIENT_AFTER_ROLLBACK=r'''
import pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_receipt_anchor import AnchoredRemoteExecutionConsumptionWitness
from session_capability import issue_session_capability
witness_sock,anchor_sock,pub=sys.argv[1:4]
authority=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
request={"operation_id":"anchored-exec-b","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
cap=issue_session_capability(authority,"authority","broker-a",request,0,holder.public_key().public_bytes_raw().hex())
w=AnchoredRemoteExecutionConsumptionWitness(witness_sock,"execution-witness-anchored",
 pathlib.Path(pub).read_text().strip(),anchor_sock)
try:
 w.consume(request,cap,"b"*64)
except PermissionError:
 print("INDEPENDENT_EXECUTION_ANCHOR_DETECTED_WITNESS_ROLLBACK")
else:
 raise AssertionError("independent anchor accepted rolled-back witness branch")
'''

def start_witness(user,broker,sock,db,key,pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_consumption_witness_service.py"),
  str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),
  "execution-witness-anchored",str(key),str(pub)],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(broker.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("execution witness died: "+proc.stderr.read())
  if sock.exists() and pub.exists(): time.sleep(.04); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError("execution witness startup timeout")

def start_anchor(user,broker,sock,db,pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_receipt_anchor_service.py"),
  str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),
  "execution-witness-anchored",pathlib.Path(pub).read_text().strip()],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(broker.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("receipt anchor died: "+proc.stderr.read())
  if sock.exists(): time.sleep(.04); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError("receipt anchor startup timeout")

def stop(proc):
 proc.terminate()
 try: proc.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  proc.kill(); proc.communicate(timeout=5)

def run(script,args,broker,env):
 r=subprocess.run([sys.executable,"-c",script,*map(str,args)],
  preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
 assert r.returncode==0,(r.stdout,r.stderr)
 return r.stdout.strip()

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 witness=pwd.getpwnam("aml_execution_witness_test")
 anchor=pwd.getpwnam("aml_execution_anchor_test")
 broker=pwd.getpwnam("aml_broker_test")
 assert len({witness.pw_uid,anchor.pw_uid,broker.pw_uid})==3
 with tempfile.TemporaryDirectory(prefix="aml-exec-anchor-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  ws=root/"witness"; ws.mkdir(mode=0o700); os.chown(ws,witness.pw_uid,witness.pw_gid)
  ast=root/"anchor"; ast.mkdir(mode=0o700); os.chown(ast,anchor.pw_uid,anchor.pw_gid)
  ipcw=root/"wipc"; ipcw.mkdir(mode=0o711); os.chown(ipcw,witness.pw_uid,witness.pw_gid)
  ipca=root/"aipc"; ipca.mkdir(mode=0o711); os.chown(ipca,anchor.pw_uid,anchor.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o755)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  names=("execution_consumption_witness","execution_consumption_witness_service",
   "execution_receipt_anchor","execution_receipt_anchor_service","session_capability",
   "gated_action_broker","signed_receipt","strict_evaluator","pin_replication",
   "pin_registry","replica_attestation")
  for name in names:
   src=HERE/(name+".py"); dst=lib/(name+".py"); shutil.copyfile(src,dst); dst.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  wsock=ipcw/"w.sock"; wdb=ws/"w.sqlite"; wkey=ws/"w.pem"; wpub=shared/"w.pub"
  asock=ipca/"a.sock"; adb=ast/"a.sqlite"
  wp=start_witness(witness,broker,wsock,wdb,wkey,wpub,lib,env); stop(wp)
  empty=shared/"empty.sqlite"; shutil.copy2(wdb,empty)
  ap=start_anchor(anchor,broker,asock,adb,wpub,lib,env)
  wp=start_witness(witness,broker,wsock,wdb,wkey,wpub,lib,env)
  try:
   first=run(CLIENT_FIRST,[wsock,asock,wpub],broker,env)
   assert "ANCHORED_EXECUTION_CONSUMPTION_ONE" in first
  finally: stop(wp)
  # Roll back only witness DB. Anchor state and witness signing key survive.
  shutil.copy2(empty,wdb); os.chown(wdb,witness.pw_uid,witness.pw_gid); wdb.chmod(0o600)
  wp=start_witness(witness,broker,wsock,wdb,wkey,wpub,lib,env)
  try:
   detected=run(CLIENT_AFTER_ROLLBACK,[wsock,asock,wpub],broker,env)
   assert "INDEPENDENT_EXECUTION_ANCHOR_DETECTED_WITNESS_ROLLBACK" in detected
   print(first); print(detected)
  finally:
   stop(wp); stop(ap)
if __name__=="__main__": main()
