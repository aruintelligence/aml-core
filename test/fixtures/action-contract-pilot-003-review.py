#!/usr/bin/env python3
"""Author-integrated regressions derived from independent Pilot 003 review.
Synthetic ephemeral keys and local SQLite only. Defect repros now assert fixes;
negative controls intentionally preserve limits. Not a new independent review.
"""
import base64, concurrent.futures, hashlib, importlib.util, json, os
from contextlib import closing
from pathlib import Path
import sqlite3, subprocess, sys, tempfile, time, unittest, uuid
ROOT = Path(__file__).resolve().parents[2]
MODULES = ROOT / 'pilots/action-boundary'
sys.path.insert(0, str(MODULES))
import authorized_execution as auth
spec = importlib.util.spec_from_file_location('atomic', MODULES / 'atomic-authorized-provider-fixture.py')
atomic = importlib.util.module_from_spec(spec); spec.loader.exec_module(atomic)

def run(args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, timeout=20)
    return p

class Review(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aml-review-')
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name); self.db = str(self.dir/'provider.sqlite')
        self.key = str(self.dir/'private.pem'); self.pub = str(self.dir/'public.pem')
        p=run(['openssl','genpkey','-algorithm','ED25519','-out',self.key]); self.assertEqual(p.returncode,0,p.stderr)
        p=run(['openssl','pkey','-in',self.key,'-pubout','-out',self.pub]); self.assertEqual(p.returncode,0,p.stderr)
        atomic.initialize_provider(self.db,self.pub)
        self.request={'operation_id':str(uuid.uuid4()),'destination':atomic.DESTINATION,'effect':atomic.EFFECT,'body':{'value':'synthetic'}}
    def envelope(self, request=None, **changes):
        req=request or self.request
        raw=json.dumps(req,ensure_ascii=True,separators=(',',':'))
        statement=dict(version='aml-authorized-execution/1',issuer='review-issuer',principal='review-principal',policy_id='review-policy',policy_epoch=1,operation_id=req['operation_id'],request_sha256=hashlib.sha256(raw.encode()).hexdigest(),destination=req['destination'],effect=req['effect'],expires_at_ms=time.time_ns()//1000000+60000)
        statement.update(changes)
        message=self.dir/'message'; message.write_bytes(auth.DOMAIN+auth.canonical(statement))
        p=run(['openssl','pkeyutl','-sign','-rawin','-inkey',self.key,'-in',str(message)])
        self.assertEqual(p.returncode,0,p.stderr)
        return dict(authorization=statement, signature=base64.b64encode(p.stdout).decode(),request_bytes=raw)
    def send(self,e,db=None, fault=None):
        return run(['python3',str(MODULES/'atomic-authorized-provider-fixture.py'),db or self.db,'request',self.pub]+(['--fault='+fault] if fault else []),json.dumps(e).encode())
    def snapshot(self,db=None):
        with closing(sqlite3.connect(db or self.db)) as c:
            return (c.execute('SELECT * FROM claims ORDER BY operation_id').fetchall(),c.execute('SELECT * FROM effects ORDER BY operation_id').fetchall())
    def empty(self): self.assertEqual(self.snapshot(),([],[]))
    def pair(self,e,db=None):
        claims,effects=self.snapshot(db)
        op=e['authorization']['operation_id']; digest=hashlib.sha256(e['request_bytes'].encode()).hexdigest()
        self.assertEqual(claims,[(op,digest)]); self.assertEqual(len(effects),1)
        self.assertEqual(effects[0][:3],(op,digest,atomic.DESTINATION))
        self.assertEqual(str(uuid.UUID(effects[0][3])),effects[0][3]); return effects[0]
    def test_all_unsigned_authority_field_mutations(self):
        original=self.envelope()
        for name,value in original['authorization'].items():
            e=json.loads(json.dumps(original)); e['authorization'][name]=value+1 if type(value) is int else value+'x'
            p=self.send(e); self.assertEqual(p.returncode,2,(name,p.stderr)); self.empty()
        p=self.send(original); self.assertEqual(p.returncode,0,p.stderr); self.pair(original)
    def test_multibyte_effect_byte_limit_and_surrogate(self):
        for value in ['é'*513, '\ud800']:
            request={**self.request,'body':{'value':value}}
            p=self.send(self.envelope(request)); self.assertEqual(p.returncode,2,p.stderr); self.empty()
        e=self.envelope({**self.request,'body':{'value':'é'*512}})
        p=self.send(e); self.assertEqual(p.returncode,0,p.stderr); self.pair(e)
    def test_sql_literal_is_only_data(self):
        e=self.envelope({**self.request,'body':{'value':"'); DROP TABLE claims; --"}})
        p=self.send(e); self.assertEqual(p.returncode,0,p.stderr); self.pair(e)
        with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute('PRAGMA integrity_check').fetchone(),('ok',))
    def test_repeated_wal_crash_matrix(self):
        with closing(sqlite3.connect(self.db)) as c: self.assertEqual(c.execute('PRAGMA journal_mode=WAL').fetchone()[0],'wal')
        for name,exit_code in atomic.FAILPOINTS.items():
            req={**self.request,'operation_id':str(uuid.uuid4())}; e=self.envelope(req)
            p=self.send(e,fault=name); self.assertEqual(p.returncode,exit_code,p.stderr)
            expected={k:e['authorization'][k] for k in ['operation_id','request_sha256','destination']}
            before=self.snapshot(); status=atomic.status(self.db,expected)
            matching_claim=[r for r in before[0] if r[0]==req['operation_id']]
            matching_effect=[r for r in before[1] if r[0]==req['operation_id']]
            self.assertEqual(len(matching_claim),int(name=='after_commit'))
            self.assertEqual(len(matching_effect),int(name=='after_commit'))
            self.assertEqual(status['result'],'PROVIDER_REPORTED' if name=='after_commit' else 'INCOMPLETE')
            self.assertEqual(self.snapshot(),before)
    def test_expiry_is_check_time_not_commit_time(self):
        # Exact existing API, real time and DB. Test harness delays fixed validation,
        # equivalent to OS scheduling pause; no signature/state check is stubbed.
        expiry=time.time_ns()//1000000+2000; e=self.envelope(expires_at_ms=expiry)
        validate=atomic.validate_fixed_request
        def delayed(req):
            while time.time_ns()//1000000 <= expiry+100: time.sleep(.01)
            validate(req)
        atomic.validate_fixed_request=delayed
        try: result=atomic.request_effect(self.db,self.pub,e)
        finally: atomic.validate_fixed_request=validate
        observed=time.time_ns()//1000000
        self.assertGreater(observed,expiry); self.assertEqual(result['operation_id'],self.request['operation_id']); self.pair(e)
        print('OBSERVATION expiry_at_check_not_commit: committed_after_expiry_ms='+str(observed-expiry),flush=True)
    def test_waiting_request_rechecks_expiry_after_write_lock(self):
        expiry=time.time_ns()//1000000+600; e=self.envelope(expires_at_ms=expiry)
        c=sqlite3.connect(self.db,isolation_level=None); c.execute('BEGIN IMMEDIATE')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.send,e)
            while time.time_ns()//1000000 <= expiry+100: time.sleep(.01)
            c.execute('ROLLBACK'); c.close(); p=future.result()
        self.assertEqual(p.returncode,2,p.stderr); self.assertIn(b'authorization_expired',p.stderr); self.empty()
    def test_waiting_request_rechecks_committed_revocation(self):
        e=self.envelope(); c=sqlite3.connect(self.db,isolation_level=None); c.execute('BEGIN IMMEDIATE')
        c.execute('INSERT INTO revoked VALUES (?)',(self.request['operation_id'],))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.send,e); time.sleep(.15); c.execute('COMMIT'); c.close(); p=future.result()
        self.assertEqual(p.returncode,2,p.stderr); self.assertIn(b'authorization_revoked',p.stderr); self.empty()
    def test_deferred_snapshot_does_not_override_new_revocation(self):
        with closing(sqlite3.connect(self.db)) as w: self.assertEqual(w.execute('PRAGMA journal_mode=WAL').fetchone()[0],'wal')
        e=self.envelope(); c=sqlite3.connect(self.db,isolation_level=None); c.execute('BEGIN')
        c.execute('SELECT * FROM revoked').fetchall() # stale reader snapshot
        auth.revoke(self.db,self.request['operation_id'])
        try:
            with self.assertRaises(sqlite3.OperationalError):
                auth.consume_in_transaction(c,self.pub,e['authorization'],e['signature'],e['request_bytes'].encode())
        finally: c.rollback(); c.close()
        self.empty()
    def test_helper_savepoint_does_not_commit_outer_transaction(self):
        e=self.envelope(); c=sqlite3.connect(self.db,isolation_level=None)
        c.execute('BEGIN IMMEDIATE'); c.execute('SAVEPOINT nested')
        auth.consume_in_transaction(c,self.pub,e['authorization'],e['signature'],e['request_bytes'].encode())
        c.execute('ROLLBACK TO nested'); c.execute('RELEASE nested'); self.assertTrue(c.in_transaction)
        c.commit(); c.close(); self.empty()
        p=self.send(e); self.assertEqual(p.returncode,0,p.stderr); self.pair(e)
    def test_concurrent_cold_initialization_is_safe_when_successful(self):
        db=str(self.dir/'cold.sqlite')
        def init(_): return run(['python3',str(MODULES/'atomic-authorized-provider-fixture.py'),db,'initialize',self.pub])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(init,range(8)))
        self.assertTrue(any(p.returncode==0 for p in results))
        self.assertTrue(all(p.returncode in (0,2) for p in results))
        with closing(sqlite3.connect(db)) as c:
            self.assertEqual(c.execute('SELECT count(*) FROM config').fetchone()[0],1)
            self.assertEqual(c.execute('PRAGMA integrity_check').fetchone(),('ok',))
        e=self.envelope(); p=self.send(e,db); self.assertEqual(p.returncode,0,p.stderr); self.pair(e,db)
        print('OBSERVATION concurrent_cold_init exit_codes='+str([p.returncode for p in results]),flush=True)
    def test_corrupt_file_fails_closed(self):
        Path(self.db).write_bytes(b'not a sqlite database')
        e=self.envelope(); p=self.send(e); self.assertEqual(p.returncode,2,p.stderr)
        expected={k:e['authorization'][k] for k in ['operation_id','request_sha256','destination']}
        with self.assertRaises(sqlite3.DatabaseError): atomic.status(self.db,expected)
        self.assertEqual(Path(self.db).read_bytes(),b'not a sqlite database')
    def test_known_control_same_key_two_databases_is_not_global_one_use(self):
        other=str(self.dir/'other.sqlite'); atomic.initialize_provider(other,self.pub); e=self.envelope()
        first=self.send(e); second=self.send(e,other)
        self.assertEqual(first.returncode,0,first.stderr); self.assertEqual(second.returncode,0,second.stderr)
        a=self.pair(e); b=self.pair(e,other); self.assertNotEqual(a[3],b[3])
        print('OBSERVATION scope: one use is per retained database, not per issuer key globally',flush=True)
    def test_literal_missing_paths_never_create_any_file(self):
        e=self.envelope()
        expected={k:e['authorization'][k] for k in ['operation_id','request_sha256','destination']}
        for suffix in ['#store.sqlite','?store.sqlite','%23store.sqlite',' space.sqlite','_雪.sqlite']:
            with self.subTest(suffix=suffix):
                literal=self.dir/('missing'+suffix)
                before=set(self.dir.iterdir())
                with self.assertRaises(sqlite3.OperationalError): atomic.status(str(literal),expected)
                p=self.send(e,str(literal)); self.assertEqual(p.returncode,2,p.stderr)
                self.assertEqual(set(self.dir.iterdir()),before)
                # Shared legacy authority helpers must not create alternate files either.
                with self.assertRaises(sqlite3.OperationalError): auth.revoke(str(literal),self.request['operation_id'])
                with self.assertRaises(sqlite3.OperationalError): auth.set_epoch(str(literal),2)
                with self.assertRaises(sqlite3.OperationalError):
                    auth.consume(str(literal),self.pub,e['authorization'],e['signature'],e['request_bytes'].encode())
                self.assertEqual(set(self.dir.iterdir()),before)
    def test_literal_paths_keep_all_tables_and_execution_in_one_file(self):
        self.envelope()  # Create the test signer message before the filesystem baseline.
        for suffix in ['#store.sqlite','?store.sqlite','%23store.sqlite',' space.sqlite','_雪.sqlite']:
            with self.subTest(suffix=suffix):
                literal=self.dir/('provider'+suffix)
                before=set(self.dir.iterdir())
                atomic.initialize_provider(str(literal),self.pub)
                self.assertEqual(set(self.dir.iterdir())-before,{literal})
                with closing(sqlite3.connect(literal)) as c:
                    tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertEqual(tables,{'claims','config','revoked','effects'})
                e=self.envelope(); p=self.send(e,str(literal)); self.assertEqual(p.returncode,0,p.stderr); self.pair(e,str(literal))
                expected={k:e['authorization'][k] for k in ['operation_id','request_sha256','destination']}
                self.assertEqual(atomic.status(str(literal),expected)['result'],'PROVIDER_REPORTED')
                # Original status is reused by signed status/history recovery.
                p=run(['python3',str(MODULES/'sqlite-provider-fixture.py'),str(literal),'status'],self.request['operation_id'].encode())
                self.assertEqual(p.returncode,0,p.stderr)
                self.assertEqual(json.loads(p.stdout)['record']['operation_id'],self.request['operation_id'])
                # Legacy consume, revoke and epoch writers resolve the same selected store.
                request={**self.request,'operation_id':str(uuid.uuid4())}; other=self.envelope(request)
                auth.consume(str(literal),self.pub,other['authorization'],other['signature'],other['request_bytes'].encode())
                auth.revoke(str(literal),request['operation_id']); auth.set_epoch(str(literal),2)
                with closing(sqlite3.connect(literal)) as c:
                    self.assertEqual(c.execute('SELECT count(*) FROM claims').fetchone()[0],2)
                    self.assertEqual(c.execute('SELECT operation_id FROM revoked').fetchall(),[(request['operation_id'],)])
                    self.assertEqual(c.execute('PRAGMA integrity_check').fetchone(),('ok',))
                self.assertEqual(set(self.dir.iterdir())-before,{literal})
    def test_legacy_gate_literal_paths_and_no_create(self):
        import sqlite_execution_gate as gate
        for suffix in ['#gate.sqlite','?gate.sqlite','%23gate.sqlite',' gate.sqlite','_雪.sqlite']:
            with self.subTest(suffix=suffix):
                literal=str(self.dir/('legacy'+suffix)); before=set(self.dir.iterdir())
                with self.assertRaises(sqlite3.OperationalError): gate.consume(literal,self.request['operation_id'],'a'*64)
                self.assertEqual(set(self.dir.iterdir()),before)
                gate.initialize(literal)
                self.assertTrue(gate.consume(literal,self.request['operation_id'],'a'*64))
                self.assertFalse(gate.consume(literal,self.request['operation_id'],'a'*64))
                with closing(sqlite3.connect(literal)) as c:
                    self.assertEqual(c.execute('SELECT * FROM claims').fetchall(),[(self.request['operation_id'],'a'*64)])
                self.assertEqual(set(self.dir.iterdir())-before,{Path(literal)})
    def test_legacy_status_and_witness_read_literal_paths_without_creation(self):
        for suffix in ['#witness.sqlite','?witness.sqlite','%23witness.sqlite',' witness.sqlite','_雪.sqlite']:
            with self.subTest(suffix=suffix):
                literal=str(self.dir/('legacy'+suffix)); before=set(self.dir.iterdir())
                for script,action in [('sqlite-status-witness.py','read'),('sqlite-provider-fixture.py','status')]:
                    p=run(['python3',str(MODULES/script),literal,action],self.request['operation_id'].encode())
                    self.assertEqual(p.returncode,2,p.stderr)
                    self.assertEqual(set(self.dir.iterdir()),before)
                p=run(['python3',str(MODULES/'sqlite-status-witness.py'),literal,'initialize',self.pub])
                self.assertEqual(p.returncode,0,p.stderr)
                p=run(['python3',str(MODULES/'sqlite-status-witness.py'),literal,'read'],self.request['operation_id'].encode())
                self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(json.loads(p.stdout),{'envelopes':[]})
                self.assertEqual(set(self.dir.iterdir())-before,{Path(literal)})
    def test_uri_mode_cannot_be_injected(self):
        from sqlite_path import sqlite_file_uri
        with self.assertRaises(ValueError): sqlite_file_uri(self.db,'ro&mode=rwc')
        self.assertIn('%23',sqlite_file_uri(str(self.dir/'x#y'),'ro'))
        self.assertIn('%3F',sqlite_file_uri(str(self.dir/'x?y'),'rw'))
        self.assertIn('%2523',sqlite_file_uri(str(self.dir/'x%23y'),'ro'))
    def test_ascii_DEL_requires_declared_profile_not_core_encoding(self):
        # Separate profile signer succeeds. Core profile intentionally remains distinct;
        # fixed JS helper is cross-checked by the native Node acceptance tests.
        e=self.envelope(principal='review\x7fprincipal')
        program="import fs from 'node:fs'; import crypto from 'node:crypto'; import {canonicalJSONStringify} from './protocol/canonicalJson.js'; const x=JSON.parse(fs.readFileSync(0,'utf8')); console.log(crypto.sign(null,Buffer.concat([Buffer.from('AML-AUTHORIZED-EXECUTION/1\\0'),Buffer.from(canonicalJSONStringify(x.auth))]),fs.readFileSync(x.key)).toString('base64'));"
        p=run(['node','--input-type=module','-e',program],json.dumps({'auth':e['authorization'],'key':self.key}).encode()); self.assertEqual(p.returncode,0,p.stderr)
        generic={**e,'signature':p.stdout.decode().strip()}; p=self.send(generic)
        self.assertEqual(p.returncode,2,p.stderr); self.assertIn(b'invalid_authorization_signature',p.stderr); self.empty()
        p=self.send(e); self.assertEqual(p.returncode,0,p.stderr); self.pair(e)
        print('CONTROL distinct signature profiles: generic core bytes rejected; declared authorization profile accepted',flush=True)

if __name__=='__main__': unittest.main(verbosity=2)
