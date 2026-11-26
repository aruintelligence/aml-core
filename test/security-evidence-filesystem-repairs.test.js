import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createFileDispatchLedger } from "../pilots/action-boundary/file-dispatch-ledger.mjs";
import { createFileOneShotGrants } from "../pilots/action-boundary/file-one-shot-grants.mjs";
import { checkExternalVerifierKit } from "../scripts/check-external-verifier-kit.mjs";
import { createAmlSupportBundle } from "../tooling/supportBundle.js";
import { readRegularFile } from "../tooling/readRegularFile.js";
import { appendOnlyFile } from "../tooling/appendOnlyFile.js";
const root = fileURLToPath(new URL("../", import.meta.url));
function temporary(fn) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-security-fs-")); try { const r=fn(dir); if(r?.then)return r.finally(()=>fs.rmSync(dir,{recursive:true,force:true})); fs.rmSync(dir,{recursive:true,force:true});return r; } catch(e){fs.rmSync(dir,{recursive:true,force:true});throw e;} }

// The same retained counterexample schedule is injected at the path-check stage
// in legacy implementations and at descriptor-stat in repaired implementations.
function replaceAfterCheck(target, replacement, action) {
 const originals={open:fs.openSync,lstat:fs.lstatSync,stat:fs.statSync,fstat:fs.fstatSync,read:fs.readFileSync};
 let descriptor, swapped=false, outsideReads=0;
 const swap=()=>{if(!swapped){swapped=true;fs.unlinkSync(target);fs.symlinkSync(replacement,target);}};
 fs.openSync=function(p,...args){const fd=originals.open.call(this,p,...args);if(String(p)===target)descriptor=fd;return fd;};
 fs.lstatSync=function(p,...args){const s=originals.lstat.call(this,p,...args);if(String(p)===target)swap();return s;};
 fs.statSync=function(p,...args){const s=originals.stat.call(this,p,...args);if(String(p)===target)swap();return s;};
 fs.fstatSync=function(fd,...args){const s=originals.fstat.call(this,fd,...args);if(fd===descriptor)swap();return s;};
 fs.readFileSync=function(p,...args){if(String(p)===target&&swapped)outsideReads++;return originals.read.call(this,p,...args);};
 try { return {result:action(),get swapped(){return swapped;},get outsideReads(){return outsideReads;}}; }
 finally {fs.openSync=originals.open;fs.lstatSync=originals.lstat;fs.statSync=originals.stat;fs.fstatSync=originals.fstat;fs.readFileSync=originals.read;}
}

test("ledger reads its checked descriptor, not a replacement pathname symlink",()=>temporary(parent=>{
 const ledger=createFileDispatchLedger({directory:path.join(parent,"ledger")});const input={operationId:"public-op-001",proposal:{synthetic:true}};const v=ledger.claim(input);
 const claim=path.join(parent,"ledger",v.operation_sha256+".claim.json"),other=path.join(parent,"replacement.json");
 fs.writeFileSync(other,JSON.stringify({protocol:"aml-file-dispatch-claim/1",operation_sha256:v.operation_sha256,proposal_sha256:"c".repeat(64)}),{mode:0o600});
 const r=replaceAfterCheck(claim,other,()=>ledger.inspect(input));
 assert.equal(r.swapped,true);assert.equal(r.outsideReads,0);assert.equal(r.result.status,"unknown");
 assert.equal(ledger.inspect(input).reason,"incomplete_claim");
}));

test("grant marker snapshot does not read a symlink replacement and later calls reject it",async()=>temporary(async parent=>{
 const directory=path.join(parent,"grants"),state=path.join(directory,"store-state.json"),other=path.join(parent,"replacement.json");
 const grants=createFileOneShotGrants({directory});await grants.issue("a".repeat(64));fs.writeFileSync(other,fs.readFileSync(state),{mode:0o600});
 const open=fs.openSync,fstat=fs.fstatSync,lstat=fsp.lstat,read=fsp.readFile;let descriptor,swapped=false,outsideReads=0;
 const swap=()=>{if(!swapped){swapped=true;fs.unlinkSync(state);fs.symlinkSync(other,state);}};
 fs.openSync=function(p,...args){const fd=open.call(this,p,...args);if(String(p)===state)descriptor=fd;return fd;};
 fs.fstatSync=function(fd,...args){const info=fstat.call(this,fd,...args);if(fd===descriptor)swap();return info;};
 fsp.lstat=async function(p,...args){const info=await lstat.call(this,p,...args);if(String(p)===state&&new Error().stack.includes("verify"))swap();return info;};
 fsp.readFile=async function(p,...args){if(String(p)===state&&swapped)outsideReads++;return read.call(this,p,...args);};syncBuiltinESMExports();
 try{assert.equal((await grants.issue("b".repeat(64))).approved,true);assert.equal(swapped,true);assert.equal(outsideReads,0);}
 finally{fs.openSync=open;fs.fstatSync=fstat;fsp.lstat=lstat;fsp.readFile=read;syncBuiltinESMExports();}
 await assert.rejects(grants.issue("c".repeat(64)),/grant_store_incomplete/);
}));

test("verifier-kit stat/read substitution never reads replacement file bytes",()=>temporary(parent=>{
 const kit=path.join(parent,"kit");fs.mkdirSync(kit);const file=path.join(kit,"public.txt"),other=path.join(parent,"replacement.txt");fs.writeFileSync(file,"before");fs.writeFileSync(other,"after");
 fs.writeFileSync(path.join(kit,"manifest.json"),JSON.stringify({schema:"aml-external-verifier-kit/1",reference_code_included:false,file_count:1,files:[{path:"public.txt",bytes:6,sha256:"a".repeat(64)}]}));fs.writeFileSync(path.join(kit,"SHA256SUMS"),"");
 const r=replaceAfterCheck(file,other,()=>checkExternalVerifierKit(kit));assert.equal(r.swapped,true);assert.equal(r.outsideReads,0);assert.equal(r.result.valid,false);
}));

test("support evidence reports a disappearing contract unavailable instead of throwing",()=>{
 const target=path.join(root,"project-contract.json"),open=fs.openSync,stat=fs.statSync,read=fs.readFileSync;let armed=false,injected=false;
 fs.statSync=function(p,...args){const info=stat.call(this,p,...args);if(String(p)===target&&new Error().stack.includes("fileEvidence"))armed=true;return info;};
 fs.readFileSync=function(p,...args){if(armed&&String(p)===target){injected=true;const e=new Error("synthetic vanished contract");e.code="ENOENT";throw e;}return read.call(this,p,...args);};
 fs.openSync=function(p,...args){if(String(p)===target&&new Error().stack.includes("fileEvidence")){injected=true;const e=new Error("synthetic vanished contract");e.code="ENOENT";throw e;}return open.call(this,p,...args);};
 try{const result=createAmlSupportBundle();assert.equal(injected,true);assert.equal(result.healthy,false);assert.equal(result.contracts.find(x=>x.path==="project-contract.json").present,false);}
 finally{fs.openSync=open;fs.statSync=stat;fs.readFileSync=read;}
 assert.equal(createAmlSupportBundle().healthy,true);
});

test("bounded reader rejects symlinks, directories and oversized files without repairs",()=>temporary(dir=>{
 const file=path.join(dir,"file"),link=path.join(dir,"link");fs.writeFileSync(file,"public synthetic",{mode:0o600});fs.symlinkSync(file,link);
 assert.throws(()=>readRegularFile(link,{maxBytes:128,noFollow:true}));assert.throws(()=>readRegularFile(dir,{maxBytes:128}));assert.throws(()=>readRegularFile(file,{maxBytes:2}));
 assert.equal(readRegularFile(file,{maxBytes:128,privateOwner:true,noFollow:true}).toString(),"public synthetic");
 assert.throws(()=>readRegularFile(file,{maxBytes:-1}));assert.equal(fs.readFileSync(file,"utf8"),"public synthetic");
}));

test("bounded reader detects same-inode growth without reading an unbounded tail",()=>temporary(dir=>{
 const file=path.join(dir,"file");fs.writeFileSync(file,"before");const fstat=fs.fstatSync;let changed=false;
 fs.fstatSync=function(fd,...args){const info=fstat.call(this,fd,...args);if(!changed){changed=true;fs.appendFileSync(file,"extra");}return info;};
 try{assert.throws(()=>readRegularFile(file,{maxBytes:128}),/changed_during_read/);}
 finally{fs.fstatSync=fstat;}
}));

test("append-only writer retains prefix, appends once, rejects mutation and leaves no owned lock",()=>temporary(dir=>{
 const file=path.join(dir,"registry");appendOnlyFile(file,"first\n");appendOnlyFile(file,"first\nsecond\n");appendOnlyFile(file,"first\nsecond\n");
 assert.throws(()=>appendOnlyFile(file,"forged\n"),/immutable/);assert.equal(fs.readFileSync(file,"utf8"),"first\nsecond\n");assert.equal(fs.existsSync(file+".write-lock"),false);
}));

test("existing/orphan registry writer lock is not automatically deleted or bypassed",()=>temporary(dir=>{
 const file=path.join(dir,"registry");fs.writeFileSync(file,"retained\n");fs.mkdirSync(file+".write-lock");
 assert.throws(()=>appendOnlyFile(file,"retained\nnew\n"),e=>e.code==="EEXIST");assert.equal(fs.readFileSync(file,"utf8"),"retained\n");assert.equal(fs.existsSync(file+".write-lock"),true);
}));

test("noncooperating concurrent append is retained and detected, never silently overwritten",()=>temporary(dir=>{
 const file=path.join(dir,"registry");fs.writeFileSync(file,"first\n");const open=fs.openSync,write=fs.writeSync;let descriptor,injected=false;
 fs.openSync=function(p,...args){const fd=open.call(this,p,...args);if(String(p)===file)descriptor=fd;return fd;};
 fs.writeSync=function(fd,...args){if(fd===descriptor&&!injected){injected=true;fs.appendFileSync(file,"external\n");}return write.call(this,fd,...args);};
 try{assert.throws(()=>appendOnlyFile(file,"first\nsecond\n"),/concurrent_change/);assert.equal(injected,true);}
 finally{fs.openSync=open;fs.writeSync=write;}
 assert.equal(fs.readFileSync(file,"utf8"),"first\nexternal\nsecond\n");assert.equal(fs.existsSync(file+".write-lock"),false);
}));

test("append-only writer refuses final symlinks and preserves destination bytes",()=>temporary(dir=>{
 const other=path.join(dir,"other"),file=path.join(dir,"registry");fs.writeFileSync(other,"public\n");fs.symlinkSync(other,file);
 assert.throws(()=>appendOnlyFile(file,"public\nextra\n"));assert.equal(fs.readFileSync(other,"utf8"),"public\n");assert.equal(fs.existsSync(file+".write-lock"),false);
}));


test("eight cooperating registry writers never duplicate the identical suffix", { timeout: 30000 }, async()=>temporary(async dir=>{
 const file=path.join(dir,"registry");fs.writeFileSync(file,"first\n");
 const moduleUrl=new URL("../tooling/appendOnlyFile.js",import.meta.url).href;
 const program=`import fs from "node:fs"; import {appendOnlyFile} from ${JSON.stringify(moduleUrl)}; process.stdout.write("READY\\n"); fs.readFileSync(0); try {appendOnlyFile(process.argv[1],"first\\nsecond\\n"); process.exitCode=0;} catch(e){ if(e.code!=="EEXIST") throw e; process.exitCode=2; }`;
 const children=[];
 try {
  const ready=Array.from({length:8},()=>new Promise((resolve,reject)=>{
   const p=spawn(process.execPath,["--input-type=module","-e",program,file],{stdio:["pipe","pipe","pipe"],timeout:15000});children.push(p);
   let output="";p.stdout.on("data",chunk=>{output+=chunk;if(output.includes("READY"))resolve();});p.once("error",reject);
   p.once("exit",code=>{if(!output.includes("READY"))reject(new Error("worker exited before barrier: "+code));});
  }));
  await Promise.all(ready);const results=children.map(p=>new Promise(resolve=>p.once("exit",code=>resolve(code))));
  for(const p of children)p.stdin.end("GO");const codes=await Promise.all(results);
  assert.ok(codes.some(c=>c===0));assert.ok(codes.every(c=>c===0||c===2));
  assert.equal(fs.readFileSync(file,"utf8"),"first\nsecond\n");assert.equal(fs.existsSync(file+".write-lock"),false);
 } finally {for(const p of children)if(p.exitCode===null)p.kill();}
}));


test("registry bounded descriptor read rejects growth after initial fstat without truncating",()=>temporary(dir=>{
 const file=path.join(dir,"registry");fs.writeFileSync(file,"first\n");
 const open=fs.openSync,stat=fs.fstatSync,read=fs.readSync,whole=fs.readFileSync;
 let descriptor,injected=false,readCalls=0,wholeCalls=0;const lengths=[];
 fs.openSync=function(p,...args){const fd=open.call(this,p,...args);if(String(p)===file&&descriptor===undefined)descriptor=fd;return fd;};
 fs.fstatSync=function(fd,...args){const info=stat.call(this,fd,...args);if(fd===descriptor&&!injected){injected=true;fs.appendFileSync(file,"GROW");}return info;};
 fs.readSync=function(fd,buffer,offset,length,...args){if(fd===descriptor){readCalls++;lengths.push(length);}return read.call(this,fd,buffer,offset,length,...args);};
 fs.readFileSync=function(fd,...args){if(fd===descriptor)wholeCalls++;return whole.call(this,fd,...args);};
 try{assert.throws(()=>appendOnlyFile(file,"first\nsecond\n"),/append_only_concurrent_change/);assert.equal(injected,true);assert.ok(readCalls>0);assert.ok(lengths.every(n=>n<=7));assert.equal(wholeCalls,0);}
 finally{fs.openSync=open;fs.fstatSync=stat;fs.readSync=read;fs.readFileSync=whole;}
 assert.equal(fs.readFileSync(file,"utf8"),"first\nGROW");assert.equal(fs.existsSync(file+".write-lock"),false);
}));
