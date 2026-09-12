import { spawnSync } from 'node:child_process';

const worker = `import { compileSource } from './index.js';
const block='engram card { value: "memory pressure" purpose: "bounded regression" memory_role: "diagnostic" user_effect: "clarity" attention_cost: 1 restoration_value: 2 }';
const source='transmission "memory" {\\n'+Array.from({length:250},(_,i)=>block.replace('card','card'+i)).join('\\n')+'\\n}';
let peak=0; for(let i=0;i<120;i++){ const r=compileSource(source,{timestamp:'2026-01-01T00:00:00.000Z'}); if(!r.tokens?.length) throw new Error('compile produced no tokens'); peak=Math.max(peak,process.memoryUsage().rss); }
console.log(JSON.stringify({iterations:120, source_bytes:Buffer.byteLength(source), peak_rss_bytes:peak}));`;

const run = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', worker], {
  encoding: 'utf8',
  timeout: 30000,
  maxBuffer: 1024 * 1024
});
if (run.error?.code === 'ETIMEDOUT') throw new Error('Memory-pressure regression exceeded 30 second timeout');
if (run.status !== 0) throw new Error(`Memory-pressure worker failed under 256 MiB V8 heap ceiling: ${run.stderr || run.stdout}`);
const report = JSON.parse(run.stdout);
if (!(report.iterations === 120 && report.source_bytes > 0 && report.peak_rss_bytes > 0)) throw new Error('Invalid memory-pressure report');
console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-memory-pressure-report/1',
  v8_heap_ceiling_mib: 256,
  execution_timeout_ms: 30000,
  ...report,
  claim_boundary: 'Project-controlled bounded memory regression only. RSS can exceed the V8 heap ceiling because it also includes code, stacks, native allocations, and mapped memory; this is not a production memory SLA or denial-of-service guarantee.'
}, null, 2));
