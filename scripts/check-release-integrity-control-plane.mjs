import { spawnSync } from 'node:child_process';

for (const script of [
  'scripts/check-release-integrity-contract.mjs',
  'scripts/check-immutable-release-manifest-contract.mjs',
  'scripts/check-compromise-response-contract.mjs',
  'scripts/check-release-integrity-response.mjs'
]) {
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(`${script} failed: ${r.stderr || r.stdout}`);
  process.stdout.write(r.stdout);
}
console.log(JSON.stringify({ protocol: 'aml-release-integrity-control-plane/1', passed: true }, null, 2));
