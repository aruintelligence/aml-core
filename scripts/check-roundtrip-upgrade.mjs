import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

function fail(message) { console.error(message); process.exit(1); }
const project = JSON.parse(fs.readFileSync('project-contract.json', 'utf8'));
const fixture = 'examples/simple.aml';
if (!fs.existsSync(fixture)) fail(`Missing fixture ${fixture}`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-roundtrip-'));
try {
  const stableDir = path.join(tmp, 'stable');
  fs.mkdirSync(stableDir);
  execFileSync('git', ['archive', '--format=tar', project.release.stableTag, '-o', path.join(tmp, 'stable.tar')], { stdio: 'inherit' });
  execFileSync('tar', ['-xf', path.join(tmp, 'stable.tar'), '-C', stableDir], { stdio: 'inherit' });

  const stablePack = execFileSync('npm', ['pack', '--silent'], { cwd: stableDir, encoding: 'utf8' }).trim().split(/\r?\n/).pop();
  const currentPack = execFileSync('npm', ['pack', '--silent'], { encoding: 'utf8' }).trim().split(/\r?\n/).pop();
  if (!stablePack || !currentPack) fail('Unable to pack one or both release candidates');

  const stableConsumer = path.join(tmp, 'stable-consumer');
  const currentConsumer = path.join(tmp, 'current-consumer');
  fs.mkdirSync(stableConsumer); fs.mkdirSync(currentConsumer);
  for (const dir of [stableConsumer, currentConsumer]) {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"type":"module"}\n');
  }

  execFileSync('npm', ['install', '--ignore-scripts', path.resolve(stableDir, stablePack)], { cwd: stableConsumer, stdio: 'inherit' });
  execFileSync('npm', ['install', '--ignore-scripts', path.resolve(currentPack)], { cwd: currentConsumer, stdio: 'inherit' });

  const source = fs.readFileSync(fixture, 'utf8');
  fs.writeFileSync(path.join(stableConsumer, 'fixture.aml'), source);
  fs.writeFileSync(path.join(currentConsumer, 'fixture.aml'), source);

  const runner = `import fs from 'node:fs'; import { compileSource } from 'aml-core'; const s=fs.readFileSync('fixture.aml','utf8'); const r=compileSource(s,{timestamp:'2026-01-01T00:00:00.000Z'}); console.log(JSON.stringify({tokens:r.tokens.length, decisions:r.renderDecisions.map(x=>x.decision||x.action||null)}));`;
  const stableResult = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', runner], { cwd: stableConsumer, encoding: 'utf8' }));
  const currentResult = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', runner], { cwd: currentConsumer, encoding: 'utf8' }));

  if (stableResult.tokens !== currentResult.tokens) fail(`Token count changed across stable/current roundtrip: ${stableResult.tokens} vs ${currentResult.tokens}`);
  if (JSON.stringify(stableResult.decisions) !== JSON.stringify(currentResult.decisions)) fail('Canonical decision sequence changed across stable/current roundtrip');

  console.log(JSON.stringify({
    valid: true,
    protocol: 'aml-release-roundtrip-report/1',
    stable_tag: project.release.stableTag,
    current_version: JSON.parse(fs.readFileSync('package.json','utf8')).version,
    fixture,
    stable_result: stableResult,
    current_result: currentResult,
    claim_boundary: 'Project-controlled canonical-fixture compatibility regression only; not proof that every application or persisted state can upgrade or downgrade safely.'
  }, null, 2));
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
