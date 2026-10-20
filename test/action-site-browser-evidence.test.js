import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = path.join(root, 'docs/action-pilots/evidence');
const verifier = path.join(root, 'scripts/build-action-site-browser-receipts.mjs');

test('a changed screenshot or serialized DOM fails paired verification', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-action-site-evidence-'));
  try {
    fs.cpSync(source, dir, { recursive: true });
    const run = () => spawnSync(process.execPath, [verifier, '--check', '--evidence-dir', dir],
      { cwd: root, encoding: 'utf8' });
    assert.equal(run().status, 0);
    const shot = path.join(dir, 'pilot-01-support-hours-before.jpg');
    const bytes = fs.readFileSync(shot);
    bytes[bytes.length - 1] ^= 1;
    fs.writeFileSync(shot, bytes);
    assert.notEqual(run().status, 0, 'changed screenshot was accepted');
    fs.copyFileSync(path.join(source, path.basename(shot)), shot);
    const dom = path.join(dir, 'pilot-01-support-hours-after.dom.html');
    fs.appendFileSync(dom, '<a href="https://other.example.test">Injected</a>');
    assert.notEqual(run().status, 0, 'changed DOM was accepted');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
