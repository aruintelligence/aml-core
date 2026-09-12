import crypto from 'node:crypto';
import { compileSource } from '../compiler/compiler.js';

const encoded = process.argv[2];
if (!encoded) process.exit(2);
const source = Buffer.from(encoded, 'base64').toString('utf8');

function outcome() {
  try {
    const result = compileSource(source, { timestamp: '1970-01-01T00:00:00.000Z' });
    const material = JSON.stringify({ amt: result.amt, renderDecisions: result.renderDecisions });
    return {
      kind: 'accepted',
      digest: crypto.createHash('sha256').update(material).digest('hex'),
      decisions: Array.isArray(result.renderDecisions) ? result.renderDecisions.length : 0
    };
  } catch (error) {
    return {
      kind: 'rejected',
      name: error?.name || 'Error',
      digest: crypto.createHash('sha256').update(String(error?.message || error)).digest('hex')
    };
  }
}

const first = outcome();
const second = outcome();
if (JSON.stringify(first) !== JSON.stringify(second)) {
  console.error(JSON.stringify({ deterministic: false, first, second }));
  process.exit(3);
}
console.log(JSON.stringify({ deterministic: true, outcome: first }));
