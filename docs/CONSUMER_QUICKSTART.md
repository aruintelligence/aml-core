# Five-minute installed-package quickstart

This path starts in a fresh consumer directory with only the installed `aml-core` package. It reproduces one ALLOW and one SUPPRESS decision, saves a receipt, and verifies it through the API and CLI. Node 18 or newer is required.

**Registry status:** Public npm publication of the canonical package has not been verified. Do not assume `npm install aml-core` retrieves the project artifact. [Issue #59](https://github.com/aruintelligence/aml-core/issues/59) tracks ownership, publication, and independent install verification. Until then, build a tarball from the stable tag or use an audited release artifact whose origin and integrity you have checked.

## 1. Rehearse an installation outside the repository

From a parent directory, use the stable `v1.3.0` tag and install its local tarball into a separate consumer project:

```bash
git clone --branch v1.3.0 --depth 1 https://github.com/aruintelligence/aml-core.git
(cd aml-core && npm pack --ignore-scripts)
mkdir aml-consumer-demo
cd aml-consumer-demo
npm init -y
npm install --ignore-scripts ../aml-core/aml-core-1.3.0.tgz
```

This is a package rehearsal, not evidence of a published registry package. Record the tag, tarball checksum, and Node version if you share a result. The stable `v1.3.0` tag resolved to commit `7c5f2ad4008fb62f6f80fac39e8e8926fdd80711` when this guide was checked; compare that target before relying on the tag. CI also packs that exact commit and runs the example below from a clean consumer directory on Node 18 and 24. A preview checkout from `main` is a different artifact even while its package metadata says `1.3.0`; identify its exact commit and keep it separate from stable claims.

## 2. Run a self-contained API example

Save this as `quickstart.mjs` in `aml-consumer-demo` and run `node quickstart.mjs`:

```js
import assert from "node:assert/strict";
import fs from "node:fs";
import { executeAccountableIntent, verifyExecutionReceipt } from "aml-core";

const intent = {
  transmission: "consumer_quickstart",
  nodes: [
    { type: "message", identifier: "pressure", properties: {
      purpose: "Create urgency", content: "Act now",
      attention_cost: 5, restoration_value: 1
    } },
    { type: "message", identifier: "continue", properties: {
      purpose: "Let the person continue", content: "Continue",
      attention_cost: 1, restoration_value: 3
    } }
  ]
};
const receipt = executeAccountableIntent(intent, {
  profile: "calm_default", context: {}, timestamp: "2030-01-01T00:00:00.000Z"
});
const verification = verifyExecutionReceipt(receipt);
assert.equal(receipt.selected_render.allowed, 1);
assert.equal(receipt.selected_render.suppressed, 1);
assert.equal(verification.verified, true);

fs.writeFileSync("intent.json", `${JSON.stringify(intent, null, 2)}\n`);
fs.writeFileSync("context.json", "{}\n");
fs.writeFileSync("receipt.json", `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify({
  allowed: receipt.selected_render.allowed,
  suppressed: receipt.selected_render.suppressed,
  receipt_sha256: receipt.receipt_sha256,
  verified: verification.verified
}, null, 2));
```

Expected counts are `allowed: 1`, `suppressed: 1`, and `verified: true`. Open `receipt.json` to inspect the source intent, selected policy, decisions, output hash, audit stream, and integrity bindings. This is project-authored reproducibility evidence, not an independent certification. The repository keeps the same runnable [consumer example](../examples/consumer/quickstart.mjs).

## 3. Exercise the installed CLI

From the same consumer directory:

```bash
npm exec -- aml execute intent.json calm_default context.json cli-receipt.json
npm exec -- aml verify-receipt cli-receipt.json
```

The verifier should report `verified: true` and exit successfully. The CLI execution uses the current time, so its receipt hash will differ from the API example's fixed-time receipt. Both should have one allowed and one suppressed decision. For a negative check, change a decision in a copy of a receipt and verify that `verified` becomes false with a nonzero CLI exit code.

## 4. Choose the correct release boundary

`v1.3.0` is the stable package and CLI contract. `v1.4.0-rc.2` is a GitHub prerelease snapshot of the broader architecture. The preview adds tools such as `aml-doctor`; that executable is not part of the stable `v1.3.0` package. Do not equate a tarball rehearsal, CI run, doctor result, or project-maintained demonstration with independent adoption. Share the exact artifact, commands, environment, receipt hash, and PASS / FAIL / MIXED result so another engineer can reproduce it.
