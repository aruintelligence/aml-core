# Verify an ĀML™ Build

ĀML filesystem builds contain `build_manifest.json`, a SHA-256 manifest binding the original source path to the emitted HTML and accountability artifacts.

ĀML v1.1 can now actively verify that bundle.

## CLI

```bash
node bin/aml.js verify dist/build_manifest.json
```

Successful verification prints a `PASS` line for the source and each artifact and exits with status `0`.

If a file is missing, its byte count changes, or its SHA-256 digest no longer matches the manifest, verification reports `FAIL` and exits non-zero.

## Programmatic API

```js
import { verifyBuildManifest } from "./index.js";

const result = verifyBuildManifest("dist/build_manifest.json");

if (!result.verified) {
  console.error(result.checks.filter(check => !check.ok));
}
```

The result includes:

- overall `verified` state;
- passed and failed counts;
- one check per source/artifact;
- expected and actual SHA-256 values;
- expected and actual byte counts;
- failure reason such as `missing`, `sha256-mismatch`, or `byte-count-mismatch`.

## Tamper-detection test

The automated suite performs both sides of the integrity contract:

1. compile a clean AML bundle and verify it successfully;
2. modify the emitted `index.html` after compilation;
3. verify again and require a SHA-256 mismatch.

This makes build integrity executable rather than merely documented.

## CI

The GitHub Actions pipeline compiles a fresh AML program and immediately executes `aml verify` against the resulting manifest. Integrity verification therefore participates in the same required pipeline as tests, compiler smoke checks, semantic lint, browser parity, and benchmark execution.

## Security boundary

Hash verification detects changes relative to the recorded manifest. It does not authenticate who created the manifest. Cryptographic signing and external attestations are separate future layers.
