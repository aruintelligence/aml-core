# ĀML™ Build Integrity

Filesystem compilation now emits `build_manifest.json` alongside the browser and accountability artifacts.

The manifest binds one AML source file to the exact emitted outputs using SHA-256 digests.

## Emitted files

```text
index.html
tokens.json
ast.json
amt.json
render_decision.json
build_manifest.json
```

## Manifest shape

```json
{
  "protocol": "ĀML Build Manifest",
  "version": "1.1.0",
  "source": {
    "path": "examples/simple.aml",
    "sha256": "..."
  },
  "generated_at": "...",
  "render_decision_count": 1,
  "artifacts": {
    "index.html": { "sha256": "...", "bytes": 1234 }
  }
}
```

## Why this matters

A decision record is more useful when reviewers can verify that it belongs to the same source and output bundle they are examining.

The manifest supports:

- reproducible research builds;
- CI artifact verification;
- tamper detection after compilation;
- independent replication;
- provenance tracking for generated interfaces;
- future signed release or attestation systems.

## Reproducible mode

Pass a fixed timestamp to `compileAML()` to make the build metadata stable across equivalent runs:

```js
compileAML("example.aml", "dist", {
  timestamp: "2026-01-01T00:00:00.000Z"
});
```

The repository includes automated tests that recompute every manifest digest and verify it against the emitted file bytes.

## Boundary

SHA-256 integrity proves that files match the recorded build manifest. It does not prove that the policy model is correct, ethical, empirically validated, or free from malicious source input.
