# AML Verifier Implementation Claims

**SHIPPED prototype contract.**

`aml-verifier-implementation-claim/1` lets a verifier declare exactly which immutable AML verifier contract snapshot it targets.

A claim includes:

- implementation ID and version;
- runtime;
- public source URL;
- contract snapshot ID;
- immutable contract source commit;
- supported artifact type;
- black-box conformance command;
- whether the implementation is maintained outside `aml-core`;
- optional public conformance-result URL.

## Important distinction

A claim is a declaration.

A conformance result is observed behavior.

A witness record is public reproduction evidence.

These are deliberately separate objects.

```text
implementation claim
      ↓
black-box test
      ↓
conformance result
      ↓
public outside reproduction
      ↓
witness record
```

Never convert a self-declared claim into an external witness automatically.

## Generate a claim

```bash
node scripts/create-verifier-implementation-claim.mjs \
  --implementation-id my-verifier \
  --implementation-version 0.1.0 \
  --runtime go1.24 \
  --source-url https://github.com/example/my-verifier \
  --command './my-verifier --now 2030-01-01T00:05:00Z bundle.json' \
  --external true
```

## Claim boundary

This mechanism records compatibility intent. It does not certify security, organizational independence, identity, correctness, trademark authorization, or regulatory compliance.
