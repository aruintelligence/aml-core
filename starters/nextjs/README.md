# ĀML Next.js example

A runnable App Router example that evaluates machine intent on the server, renders a known React component for an allowed decision, and displays a policy-suppressed fallback for an urgency prompt. The full accountable execution receipt is available as JSON, with a View Meaning page and a semantic diff from the baseline intent.

## Run from a clone of aml-core

Requires Node.js 20.9 or newer (Node 24 is used in CI). From the repository root:

```bash
cd starters/nextjs
npm install --ignore-scripts
npm test
npm run dev
```

Open <http://localhost:3000>, then inspect `/meaning` and `/api/receipt`. `npm run build && npm start` rehearses the production server. The `file:../..` dependency installs the local repository package; it does not assume that `aml-core` has been published to a registry. Keep the package, example, and tests at the same commit.

The server constructs `candidateIntent` in `lib/demo.mjs`, enforces the `calm_default` profile, and verifies the receipt before responding. The urgency node is suppressed, while the calm continuation appears. The page maps allowed decisions to application-owned React components and lets React escape displayed text. It does not inject the generated AML HTML.

The example's `/api/receipt` endpoint is deliberately public and contains only a fixed demonstration fixture. In a real app, authenticate and authorize receipt access, avoid exposing private context, validate machine intent, choose policy and context on the server, and keep ordinary Next.js/XSS controls. AML checks declared meaning; it does not prove that the declaration matches the UI or sanitize untrusted HTML.

## Meaning Gate in CI

The root [Next.js example workflow](../../.github/workflows/nextjs-example.yml) builds the app, exercises the receipt endpoint, and runs the repository Meaning Gate against `fixtures/before.aml` and `fixtures/after.aml`:

```bash
node scripts/meaning-gate.js starters/nextjs/fixtures/before.aml starters/nextjs/fixtures/after.aml calm_default calm_default
```

Replace these committed example snapshots with the before/after AML produced by your own interface changes. The fixture edit changes copy while preserving purpose and policy behavior. The on-page semantic diff separately shows the added urgency node in the demonstrated machine intent.
