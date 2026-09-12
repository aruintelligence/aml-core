# ĀML supportability bundle

Enterprise support needs a compact way to answer a basic question: **what exactly is installed, healthy, and contract-bound in this environment?**

`aml-support-bundle` generates a deterministic JSON support artifact containing:

- package name and version;
- Node.js version, operating system, and architecture;
- the complete `aml-doctor` result;
- presence, byte size, and SHA-256 digest for the project/package/API/upgrade/security/evidence contracts used by the installed checkout;
- one aggregate SHA-256 digest over that contract set.

The bundle deliberately does **not** copy contract file contents, environment variables, credentials, or private keys. `generated_at` is intentionally null so repeated generation against unchanged inputs remains deterministic.

Run:

```bash
aml-support-bundle
```

or write the artifact to disk:

```bash
aml-support-bundle aml-support-bundle.json
```

A healthy support bundle is useful for support tickets, deployment records, upgrade comparisons, incident triage, and verifying that two environments are actually using the same declared contract set.

It is local diagnostic evidence only. It does not prove npm publication, independent validation, certification, standards status, organizational identity, or production suitability.
