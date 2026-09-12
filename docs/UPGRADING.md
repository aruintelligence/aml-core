# Upgrading AML

AML separates the stable package contract from preview architecture work. The canonical machine-readable upgrade rules live in [`upgrade-contract.json`](../upgrade-contract.json), while protected consumer exports live in [`api-stability.json`](../api-stability.json).

## Stable release discipline

For a published stable package, patch releases are for compatible fixes and hardening, minor releases are for backward-compatible additions, and intentional breaking changes belong in a major release with migration guidance. Security or correctness emergencies may require faster action, but those exceptions must be explicit rather than silent.

Preview releases may evolve before they become stable. A prerelease tag is not a promise that every preview behavior is frozen.

## What CI protects

`npm run api:stability` verifies that every protected API still exists at runtime and still has a first-party TypeScript declaration. `npm run upgrade:check` verifies release metadata and the migration-note requirement. The enterprise-readiness workflow also generates a CycloneDX 1.5 SBOM artifact for the package manifest.

## Migration notes

When a future stable release intentionally removes or changes a protected API, the release should identify the old API, the replacement or changed behavior, the first affected release, and the minimum migration steps. The API contract should only be changed in the same reviewed release change that contains that migration guidance.

These are project-maintained release-engineering controls. They are not an SLA, warranty, certification, or claim that AML is a ratified standard.
