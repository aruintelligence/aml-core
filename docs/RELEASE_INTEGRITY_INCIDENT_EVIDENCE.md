# Release incident evidence

When a modeled release-integrity trigger is observed, `scripts/build-release-incident-evidence.mjs` can preserve the observed JSON bytes by SHA-256, bind the trigger to the response actions required by `compromise-response-contract.json`, and produce an incident root.

This evidence is intentionally descriptive and project-controlled. It does not revoke an npm token, remove a registry artifact, rotate a production key, or claim external containment. Those actions remain external operational responsibilities. The project contract forbids rewriting a published artifact during response and requires fresh integrity verification before recovery.
