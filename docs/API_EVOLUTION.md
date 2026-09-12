# ĀML API evolution

ĀML maintains an explicit protected consumer surface for shelf-readiness work.

The protected names are declared in `api-stability.json`. `api-surface.snapshot.json` binds that ordered set to a SHA-256 digest, and `api-deprecations.json` records intentional deprecations. CI rejects silent drift, duplicate protected exports, invalid deprecation entries, and protected removals targeted at a non-major release relative to the current stable contract.

This does not freeze every experimental or preview API forever. It creates a reviewable boundary for the consumer-facing names the project currently promises to preserve.

For a protected export to be removed from a published stable package, the intended path is: deprecate it, document a replacement or reason, provide migration guidance, and remove it only in a later SemVer major release.

These controls are project-maintained engineering policy. They are not an independent compatibility certification or a guarantee that unreleased preview behavior will never change.
