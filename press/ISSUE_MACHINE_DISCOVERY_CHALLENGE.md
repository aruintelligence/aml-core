# Issue draft — discover and reproduce AML proof without scraping prose

**Status: PITCH**

## Goal

Use the reference project's machine-readable discovery surfaces to locate and reproduce an AML proof without manually reading the README.

## Start

- https://aruintelligence.github.io/aml-core/.well-known/aml.json
- https://aruintelligence.github.io/aml-core/proof-manifest.json
- https://aruintelligence.github.io/aml-core/proof-links.json

## Acceptance

- independent script/tool/runtime
- reads one of the machine documents
- discovers a proof URL
- reproduces its expected ALLOW/SUPPRESS decision
- records the exact observed result
- files any ambiguity in the discovery fields

The `.well-known/aml.json` path is experimental and is not claimed as a ratified Internet convention.
