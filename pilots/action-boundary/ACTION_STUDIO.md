# Action Boundary Studio

[Open the interactive Studio](https://aruintelligence.github.io/aml-core/action-boundary-studio.html) and edit both JSON inputs. The browser computes the reference subset's canonical proposal, SHA-256 digest, exact rule decision, and reason. Presets cover a matching send that needs approval, a changed destination, a changed body on the same route, an allowed read, and duplicate rules. All inputs stay in the browser; the page invokes no tool.

The Studio uses `docs/action-lab-core.js`, a project-authored browser mirror of `boundary.mjs`. The Node verifier uses `planAction` from that reference module, not the browser calculation. Download a bundle and run:

```bash
node scripts/verify-action-studio-bundle.mjs aml-action-studio-bundle.json
node scripts/verify-action-studio-bundle.mjs examples/action-studio/changed-destination.json
```

It exits zero for a consistent calculation and nonzero for a malformed or mismatched record. The checked-in example is generated from the published action vectors with `node scripts/build-action-studio-example.mjs`; CI runs `--check` and the mutation tests.

## Bundle contract

`aml-action-studio-bundle/1` contains `proposal`, `policy`, a four-field `plan`, and `canonical_proposal_json`. The verifier validates the fixed bundle and plan shapes, recomputes the plan against **the policy inside that same bundle**, and compares the canonical proposal bytes. If a proposal or policy is invalid under the reference subset, the plan denies with a null digest and null canonical proposal. Broken editor JSON cannot be exported.

This is a **consistency check**, not an authenticated record: someone can alter both inputs and recompute a matching bundle. The `source` string is descriptive, not a signature. A real host must independently establish the tool and destination, own the policy and approval flow, bind approval to the digest, control the callback, and keep audit evidence. `allow` describes a policy result only. `requires_approval` still needs a later trusted host action. No browser action or verifier result proves consent, tool execution, or delivery.

The exact rule tuple is `tool + effect + resource`, with no wildcard or prefix match. It does not constrain an argument body on its own. If body content needs approval, use a trusted approval tied to the proposal digest or a stricter host-specific rule. See [Policy X-ray](POLICY_SCOPE.md) for the executable same-route counterexample and the [boundary README](README.md) for full contract limits.

MCP Apps describes a host-mediated view-to-tool path and host-managed OAuth for protected tools; this workbench is a standalone design aid, not an MCP App or an implementation of its authentication. A2UI actions likewise require a host integration outside this page. See [MCP Apps overview](https://apps.extensions.modelcontextprotocol.io/api/documents/overview.html) and [authorization](https://apps.extensions.modelcontextprotocol.io/api/documents/authorization.html).
