# ĀML for AI Agents

## A policy and evidence boundary for agent-generated interfaces

AI agents can do more than answer questions. They can choose tools, assemble actions, generate interfaces, personalize options, and present decisions to people. Once an agent starts shaping the human interface, a new question appears:

> **How can another system inspect why the agent chose this interface, under which policy, and with what authority?**

ĀML™ — ĀRU Meaning Language™ — is a working research prototype for representing interface meaning, policy context, authority boundaries, decisions, provenance, and evidence in machine-readable form.

## The agentic interface problem

An agent may dynamically decide:

- which action to expose
- which option to emphasize
- what information to suppress or reveal
- whether consent is required
- whether a capability is authorized
- whether an accessibility constraint changes presentation
- whether a policy permits rendering
- whether a generated interface should be allowed at all

Rendered HTML can show the final result. It does not inherently provide a portable account of the reasoning and policy boundary that produced the result.

## A possible control path

```text
agent intent
   ↓
structured meaning
   ↓
authority + policy evaluation
   ↓
ALLOW / SUPPRESS / explanation
   ↓
receipt + provenance
   ↓
existing UI renderer
```

ĀML explores that boundary without requiring teams to abandon their existing frontend stack.

## Why receipts matter for agents

When software is deterministic and manually designed, developers can often reconstruct why a screen appeared by reading source code. With agentic systems, runtime context and model-generated choices can make that reconstruction harder.

A machine-readable receipt can preserve evidence about the decision that actually occurred.

That creates useful questions for agent developers:

1. Can the agent declare purpose separately from presentation?
2. Can policy evaluate that purpose before rendering?
3. Can authority/capability constraints be represented explicitly?
4. Can the resulting decision be reproduced?
5. Can another verifier inspect the receipt without trusting the agent that produced it?
6. Can semantic changes be detected across versions even when the visual result looks similar?

## Try the public proof

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

The reference prototype begins with a deliberately simple declared rule:

```text
render_allowed = restoration_value >= attention_cost
```

Change `restoration_value` from `1` to `5`, inspect the decision, and then reproduce it locally with [`TRY_AML_10_MINUTES.md`](../docs/TRY_AML_10_MINUTES.md).

The scores used by this prototype are declared/model inputs, not objective measurements of human cognition or wellbeing.

## Related AML work

- [AI Interface Firewall™](AI_INTERFACE_FIREWALL.md)
- [Generative UI Governance](GENERATIVE_UI_GOVERNANCE.md)
- [Public Witness Protocol](AML_WITNESS_PROTOCOL.md)
- [Claims ledger](../CLAIMS.md)
- [Security threat model](../SECURITY_THREAT_MODEL.md)

## Discovery language

This work is relevant to **AI agents, agentic UI, agent-generated interfaces, AI tool governance, AI capability boundaries, AI interface accountability, interface provenance, machine-verifiable AI actions, generative UI safety, policy-aware agents, and accountable agentic interfaces**.

These are descriptive discovery terms. They do not imply standards-body adoption or third-party endorsement.

## Evidence boundary

ĀML is a working research prototype. It should be evaluated by running its proof surfaces, inspecting its schemas and receipts, testing its conformance fixtures, and challenging its claims.

**When an agent can change the interface, the interface decision itself should become inspectable.**
