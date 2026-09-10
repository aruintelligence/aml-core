# ĀML™ Is Here: An Accountability Layer for AI-Generated Interfaces

**ĀML™ — ĀRU Meaning Language™** is a working research prototype for meaning-native, policy-aware, accountable AI interfaces.

> **HTML tells the browser what to display. ĀML tells the system why it deserves to be displayed.**

AI systems can generate interfaces, messages, offers, workflows, recommendations, and calls to action at machine speed. Existing web stacks are excellent at rendering those outputs. They are much less equipped to expose the declared purpose, policy context, authority, consent state, privacy implications, accessibility context, decision rationale, and evidence behind them.

ĀML explores a layer between machine intent and human-facing output: an **AI Interface Firewall™**.

## This is not a concept-only page

The repository already contains a working implementation and public evidence surfaces including:

- lexer/parser, AST, and Abstract Meaning Tree
- deterministic machine-intent → ĀML generation
- semantic and policy diffs
- consent-, privacy-, accessibility-, and attention-aware policy inputs
- allow/suppress render decisions
- execution receipts and signed receipts
- audit streams, provenance graphs, and verification tooling
- policy packs, capability negotiation, trust delegation, revocation, and threshold authorization primitives
- zero-install `<aml-gate>` browser bridge
- existing-HTML `data-aml-*` bridge
- **View Meaning™** inspection tooling
- **Meaning Gate™** GitHub Action
- dependency-free HTTP evaluation service
- public RFCs, schemas, protocol vectors, conformance fixtures, publications, and an enterprise pilot kit

These are repository capabilities, not claims of global adoption or standardization.

## The 60-second proof

Open:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

The prototype evaluates a declared rule:

```text
render_allowed = restoration_value >= attention_cost
```

Change `restoration_value` from `1` to `5` and inspect the decision and receipt.

The values are declared/model inputs. They are not objective measurements of cognition, wellbeing, or human worth.

## The question ĀML is forcing into the open

As AI-generated UI becomes more dynamic and individualized, the number of possible interface states can grow faster than traditional human review can inspect them.

That creates a new engineering question:

**How do we make generated interface behavior inspectable, testable, governable, and independently verifiable before and after rendering?**

ĀML is one concrete answer being built in public.

## Start by audience

**Developers:** `publications/DEVELOPER_INTEGRATION_BRIEF.md`, `docs/TRY_AML_10_MINUTES.md`, `API.md`, `docs/AML_GATE_ELEMENT.md`, `docs/HTML_BRIDGE.md`

**AI product teams:** `publications/AI_PRODUCT_LEADER_BRIEF.md`, `publications/WHY_AI_UI_NEEDS_A_FIREWALL.md`, `publications/VIEW_MEANING_EXPLAINER.md`

**Security / privacy / governance:** `SECURITY.md`, `SECURITY_THREAT_MODEL.md`, `VERIFY.md`, `CLAIMS.md`, `claims.json`

**Researchers / standards engineers:** `STANDARDIZATION.md`, `ECOSYSTEM.md`, `rfcs/README.md`, `publications/RESEARCH_STANDARDS_BRIEF.md`, `publications/EXTERNAL_VERIFIER_CHALLENGE.md`

**Enterprise evaluators:** `publications/EVALUATE_AML_IN_15_MINUTES.md`, `pilots/enterprise-30min/`, `publications/ENTERPRISE_BUYER_BRIEF.md`, `publications/BUYER_DECISION_TREE.md`

**Media / analysts / technical writers:** `publications/PRESS_FACT_SHEET.md`, `publications/PODCAST_MEDIA_BRIEF.md`, `publications/CATEGORY_BRIEF.md`, `CITATION.cff`

## Search and discovery language

AI interface accountability · AI-generated UI governance · generative UI safety · AI interface firewall · semantic interface policy · inspectable AI UI · verifiable generated interfaces · AI UI receipts · interface provenance · AI consent enforcement · AI privacy policy enforcement · accessibility policy for generated UI · semantic diff for AI interfaces · policy-aware rendering · machine-generated interface audit · View Meaning · Meaning Gate · ĀRU Meaning Language · AML interface language

These phrases describe the problem space and repository capabilities; they are not assertions of market leadership or external adoption.

## Do not trust the pitch — test the system

1. Open the proof.
2. Change the inputs.
3. Inspect the decision.
4. Reproduce it locally.
5. Verify the receipt.
6. Read the claims ledger.
7. Try to break the assumptions.
8. Publish what you find.

If ĀML is useful, build with it.

If ĀML is wrong, show exactly where.

If the category is real, help define it in public.

## Project status

- Stable package/CLI/capability contract: `v1.3.0`
- Current broader architecture prerelease on `main`: `v1.4.0-rc.2`
- Code license: MIT
- Official ĀML™ / ĀRU™ marks and official authorization identity are separate from the code license

Commercial, OEM, enterprise, standards, research, media, and strategic inquiries: **Office@aruintelligence.com**

---

**ĀML™ — ĀRU Meaning Language™**  
**AI Interface Firewall™ · View Meaning™ · Meaning Gate™**
