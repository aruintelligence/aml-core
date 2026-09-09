# ĀML Publications

**Status: SHIPPED public reading room**

ĀML is an interface firewall between AI/app intent and pixels. This page is the shortest route to the public material explaining why it exists, how to try it, where it fits, and how to challenge it.

## Start here

1. [Start Here — ĀML in 5 minutes](publications/START_HERE.md)
2. [ĀML in one page](publications/AML_IN_ONE_PAGE.md)
3. [ĀML Library — numbered papers, casebooks, comparisons, and 100 use cases](library/README.md)
4. [Claims Ledger — what is SHIPPED, SPEC, DRAFT, or PITCH](CLAIMS.md)
5. [Proof Map — claim → shortest evidence path](publications/PROOF_MAP.md)
6. [Evaluate ĀML in 15 minutes](publications/EVALUATE_AML_IN_15_MINUTES.md)
7. [Deploy ĀML without breaking production](publications/DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md)
8. [Security hardening bulletin — September 8, 2026](publications/SECURITY_HARDENING_BULLETIN_2026-09-08.md)
9. [Meaning Fingerprint — deterministic AMT identity](publications/MEANING_FINGERPRINT.md)
10. [Why AI-generated UI needs a firewall](publications/WHY_AI_UI_NEEDS_A_FIREWALL.md)
11. Live proof: https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en
12. View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

## Trust the evidence, not the volume

The publication system now has a machine-readable [claims ledger](claims.json). A claim labeled **SHIPPED** in that ledger must point to repository evidence. The CI claims guard rejects unsupported SHIPPED claims.

Useful trust surfaces:

- [Public Claims Ledger](CLAIMS.md)
- [Machine-readable claims ledger](claims.json)
- [Proof Map](publications/PROOF_MAP.md)
- [15-minute evaluation path](publications/EVALUATE_AML_IN_15_MINUTES.md)
- [Deployment rollout brief](publications/DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md)
- [Security hardening bulletin — September 8, 2026](publications/SECURITY_HARDENING_BULLETIN_2026-09-08.md)
- [Meaning Fingerprint — deterministic AMT identity](publications/MEANING_FINGERPRINT.md)
- [Press fact sheet](publications/PRESS_FACT_SHEET.md)
- [Category brief — interface accountability](publications/CATEGORY_BRIEF.md)
- [Buyer decision tree](publications/BUYER_DECISION_TREE.md)

## ĀML Library

The [ĀML Library](library/README.md) is the stable, numbered publication shelf. Each item has a library ID and an explicit status/claim boundary.

### Numbered papers

- [AML-LIB-001 — The Interface Firewall](library/AML-LIB-001-THE-INTERFACE-FIREWALL.md)
- [AML-LIB-002 — Receipts for Generated Interfaces](library/AML-LIB-002-RECEIPTS-FOR-GENERATED-INTERFACES.md)
- [AML-LIB-003 — Why Generated UI Needs a Decision Boundary](library/AML-LIB-003-WHY-GENERATED-UI-NEEDS-A-DECISION-BOUNDARY.md)
- [AML-LIB-004 — View Meaning](library/AML-LIB-004-VIEW-MEANING.md)
- [AML-LIB-005 — Meaning Gate](library/AML-LIB-005-MEANING-GATE.md)
- [AML-LIB-006 — Reproducible Interface Decisions](library/AML-LIB-006-REPRODUCIBLE-INTERFACE-DECISIONS.md)
- [AML-LIB-007 — Independent Verification](library/AML-LIB-007-INDEPENDENT-VERIFICATION.md)
- [AML-LIB-008 — The Case for Declared Interface Intent](library/AML-LIB-008-DECLARED-INTERFACE-INTENT.md)

### Industry casebooks

- [AI assistants](library/AML-CASE-001-AI-ASSISTANTS.md)
- [E-commerce](library/AML-CASE-002-E-COMMERCE.md)
- [Social feeds](library/AML-CASE-003-SOCIAL-FEEDS.md)
- [Health interfaces](library/AML-CASE-004-HEALTH-INTERFACES.md)
- [Financial interfaces](library/AML-CASE-005-FINANCIAL-INTERFACES.md)
- [Education](library/AML-CASE-006-EDUCATION.md)

Casebooks are proposed application areas unless independent evidence is explicitly linked. They are not claims of industry adoption.

### Comparisons and adoption catalog

- [ĀML and Content Security Policy](library/AML-COMP-001-AML-AND-CSP.md)
- [ĀML and consent banners](library/AML-COMP-002-AML-AND-CONSENT-BANNERS.md)
- [ĀML and general policy engines](library/AML-COMP-003-AML-AND-POLICY-ENGINES.md)
- [100 Ways to Use an Interface Firewall](library/AML-100-WAYS-TO-USE-AN-INTERFACE-FIREWALL.md)
- [Executive brief](library/AML-EXEC-001-EXECUTIVE-BRIEF.md)
- [Citation rules](library/CITATION.md)
- [Machine-readable catalog](library/catalog.json)

## By audience

- Developers: [Developer integration brief](publications/DEVELOPER_INTEGRATION_BRIEF.md)
- AI product leaders: [AI product leader brief](publications/AI_PRODUCT_LEADER_BRIEF.md)
- Designers: [Designer brief](publications/DESIGNER_BRIEF.md)
- Security and privacy teams: [Security/privacy brief](publications/SECURITY_PRIVACY_BRIEF.md)
- Researchers and standards engineers: [Research/standards brief](publications/RESEARCH_STANDARDS_BRIEF.md)
- Enterprise evaluators: [Enterprise buyer brief](publications/ENTERPRISE_BUYER_BRIEF.md)
- Platform/release teams: [Deploy ĀML without breaking production](publications/DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md)
- Media/podcasts: [Media brief](publications/PODCAST_MEDIA_BRIEF.md)

## Core explainers

- [Why teams might try ĀML](publications/WHY_TEAMS_TRY_AML.md)
- [Dark-pattern casebook](publications/DARK_PATTERN_CASEBOOK.md)
- [Receipt anatomy](publications/RECEIPT_ANATOMY.md)
- [View Meaning explainer](publications/VIEW_MEANING_EXPLAINER.md)
- [Meaning Gate explainer](publications/MEANING_GATE_EXPLAINER.md)
- [Meaning Fingerprint](publications/MEANING_FINGERPRINT.md)
- [Fair comparison landscape](publications/COMPARISON_LANDSCAPE.md)
- [Executive FAQ](publications/FAQ_EXECUTIVE.md)
- [Buyer objections — answered without hype](publications/BUYER_OBJECTIONS.md)
- [A critic's guide to ĀML](publications/CRITICS_GUIDE.md)

## Ready-to-publish distribution assets

- [20-post launch pack](publications/20_POST_LAUNCH_PACK.md)
- [10 outreach emails](publications/EMAIL_OUTREACH_10.md)
- [Conference talk proposal](publications/CONFERENCE_TALK.md)
- [Media/podcast brief](publications/PODCAST_MEDIA_BRIEF.md)
- [Launch release draft](publications/LAUNCH_RELEASE.md)

## Product truth

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

The scores are declared/model inputs. ĀML is a working research prototype, not a ratified global standard. Code is MIT licensed; official marks are separate.

## Fastest skeptical path

- Try the proof.
- Change one value.
- Inspect the receipt.
- Run the 10-minute reproduction.
- Verify an artifact without trusting the original page.
- Run the deployment rollout example in shadow/canary/enforce modes.
- Check the claim against `CLAIMS.md`.
- Publish disagreement if you find it.

**Witness ask:** Open the proof. Change `restoration_value`. Screenshot the decision and receipt. File what happened.
