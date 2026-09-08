# ĀML Outreach Notes — 10 Roles

**Status: DRAFT**

## 1 — Frontend framework maintainer
Subject: Can you break this interface-firewall demo?

I’m working on ĀML, a prototype interface firewall between AI/app intent and pixels. The shortest proof is here: https://aruintelligence.github.io/aml-core/playground.html

Would you spend 10 minutes trying to break the developer model or tell me what makes it too awkward for a real frontend stack?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 2 — AI product engineer
Subject: A receipt for generated UI decisions

ĀML records declared purpose, policy inputs, render decisions, and a receipt around AI-generated UI. I’m looking for someone who ships generated interfaces and can tell me where this model fails in practice.

Repo: https://github.com/aruintelligence/aml-core

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 3 — Design systems lead
Subject: Dark-pattern controls as interface metadata

I’m testing whether dark-pattern review can move from screenshots and policy docs into inspectable interface metadata. ĀML is the prototype.

Proof path: https://aruintelligence.github.io/aml-core/playground.html

Would you critique the fields and the developer ergonomics rather than the branding?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 4 — Privacy engineer
Subject: Can interface receipts improve reviewability?

ĀML is experimenting with receipts that bind declared purpose, consent/privacy context, policy decisions, and rendered output. It is not a compliance claim.

I’d value a privacy engineer trying to identify where the receipt is misleading, incomplete, or useful.

View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 5 — Accessibility engineer
Subject: Please attack the accessibility assumptions in ĀML

ĀML includes declarative accessibility checks, but explicitly does not claim to replace WCAG or assistive-technology testing.

I’d like an accessibility engineer to identify missing fields, harmful abstractions, and test cases we should publish.

Repo: https://github.com/aruintelligence/aml-core

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 6 — Security engineer
Subject: Break the AML receipt and trust model

ĀML includes signed receipts, replay guards, trust roots, revocation, and public conformance fixtures. I want independent attempts to break them.

Threat model and source: https://github.com/aruintelligence/aml-core

Please file the smallest reproducible failure you can find.

## 7 — Standards engineer
Subject: Is this interface accountability work standard-shaped yet?

ĀML has public fixtures, RFCs, schemas, protocol vectors, and conformance language, but it is not a ratified standard.

I’m looking for criticism from people who know what makes interoperability specs fail.

Repo: https://github.com/aruintelligence/aml-core

Open a fixture, reproduce it independently, and file the mismatch.

## 8 — Browser tooling developer
Subject: View Source, but for declared interface meaning

ĀML’s View Meaning prototype exposes declared purpose, policy decisions, and receipt data for an interface execution.

Inspector: https://aruintelligence.github.io/aml-core/view-meaning.html

Would you critique what belongs in a browser-facing inspector versus what should stay developer-only?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 9 — HCI researcher
Subject: Research prototype for inspectable AI-generated interfaces

ĀML is a software prototype for declaring and evaluating interface intent. Its attention/restoration values are model inputs, not validated human-science measurements.

I’d value criticism on experimental design and what evidence would be needed before making stronger human-outcome claims.

Repo: https://github.com/aruintelligence/aml-core

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 10 — Open-source maintainer
Subject: Is AML reproducible enough for an independent implementation?

I’m trying to make ĀML boringly reproducible: public fixtures, protocol vectors, conformance checks, and a tiny proof demo.

Repo: https://github.com/aruintelligence/aml-core

The ask is specific: implement one fixture without importing our runtime and file where the spec is ambiguous.
