# Enterprise Buyer Brief

**Status: SHIPPED**

ĀML is not a replacement for your frontend stack. It is a control layer that can sit between generated interface intent and user-facing output.

A sensible enterprise pilot is narrow:

1. choose one generated UI region;
2. declare purpose, attention cost, and restoration value;
3. enforce ALLOW/SUPPRESS decisions;
4. inspect receipts;
5. replay the same decision;
6. decide whether the added accountability is operationally useful.

What to evaluate:

- integration friction
- quality of review evidence
- reproducibility
- policy clarity
- developer ergonomics
- audit usefulness

What not to assume:

- no legal-compliance guarantee
- no objective human-wellbeing metric
- no standards-body certification
- no automatic official-brand authorization

30-minute pilot:
https://github.com/aruintelligence/aml-core/tree/main/pilots/enterprise-30min

Local signed HTTP render gate pilot (thirteen asserted outcomes, including tampering, untrusted signers, replay, and service failure):
https://github.com/aruintelligence/aml-core/tree/main/pilots/enterprise-http-gate

The same pilot now includes a 14-case adversarial comparison of a deliberately unsafe host and the verified gate, with callback counts and HTML hashes in a CI artifact. This is project-authored engineering evidence, not an independent security review.

Local screen pilot (verified allowed HTML reaches an isolated frame; missing consent leaves it empty). You can supply one local intent JSON and a separate host-owned context JSON to try your own proposed interface:
https://github.com/aruintelligence/aml-core/tree/main/pilots/enterprise-screen

Partnership/OEM inquiries: Office@aruintelligence.com
