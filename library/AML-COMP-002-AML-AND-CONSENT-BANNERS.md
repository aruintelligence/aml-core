# AML-COMP-002 — ĀML and Consent Banners

**Status: SHIPPED comparison paper**

Consent banners and ĀML solve different problems.

A consent banner usually asks for or records permission around categories of processing or storage. ĀML explores whether a particular interface element should render under declared meaning and runtime policy context.

| Question | Consent banner | ĀML prototype |
|---|---|---|
| Ask for permission | Often | Can consume consent context |
| Store consent state | Often | Prototype includes consent ledger mechanisms |
| Explain why a specific generated UI element appeared | Usually not | Core use case |
| ALLOW/SUPPRESS individual interface output | Usually not | Yes, under selected policy |
| Produce execution receipt | Usually not | Yes |

ĀML does not replace consent-management systems and does not guarantee privacy-law compliance. It can potentially consume consent state as one input to an interface decision and preserve evidence of how that state affected rendering.

The useful distinction: **consent answers whether permission exists; an interface firewall can additionally ask what should be shown under that context.**
