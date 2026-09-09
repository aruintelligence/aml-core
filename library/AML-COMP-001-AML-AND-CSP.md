# AML-COMP-001 — ĀML and Content Security Policy

**Status: SHIPPED comparison paper**

Content Security Policy (CSP) and ĀML address different layers.

| Question | CSP | ĀML prototype |
|---|---|---|
| Which resource origins may load? | Primary concern | Not primary concern |
| Can inline/script behavior be restricted? | Yes, within CSP model | Not CSP replacement |
| Why is this interface element being shown? | Usually outside scope | Declared meaning is central |
| Can a render decision produce a receipt? | Not CSP's role | Yes, prototype supports receipts |
| Can a semantic change be reviewed in CI? | Not its main purpose | Meaning Gate explores this |

The technologies are complementary. A secure application could use CSP to constrain resource execution while using ĀML to evaluate declared interface meaning before human-facing output.

ĀML should not be described as a security replacement for CSP. CSP is mature browser security infrastructure. ĀML is a working research prototype focused on an accountability layer at the interface boundary.
