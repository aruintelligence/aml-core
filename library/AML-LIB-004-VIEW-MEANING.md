# AML-LIB-004 — View Meaning

**Status: SHIPPED**

The web gave developers View Source. ĀML explores **View Meaning**.

Source code can tell you what software is capable of doing. A generated interface still leaves another question: what did the system declare this particular interface element was trying to do when it rendered?

View Meaning is the inspection surface for that layer.

A View Meaning report can expose:

- declared purpose
- attention cost
- restoration value
- selected policy/profile
- consent and privacy context where present
- accessibility context where present
- ALLOW or SUPPRESS outcome
- rationale
- receipt integrity

The point is not to replace source inspection. It is to make semantic execution evidence inspectable alongside it.

## Try it

https://aruintelligence.github.io/aml-core/view-meaning.html

A useful future test is whether a reviewer can answer “why did the user see this?” without reverse-engineering a model prompt, application state, and frontend implementation after the fact.

View Meaning does not prove hidden intent. It exposes declared meaning and recorded decision evidence.
