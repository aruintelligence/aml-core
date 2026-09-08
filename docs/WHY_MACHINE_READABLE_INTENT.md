# Why Machine-Readable Intent Matters

Interfaces already contain intent, but much of it lives in names, comments, tickets, design files, analytics plans, or the heads of the people who built the product.

ĀML™ experiments with making intent part of the executable source representation.

## From implicit to explicit

Instead of treating purpose as external documentation, an ĀML element can carry fields that describe why it exists and how it should be evaluated.

That matters because machine-readable intent can survive into compiler artifacts and policy evaluation.

## Potential benefits

Machine-readable intent can support:

- stronger automated testing
- policy comparison
- auditable AI-generated UI
- provenance-aware interfaces
- accessibility analysis
- explicit attention budgeting
- reproducible render decisions
- tooling that reasons over purpose instead of only structure

## What this does not solve

Declared intent can be incomplete, wrong, or dishonest. A schema cannot guarantee that an author tells the truth. It can, however, create a place where intent must be stated, inspected, versioned, and compared with behavior.

That is a meaningful shift from interfaces where purpose is often absent from the executable artifact entirely.

## ĀML's current implementation

The compiler turns `.aml` source into structural and meaning artifacts before policy-aware rendering. The resulting decision record makes the gate outcome inspectable alongside final browser output.

Live lab: https://aruintelligence.github.io/aml-core/

Source: https://github.com/aruintelligence/aml-core
