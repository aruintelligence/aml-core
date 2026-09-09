# AML-EXEC-001 — Executive Brief

**Status: SHIPPED**

## The problem

AI can increasingly decide what a person sees at runtime. Existing frontend controls do not always preserve why a generated interface element appeared, which policy governed it, or what evidence survives after the screen changes.

## The AML proposal

ĀML is an **interface firewall** between AI/app intent and pixels.

A generated element can declare purpose and policy-relevant values, pass through an ALLOW/SUPPRESS decision, and produce a receipt that can be inspected and reproduced.

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

The values are declared/model inputs—not objective scientific measurements.

## Why evaluate it

- generated UI can outrun manual review
- receipts create an audit artifact
- View Meaning exposes the recorded rationale
- Meaning Gate moves semantic review into CI
- existing HTML/React stacks do not need to be replaced
- a small pilot can test the concept without committing to a platform migration

## Lowest-risk pilot

One AI-generated interface region. One policy. Five ALLOW fixtures. Five SUPPRESS fixtures. One deterministic replay. One receipt review.

Pilot kit:
https://github.com/aruintelligence/aml-core/tree/main/pilots/enterprise-30min

Commercial, OEM, enterprise, and strategic inquiries:
Office@aruintelligence.com

ĀML is a working research prototype, not a ratified global standard and not a compliance guarantee.
