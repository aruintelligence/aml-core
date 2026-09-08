# ĀML in One Page

**Status: SHIPPED**

## The problem

AI can generate interface output faster than people can review why it appeared, what it was trying to do, or what rules governed it.

## The idea

ĀML is an **interface firewall** between AI/app intent and pixels.

The prototype asks each interface element to carry declared meaning, including purpose, attention cost, and restoration value.

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

If the declared restoration value is lower than the declared attention cost, the reference policy suppresses the element. If it meets or exceeds the cost, the element can render.

## Why this matters

The output is not just ALLOW or SUPPRESS. ĀML can produce a **receipt** showing what was declared and why the decision happened.

That creates a review path:

```text
AI/app intent
  ↓
ĀML declaration
  ↓
policy decision
  ↓
pixels or suppression
  ↓
receipt
  ↓
View Meaning
```

## Try it

SUPPRESS:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

ALLOW:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=5&lang=en

## What ĀML is not

ĀML is not a claim that attention or restoration are objectively solved human-science measurements. It is not a ratified global standard. It does not make AI intent truthful. It does not guarantee legal or accessibility compliance.

It is a working prototype for making interface decisions **inspectable, reproducible, and challengeable**.

Repository: https://github.com/aruintelligence/aml-core

Open the proof. Change `restoration_value`. Screenshot the decision and receipt. File what happened.
