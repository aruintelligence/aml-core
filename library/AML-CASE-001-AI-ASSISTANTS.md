# AML-CASE-001 — AI Assistants

**Status: DRAFT casebook built on SHIPPED AML primitives**

AI assistants increasingly generate interface behavior, not just sentences: suggested actions, follow-up prompts, permission requests, upgrade offers, and task-completion controls.

## Where an interface firewall can help

A product team could place ĀML around assistant-generated UI regions and require explicit declared meaning for elements before rendering.

Example cases:

1. Helpful next-step suggestion — low attention cost, useful restoration value → ALLOW.
2. Repeated upgrade nag — higher attention cost, low restoration value → SUPPRESS under the prototype rule.
3. Request for personal data — attach consent/privacy context for review.
4. Tool action confirmation — preserve a receipt explaining why the action control appeared.
5. Dynamic assistant panel — use a strict AML zone so undeclared top-level UI is hidden rather than silently displayed.

## What this does not prove

ĀML cannot know whether the assistant's declared purpose is truthful. It does not guarantee safety or legal compliance. The casebook shows where an inspectable decision boundary may be useful.

**This casebook is not evidence of AI-assistant adoption. It describes a proposed application area for public testing.**

Try the public proof:
https://aruintelligence.github.io/aml-core/proof.html
