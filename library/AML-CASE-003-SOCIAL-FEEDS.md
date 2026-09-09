# AML-CASE-003 — Social Feeds

**Status: DRAFT casebook built on SHIPPED AML primitives**

Social feeds compete continuously for user attention. Generated recommendations, notification prompts, autoplay units, ranking explanations, and engagement nudges can all appear dynamically.

## Candidate AML controls

- gate autoplay interruptions
- inspect notification nags
- attach purpose to recommended modules
- preserve receipts for dynamic feed insertions
- compare attention cost across a session
- allow calm navigation and status information
- use Meaning Gate to catch semantic changes in engagement UI

A useful experiment is cumulative rather than single-element: how much declared attention cost has a session accumulated, and which generated elements were suppressed after policy thresholds were reached?

ĀML already contains a cumulative attention ledger prototype, but its values remain declared/model inputs rather than objective measurements of human attention.

The case for the firewall is not anti-feed or anti-recommendation. It is pro-inspectability at the human-interface boundary.

Repository:
https://github.com/aruintelligence/aml-core
