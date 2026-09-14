# Kinthria — AML navigation experiment

Target: `https://kinthria.com/`

## Experiment

Kinthria's primary navigation exposed eight destinations before its primary contact/profile action: Home, Services, Legacy Profiles, How It Works, Portfolio, Research, Pricing, and About.

The first remediation reduces the primary navigation to five choices: Services, Legacy Profiles, How It Works, Pricing, and About.

`Home`, `Portfolio`, and `Research` are removed from the primary navigation presentation only. The underlying site content is not deleted by this experiment.

Base44 checkpoint: `6aa5f387acd8cd8b0991d4d2`
Base44 commit: `4a5b203761a13d36effee376538bb08ecea688bd`
Build: passed
Lint: passed

## Hypothesis

A primary navigation bar is an attention-allocation surface. When several destinations are available elsewhere in the page or site, presenting all of them at the highest navigation level may create redundant competition with the principal user paths.

The experiment therefore tests **hierarchical suppression**: reduce the prominence of a destination without deleting the destination or its content.

## Evidence boundary

This is currently a code-remediation experiment, not a completed real-screen before/after evidence package. No objective attention measurement, conversion improvement, usability improvement, accessibility improvement, or independent validation is claimed.

A complete AML evidence package requires exact rendered captures, hashes, separate labels with provenance, deterministic receipts, and post-change reproduction. Until those exist, this experiment should not be described as production-verified.

## Why it matters

If the pattern survives stronger testing, AML could distinguish **capability** from **presentation priority**. A feature may remain available while policy determines that it does not deserve scarce top-level attention in a particular interface state.

That is a testable engineering hypothesis, not a scientific conclusion.