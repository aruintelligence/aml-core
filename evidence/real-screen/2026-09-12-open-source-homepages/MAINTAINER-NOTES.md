# Maintainer conversation notes

These are drafts, not messages that were sent. Before opening any issue, check
the project's current issue template and ask whether UX experiment proposals are
in scope. One targeted conversation is preferable to a campaign.

## React: publish as the control, not an issue

The captured React homepage produced 6 ALLOW and 0 SUPPRESS decisions under the
declared labels. Its value in the cohort is methodological: it demonstrates that
the gate does not manufacture criticism on every screen. There is no actionable
proposal, so filing an issue would create noise.

## Vite: optional discussion draft

> We ran a small, reproducible screen-attention experiment against the public
> Vite homepage at a 1363×936 viewport. Under our explicitly subjective operator
> labels, six elements were retained and the sponsor announcement was the only
> SUPPRESS result. This is not user research, a performance finding, or a request
> to remove sponsor recognition. Would the team be interested in a small mockup
> or controlled test of a lower-salience sponsor treatment that preserves the
> link and contractual value? The receipt includes the screen hash, labels hash,
> provenance, exact gate, and deterministic result.

Do not send this until the current contribution and issue guidance confirms the
repository accepts homepage design proposals.

## MDN: optional discussion draft

> We ran a reproducible screen-attention experiment against the public MDN
> homepage at a 1363×936 viewport. Under explicitly subjective operator labels,
> six elements were retained and the top ad, hero decoration, and large inline ad
> were flagged for suppression. We recognize that advertising supports MDN and
> are not proposing unilateral removal. Would the team be open to a controlled
> experiment on reduced ad salience or an existing user preference? The receipt
> includes the screen hash, labels hash, provenance, exact gate, and deterministic
> result. This is not user research or an accessibility finding.

Do not send this until MDN's current contribution and advertising feedback paths
confirm the right venue. A revenue-bearing placement should not be treated as a
pure front-end cleanup.

## What attracts maintainers

- A tiny reproducible artifact, not a marketing pitch.
- A neutral control with zero suppressions.
- Explicitly subjective labels that maintainers can replace.
- A question and reversible experiment, not a verdict.
- No mass mentions, unsolicited patches, security language, or adoption claims.
