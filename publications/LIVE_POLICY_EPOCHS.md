# An AI interface can change policy mid-generation without making the history invisible

Generated interfaces do not always arrive as one finished object. They may stream for minutes or hours while rollout mode, policy context, or enforcement posture changes.

ĀML now makes those changes explicit protocol events instead of invisible mutable configuration.

A live governance stream can accept `aml-governance-stream-policy-update/1` and return a `aml-governance-stream-policy-applied/1` acknowledgement containing a policy epoch plus hashes of the previous and new policy states.

That means a later transcript can show not only what interface nodes were evaluated, but **under which policy epoch each part of the session occurred**. The same transcript can be deterministically replayed because the policy changes themselves are part of the recorded input history.

This does not grant authority to change policy. Authorization and organizational approval remain separate. The milestone is narrower: policy mutation no longer has to be hidden from the evidence trail.

For long-lived agentic interfaces, that is a meaningful shift from static configuration toward replayable governance state transitions.
