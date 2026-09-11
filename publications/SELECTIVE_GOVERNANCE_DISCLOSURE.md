# Verify part of an AI governance history without publishing all of it

Accountability and confidentiality can conflict. A full governance transcript can be useful evidence, but it can also contain interface content or policy context that should not automatically become public.

ĀML now includes a project-defined selective-disclosure artifact for governance transcripts.

It builds a Merkle commitment over every transcript entry hash, then allows specific entries to be revealed with inclusion proofs. A verifier can check that a disclosed entry belongs to the committed transcript without receiving every undisclosed message body.

Protocol:

```text
aml-governance-selective-disclosure/1
```

This is **not** a zero-knowledge proof. It still reveals metadata including the transcript entry count, selected indices, disclosed entries, the transcript root, and the Merkle root.

It also does not make an unauthenticated Merkle root trustworthy. For authenticity, the commitment or source transcript root must be obtained through a signed, witnessed, published, or otherwise authenticated channel.

The milestone matters because future governance evidence should not force an all-or-nothing choice between total secrecy and total disclosure.
