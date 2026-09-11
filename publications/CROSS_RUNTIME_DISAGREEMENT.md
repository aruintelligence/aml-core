# When two AI governance runtimes disagree, find the exact boundary

A system that claims interoperability should not hide disagreement behind a single red or green badge.

ĀML now includes a project-defined cross-runtime disagreement report that compares two governance transcripts and identifies the first observable point where their executions diverge.

The report can distinguish decision disagreement from input drift, protocol mismatch, missing output, and other output divergence. It also hashes both sides of the divergent entry so the disputed boundary can be archived and referenced precisely.

Protocol:

```text
aml-runtime-disagreement-report/1
```

This creates a practical path for a future independent runtime test:

```text
same inputs
→ runtime A executes
→ runtime B executes
→ transcripts compared
→ first divergence localized
→ contract or humans adjudicate correctness
```

That last step matters. The localizer does not declare one runtime correct merely because it is the project reference implementation. It exposes the disagreement and preserves the evidence needed to investigate it.

This is project-authored engineering capability, not evidence that an independently maintained external runtime currently implements ĀML or has reproduced the result.
