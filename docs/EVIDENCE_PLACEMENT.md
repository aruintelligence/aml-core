# Model common failures before placing ĀML shares

The three-pair [recovery drill](EVIDENCE_DRILL.md) checks the files. It cannot tell whether two copies sit in the same building, rely on the same storage provider, or are controlled by one custodian. `aml-evidence-placement-assessment/1` adds an **operator-declared** failure-domain simulation. It removes every share with a matching label, one domain at a time, and verifies that the remaining shares still recover the same handoff under the separate trust policy.

Try the [visual Resilience Lab](resilience-lab.html) to explore shared dependencies. Select a failure row to highlight lost and surviving shares. Download a placement manifest and reopen it locally in the lab to review the same declarations later. The browser page runs a topology-only simulation with no share files or policy; the manifest is read in the browser and is not uploaded. Use the commands below for the full verified assessment.

The lab's dependency review lists each declared label shared by multiple shares. For a two-of-three scheme, each distinct site, infrastructure, and custodian label must affect at most one share to survive every modeled single-domain loss. Its minimum label-change count is the sum of `(number of shares with a conflicting label − 1)` across those groups. It counts label assignments, not physical moves; a real move can affect several labels, and changing text without changing storage does nothing. Confirm real independence before updating a manifest.

Create a local JSON manifest with exactly three indexed entries:

```json
{
  "protocol": "aml-evidence-placement/1",
  "shares": [
    { "index": 0, "site": "site-a", "infrastructure": "system-a", "custodian": "keeper-a" },
    { "index": 1, "site": "site-b", "infrastructure": "system-b", "custodian": "keeper-b" },
    { "index": 2, "site": "site-c", "infrastructure": "system-c", "custodian": "keeper-c" }
  ]
}
```

Use the **same label** when two shares share a failure domain. `site` means a location that can be lost together; `infrastructure` means a storage platform or other common dependency; `custodian` means one party whose loss of access can affect both copies. Labels can be aliases if locations are sensitive. List what is actually shared rather than inventing distinct names to make the report pass.

```bash
node scripts/evidence-placement.mjs share-0.json share-1.json share-2.json trusted-policy.json placement.json > placement-report.json
python3 independent/python/evidence_placement.py share-0.json share-1.json share-2.json trusted-policy.json placement.json > placement-python.json
```

Exit code 0 means the baseline drill is ready and each **declared** single-domain failure leaves a trusted recovery path. A nonzero exit still prints a diagnostic JSON report. `correlated` identifies one or more losses that break recovery; `unverified` means the baseline drill is not ready even though these simulated losses recovered; `unrecoverable` means the input copies could not recover a handoff; `invalid` means the manifest was incomplete or malformed. The report includes a hash of the manifest for comparison and lists which share indices each scenario would lose. It does not include a trusted clock.

This model cannot establish that a copy was placed, that labels are accurate, that the sites are independent, or that a future custodian will cooperate. Verify placement and access by retrieving each physical copy during an actual rehearsal. Keep the external trust policy and accepted head in independently governed custody too. The [frozen example](../independent/vectors/placement-v1/README.md) is synthetic.
