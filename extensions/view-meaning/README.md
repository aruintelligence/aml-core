# View Meaning™ browser extension prototype

This Manifest V3 prototype brings the ĀML™ **View Meaning™** concept into the browser toolbar.

## What it does

When the user explicitly invokes the extension on the active tab, it can inspect AML metadata that the page has deliberately exposed, including:

- an embedded `application/vnd.aru.aml-execution-receipt+json` execution receipt;
- an embedded `application/vnd.aru.aml-brand-authorization+json` official-brand credential;
- optional AML profile/policy metadata.

The popup then:

1. recomputes the execution-receipt SHA-256 locally;
2. verifies an Ed25519 brand-authorization credential locally when browser Web Crypto supports Ed25519;
3. fetches the public canonical `BRAND_TRUST_ROOTS.json` registry from `aruintelligence/aml-core` only when an authorization credential is present;
4. distinguishes **cryptographically valid** from **officially trusted by ĀRU**;
5. links to the full View Meaning and Official AML verification pages.

## Privacy boundary

The extension requests only:

- `activeTab` — the page the user explicitly chooses to inspect;
- `scripting` — to read explicitly exposed AML metadata from that active page;
- host access limited to the canonical raw GitHub path for the public AML trust-root registry.

It does not request browsing-history permission, persistent access to all sites, or background collection. Page content, receipts, and authorization credentials are not uploaded by this prototype.

## Load locally in Chromium-based browsers

1. Clone this repository.
2. Open the browser's extensions page.
3. Enable Developer mode.
4. Choose **Load unpacked**.
5. Select `extensions/view-meaning/`.
6. Open a participating page and click **View Meaning™**.

## Metadata embedding

A participating page can expose a receipt:

```html
<script type="application/vnd.aru.aml-execution-receipt+json">
{ "protocol": "ĀML Accountable Execution Receipt", "...": "..." }
</script>
```

And, when applicable, a brand authorization:

```html
<script type="application/vnd.aru.aml-brand-authorization+json">
{ "type": "aml-brand-authorization/1", "...": "..." }
</script>
```

The page's declaration is not automatically trustworthy. The extension separately verifies the cryptographic evidence it can verify.

## Evidence boundary

Receipt-hash verification establishes integrity relative to the receipt's committed hash. It does not prove the truthfulness of declared intent or policy inputs.

A valid brand-credential signature proves integrity and possession of the signing key. **Official ĀRU authorization additionally requires that the signing-key fingerprint appear in the canonical active ĀRU trust-root registry.**

The public production trust registry intentionally remains unprovisioned until a real ĀRU production signing key is deliberately created and its public fingerprint is published. No test key is treated as official.
