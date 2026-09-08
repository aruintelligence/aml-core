# View Meaning™ Browser Extension — Prototype Specification

## Goal

Let a person inspect AML accountability information on an AML-aware page without opening developer tools.

## Core interaction

1. User clicks the View Meaning extension icon.
2. Extension looks for a page-exposed AML receipt or receipt endpoint.
3. Extension verifies the receipt when possible.
4. Extension shows a compact panel with:
   - declared purpose;
   - selected policy/profile;
   - allow/suppress result;
   - consent/privacy declarations;
   - accessibility declarations;
   - attention/restoration inputs;
   - rationale;
   - receipt integrity;
   - provenance/signature status.
5. Advanced mode can open the full receipt JSON and provenance graph.

## Proposed page contract

An AML-aware page may expose one of:

```html
<meta name="aml-receipt" content="/accountability/receipt.json">
```

or:

```js
window.__AML_RECEIPT__ = receipt;
```

The first form is easier to isolate and fetch; the second is useful for prototypes. A future standard should prefer a scoped, permission-aware mechanism rather than an unrestricted global object.

## Trust display

The extension must distinguish:

- **receipt found** from **receipt verified**;
- **signature valid** from **signer trusted**;
- **declaration present** from **declaration independently validated**.

It must never turn a valid cryptographic signature into a claim that an interface is universally ethical or safe.

## Privacy

The extension should process receipts locally by default and avoid uploading browsing history or accountability data to a central server.

## Prototype milestones

1. Chromium Manifest V3 shell.
2. Detect `meta[name="aml-receipt"]`.
3. Fetch and render a View Meaning summary.
4. Verify receipt hashes in-browser.
5. Add signer fingerprint display.
6. Add a provenance graph view.
7. Test on the AML GitHub Pages demo.

## Mainstream value

The web normalized **View Source**. View Meaning aims to make the policy and accountability layer visible to ordinary users, reviewers, auditors, and developers.