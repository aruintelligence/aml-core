// The integration studio emits ordinary HTML, with user text escaped as data.
// The hosted browser bridge is a changing project preview, not a pinned release.
export const BROWSER_BRIDGE_URL = "https://aruintelligence.github.io/aml-core/aml-gate.js";

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

export function normalizeIntegration(input) {
  const purpose = String(input.purpose ?? "").trim().slice(0, 120);
  const label = String(input.label ?? "").trim().slice(0, 120);
  const attention = Number(input.attention);
  const restoration = Number(input.restoration);
  const mode = input.mode;
  if (!purpose || !label) throw new RangeError("Purpose and button label are required");
  if (![attention, restoration].every(number => Number.isInteger(number) && number >= 0 && number <= 10)) {
    throw new RangeError("Declared values must be integers from 0 to 10");
  }
  if (mode !== "enforce" && mode !== "shadow") throw new RangeError("Unknown deployment mode");
  return { purpose, label, attention, restoration, mode };
}

const sharedFields = ["v", "purpose", "label", "attention", "restoration", "mode"];

export function shareableStudioUrl(input, pageUrl) {
  const declaration = normalizeIntegration(input);
  const url = new URL(pageUrl);
  const state = new URLSearchParams({ v: "1", ...declaration });
  url.search = "";
  url.hash = state.toString();
  return url.href;
}

export function parseSharedIntegration(pageUrl) {
  const hash = new URL(pageUrl).hash.slice(1);
  if (!hash || hash === "studio") return null;
  // Two 120-character Unicode fields can exceed 1 KB once percent-encoded.
  if (hash.length > 4096) throw new RangeError("Shared configuration is too long");
  const state = new URLSearchParams(hash);
  if (state.size !== sharedFields.length || sharedFields.some(field => state.getAll(field).length !== 1) ||
      [...state.keys()].some(field => !sharedFields.includes(field)) || state.get("v") !== "1") {
    throw new RangeError("Invalid shared configuration");
  }
  if (["purpose", "label"].some(field => state.get(field).length > 120)) {
    throw new RangeError("Shared text exceeds the Studio field limit");
  }
  return normalizeIntegration(Object.fromEntries(sharedFields.slice(1).map(field => [field, state.get(field)])));
}

function gateMarkup({ purpose, label, attention, restoration, mode }) {
  return `<aml-gate
  purpose="${escapeHtml(purpose)}"
  attention-cost="${attention}"
  restoration-value="${restoration}"
  mode="${mode}"
  failure-mode="closed">
  <button type="button">${escapeHtml(label)}</button>
</aml-gate>`;
}

export function integrationSnippet(input) {
  return `<script type="module" src="${BROWSER_BRIDGE_URL}"></script>

${gateMarkup(normalizeIntegration(input))}`;
}

export function downloadablePage(input) {
  const gate = gateMarkup(normalizeIntegration(input));
  // Register the listener before the deferred module upgrades <aml-gate>.
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>My ĀML interface gate</title>
  <style>
    body{max-width:680px;margin:10vh auto;padding:24px;font:17px/1.5 system-ui,sans-serif;background:#0b1525;color:#f1f7fa}
    button{font:inherit;padding:12px 18px;border-radius:10px;cursor:pointer}
    code{color:#8dece9}#decision{margin-top:24px;color:#c6d7df}
  </style>
</head>
<body>
  <h1>One interface decision</h1>
  <p>Declared values are prototype inputs. Enforce can hide the element; shadow records the would-be decision and keeps it visible.</p>
  ${gate}
  <p id="decision" role="status" aria-live="polite">Loading the project browser bridge…</p>
  <script>
    document.querySelector('aml-gate').addEventListener('aml-decision', function (event) {
      var result = event.detail;
      document.getElementById('decision').textContent = result.ok
        ? (result.render_allowed ? 'Policy: allow' : 'Policy: suppress') +
          ' · ' + (result.effective_rendered ? 'Visible' : 'Hidden') +
          ' · mode: ' + result.deployment_mode
        : 'Gate error: ' + result.error;
    });
  </script>
  <script type="module" src="${BROWSER_BRIDGE_URL}"></script>
  <p><small>This experiment loads the changing ĀML project preview from GitHub Pages. Review and pin audited assets before deployment. The values are declarations, not measurements or safety certification.</small></p>
</body>
</html>
`;
}
