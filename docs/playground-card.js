// An SVG keeps the visual share card sharp and inspectable without a canvas,
// external image service, or hidden upload. Only verified local-run data is used.
function xml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function short(value, limit) {
  const clean = String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/\s+/g, " ").trim();
  const chars = Array.from(clean);
  return xml(chars.length > limit ? chars.slice(0, limit - 1).join("") + "…" : clean);
}

function gatePanel(gate, x, number) {
  const allowed = gate.browser.effective_rendered;
  const accent = allowed ? "#9EF0BF" : "#FFA4B7";
  const wash = allowed ? "#143D3E" : "#432638";
  const label = allowed ? "VISIBLE" : "WITHHELD";
  const verdict = allowed ? "ALLOW" : "SUPPRESS";
  return `<g transform="translate(${x} 237)">
    <rect width="518" height="256" rx="22" fill="#0D2433" stroke="${accent}" stroke-opacity=".62"/>
    <path d="M22 0H496" stroke="${accent}" stroke-width="3" stroke-linecap="round"/>
    <text x="26" y="47" class="mono tiny" fill="${accent}">${number} / ENGRAM</text>
    <text x="26" y="80" class="name" fill="#F4FAFA">${short(gate.identifier || "Unnamed engram", 23)}</text>
    <rect x="365" y="29" width="128" height="34" rx="17" fill="${wash}" stroke="${accent}" stroke-opacity=".65"/>
    <text x="429" y="52" text-anchor="middle" class="mono badge" fill="${accent}">${verdict}</text>
    <path d="M26 103H492" stroke="#426071"/>
    <text x="26" y="131" class="mono tiny" fill="#9DC3D0">INTERFACE ELEMENT</text>
    <text x="26" y="167" class="label" fill="#F2F8FA">${short(gate.declaration.label, 34)}</text>
    <text x="26" y="194" class="purpose" fill="#B9CDD6">${short(gate.declaration.purpose, 49)}</text>
    <text x="26" y="231" class="mono detail" fill="${accent}">BROWSER: ${label}</text>
    <text x="493" y="231" text-anchor="end" class="mono detail" fill="#C4D8E0">COST ${gate.declaration.attention_cost}  ·  VALUE ${gate.declaration.restoration_value}</text>
  </g>`;
}

export function buildComparisonCard(record) {
  if (record?.format !== "aml-playground-local-run/v1" || !Array.isArray(record.gates) ||
      record.gates.length !== 2 || !/^[0-9a-f]{64}$/.test(record.source_sha256 || "") ||
      record.gates.some(gate => gate?.matched !== true ||
        typeof gate.identifier !== "string" || typeof gate.declaration?.label !== "string" ||
        typeof gate.declaration?.purpose !== "string" ||
        ![gate.declaration.attention_cost, gate.declaration.restoration_value].every(Number.isInteger) ||
        typeof gate.compiler?.render_allowed !== "boolean" ||
        gate.browser?.effective_rendered !== gate.compiler.render_allowed)) {
    throw new RangeError("A matched two-gate local run is required for a comparison card");
  }
  const page = new URL(record.page);
  const title = `${record.gates[0].identifier} ${record.gates[0].browser.effective_rendered ? "visible" : "withheld"}; ${record.gates[1].identifier} ${record.gates[1].browser.effective_rendered ? "visible" : "withheld"}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-labelledby="title desc">
  <title id="title">ĀML comparison: ${xml(title)}</title>
  <desc id="desc">Two project browser gates matched the compiler. Values are declared prototype inputs, not measurements or independent validation.</desc>
  <defs>
    <linearGradient id="background" x2="1" y2="1"><stop stop-color="#071321"/><stop offset=".62" stop-color="#0B2836"/><stop offset="1" stop-color="#071321"/></linearGradient>
    <radialGradient id="glow"><stop stop-color="#73E7DE" stop-opacity=".25"/><stop offset="1" stop-color="#73E7DE" stop-opacity="0"/></radialGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#6CA8B3" stroke-opacity=".09"/></pattern>
  </defs>
  <style>.sans{font-family:Arial,Helvetica,sans-serif}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.tiny{font-size:13px;font-weight:700;letter-spacing:2px}.badge{font-size:13px;font-weight:800;letter-spacing:1px}.name{font-family:Arial,Helvetica,sans-serif;font-size:24px;font-weight:800}.label{font-family:Arial,Helvetica,sans-serif;font-size:23px;font-weight:800}.purpose{font-family:Arial,Helvetica,sans-serif;font-size:15px}.detail{font-size:12px;font-weight:700;letter-spacing:.3px}</style>
  <rect width="1200" height="630" fill="url(#background)"/>
  <rect width="1200" height="630" fill="url(#grid)"/>
  <circle cx="1000" cy="64" r="360" fill="url(#glow)"/>
  <rect x="30" y="30" width="1140" height="570" rx="28" fill="none" stroke="#54818F" stroke-opacity=".65"/>
  <path d="M62 67H99" stroke="#83EDEC" stroke-width="5" stroke-linecap="round"/>
  <text x="112" y="73" class="mono tiny" fill="#83EDEC">ĀML™ / LIVE COMPARISON</text>
  <rect x="910" y="47" width="228" height="36" rx="18" fill="#153642" stroke="#6096A3"/>
  <text x="1024" y="70" text-anchor="middle" class="mono" font-size="12" font-weight="700" fill="#C7E3E7">PROJECT SELF-CHECK</text>
  <text x="62" y="153" class="sans" font-size="53" font-weight="900" letter-spacing="-2" fill="#F5FAFC">Two gates. One inspectable run.</text>
  <text x="64" y="192" class="sans" font-size="21" fill="#BAD3DB">From source to compiler decision to the browser screen.</text>
  ${gatePanel(record.gates[0], 62, "01")}
  ${gatePanel(record.gates[1], 620, "02")}
  <circle cx="600" cy="365" r="20" fill="#102E3D" stroke="#71AEB8"/>
  <text x="600" y="370" text-anchor="middle" class="mono" font-size="12" font-weight="800" fill="#D1F1F0">VS</text>
  <path d="M62 526H1138" stroke="#4C7080"/>
  <text x="62" y="555" class="mono" font-size="13" font-weight="700" fill="#83EDEC">SOURCE SHA-256  ${record.source_sha256.slice(0, 16)}…</text>
  <text x="1138" y="555" text-anchor="end" class="mono" font-size="13" fill="#B7D1DA">${short(page.hostname + page.pathname, 56)}</text>
  <text x="62" y="582" class="sans" font-size="15" fill="#C3D5DC">Author-declared prototype values · unsigned browser self-check · no independent validation</text>
</svg>`;
}
