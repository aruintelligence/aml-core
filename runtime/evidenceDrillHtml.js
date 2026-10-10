// Offline presentation of a locally computed drill. Rendering does not verify
// a report; the CLI computes it from physical share files and external policy.
const escape = value => String(value ?? "—").replace(/[&<>"']/g, character =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

export function renderEvidenceDrillHtml(report) {
  if (!report || report.protocol !== "aml-evidence-recovery-drill/1" ||
      !["ready", "degraded", "unrecoverable", "unbounded", "conflict"].includes(report.health) ||
      !Array.isArray(report.pairs) || report.pairs.length > 3) {
    throw new Error("AML_DRILL_HTML_INVALID_REPORT");
  }
  const state = report.health;
  const heading = {
    ready: "All recovery paths open",
    degraded: "Recovery possible. Repair needed.",
    unrecoverable: "No trusted recovery pair",
    unbounded: "Recovery works. Head unbounded.",
    conflict: "Recovery paths disagree"
  }[state];
  const guidance = {
    ready: "Keep the three shares in separate failure domains and rehearse again from those locations.",
    degraded: "Recover from the surviving pair, rebuild the missing share in a new file, and rerun all three pairs.",
    unrecoverable: "Check physical copies and the separately held trust policy. Do not infer the handoff from these files.",
    unbounded: "Supply a previously accepted head from outside the share set to check for rollback.",
    conflict: "Preserve all inputs and investigate the divergent recoveries before use."
  }[state];
  const pairs = report.pairs.map(pair => {
    const label = Array.isArray(pair.shares) ? pair.shares.map(escape).join(" + ") : "unknown";
    return `<article class="pair ${pair.recovered ? "pass" : "fail"}"><div class="pair-top"><span>SHARES ${label}</span><strong>${pair.recovered ? "RECOVERED" : "FAILED"}</strong></div><p>${pair.recovered ? "Trusted handoff reconstructed" : escape(pair.reason)}</p>${pair.payload_sha512 ? `<small>PAYLOAD SHA-512 <code>${escape(pair.payload_sha512)}</code></small>` : ""}</article>`;
  }).join("\n");
  const subject = report.subject;
  const detail = (name, value) => `<div class="detail"><dt>${name}</dt><dd><code>${escape(value)}</code></dd></div>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ĀML · Recovery drill · ${escape(state)}</title>
<style>
:root{color-scheme:dark;--ink:#ecf3f6;--muted:#9eafba;--line:#334650;--panel:#142630;--accent:#a9e3d1}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0%,#1f3941 0,transparent 44%),#09171d;color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1080px;margin:auto;padding:32px 26px 72px}
header{display:flex;justify-content:space-between;gap:20px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:24px}.mark{font-weight:800;letter-spacing:.1em;font-size:20px}.eyebrow,.label{font-size:11px;font-weight:800;letter-spacing:.17em;text-transform:uppercase;color:var(--accent)}header .right{color:var(--muted);font-size:13px;text-align:right}
.hero{padding:78px 0 55px}.hero h1{font-size:clamp(38px,6vw,76px);line-height:1.04;letter-spacing:-.055em;max-width:820px;margin:16px 0 24px}.hero p{max-width:710px;color:var(--muted);font-size:18px}.pill{display:inline-flex;padding:7px 13px;border:1px solid var(--line);border-radius:99px;text-transform:uppercase;font-size:12px;letter-spacing:.12em;font-weight:800}.ready .pill{color:#a9e3d1;border-color:#4f927c}.degraded .pill,.unbounded .pill{color:#ffe0a1;border-color:#b39253}.unrecoverable .pill,.conflict .pill{color:#ffb2a8;border-color:#b26a62}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:0 0 56px}.metric,.pair,.record{border:1px solid var(--line);background:var(--panel);border-radius:16px}.metric{padding:20px}.metric b{font-size:34px;display:block;line-height:1.2;margin-top:14px}.metric span{font-size:12px;text-transform:uppercase;letter-spacing:.11em;color:var(--muted)}h2{font-size:25px;letter-spacing:-.03em;margin:0 0 18px}.pairs{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:54px}.pair{padding:19px;min-width:0}.pair-top{display:flex;justify-content:space-between;gap:12px;font-size:11px;letter-spacing:.1em;font-weight:800}.pair.pass strong{color:#a9e3d1}.pair.fail strong{color:#ffb2a8}.pair p{margin:28px 0;color:var(--ink)}.pair small{color:var(--muted);font-size:10px;letter-spacing:.1em}.pair code{display:block;letter-spacing:0;margin-top:6px;overflow-wrap:anywhere;color:#c6d5db}
.record{padding:25px}.detail{display:grid;grid-template-columns:205px minmax(0,1fr);border-top:1px solid var(--line);gap:16px;padding:15px 0}.detail:first-child{border:0;padding-top:0}.detail:last-child{padding-bottom:0}dt{color:var(--muted);font-size:13px}dd{margin:0;overflow-wrap:anywhere;font-size:13px}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}footer{border-top:1px solid var(--line);margin-top:56px;padding-top:24px;color:var(--muted);font-size:13px;max-width:850px}
@media(max-width:720px){main{padding:22px 16px 48px}.hero{padding:56px 0 35px}.metrics,.pairs{grid-template-columns:1fr}.detail{grid-template-columns:1fr;gap:5px}header .right{display:none}}
@media print{:root{color-scheme:light;--ink:#172b34;--muted:#52616b;--line:#cbd6d9;--panel:#fff;--accent:#286b56}body{background:#fff}.hero{padding:30px 0}.pair,.metric,.record{break-inside:avoid}}
</style></head><body><main class="${escape(state)}"><header><div class="mark">ĀML <span class="label">/ EVIDENCE</span></div><div class="right">COLD STORAGE · LOCAL RECOVERY REHEARSAL<br>aml-evidence-recovery-drill/1</div></header>
<section class="hero"><span class="pill">${escape(state)}</span><h1>${escape(heading)}</h1><p>${escape(guidance)}</p></section>
<section class="metrics" aria-label="Recovery summary"><div class="metric"><span>Verified pairs</span><b>${escape(report.passed_pairs)} / 3</b></div><div class="metric"><span>Recovery possible</span><b>${report.recovery_possible ? "Yes" : "No"}</b></div><div class="metric"><span>Accepted head bound</span><b>${subject?.accepted_head_bound ? "Yes" : "No"}</b></div></section>
<section aria-labelledby="pairs-heading"><h2 id="pairs-heading">Every pair, checked independently</h2><div class="pairs">${pairs || "<p>No pairs were checked.</p>"}</div></section>
<section aria-labelledby="record-heading"><h2 id="record-heading">Evidence context</h2><dl class="record">${detail("Policy SHA-256", report.policy_sha256)}${detail("Payload SHA-512", subject?.payload_sha512)}${detail("Migration root SHA3-512", subject?.migration_root_sha3_512)}${detail("Archive root SHA3-512", subject?.source_archive_root_sha3_512)}${detail("Reason", report.reason)}</dl></section>
<footer>Generated locally from the supplied share files and external policy. The policy digest identifies the input for comparison; it does not make the policy authoritative. This project-authored report is not an independent witness, trusted timestamp, physical storage guarantee, or future cryptographic guarantee.</footer></main></body></html>\n`;
}
