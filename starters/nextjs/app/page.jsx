import { evaluateDemo } from "../lib/demo.mjs";

export default function HomePage() {
  const { result, verification, meaning, diff } = evaluateDemo();
  // The application owns its UI. Only recognized, allowed decisions select a
  // component. React escapes the text; AML's generated HTML is never injected.
  const components = new Map([
    ["continue", <p className="message">Review your order at your own pace.</p>]
  ]);

  return <main>
    <header><span className="eyebrow">ĀML × NEXT.JS</span><h1>A calmer checkout boundary</h1>
      <p>The server evaluates machine intent before React chooses what to show.</p></header>
    <section aria-labelledby="preview-title">
      <h2 id="preview-title">Customer view</h2>
      {result.decisions.map((decision, index) =>
        <div className="decision" key={`${decision.identifier ?? "unknown"}-${index}`}>
          {decision.render_allowed && components.has(decision.identifier)
            ? components.get(decision.identifier)
            : <p className="fallback">{decision.identifier === "pressure"
              ? "Urgency prompt withheld by policy. You can continue without pressure."
              : "This content is unavailable under the current policy."}</p>}
        </div>)}
    </section>
    <section aria-labelledby="evidence-title" className="evidence">
      <h2 id="evidence-title">What the boundary recorded</h2>
      <ul>
        <li>{meaning.summary.allowed} allowed · {meaning.summary.suppressed} suppressed</li>
        <li>Receipt integrity: {verification.verified ? "verified" : "failed"}</li>
        <li>Semantic diff: {diff.added.filter(node => node.identifier).length} added interface node</li>
      </ul>
      <p className="hash">Receipt SHA-256: <code>{result.receipt.receipt_sha256}</code></p>
      <nav><a href="/meaning">View Meaning</a><a href="/api/receipt">Download receipt JSON</a></nav>
    </section>
    <footer>AML evaluates declared intent; the application must validate inputs and enforce normal web security controls.</footer>
  </main>;
}
