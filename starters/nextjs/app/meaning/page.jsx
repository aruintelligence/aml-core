import { evaluateDemo } from "../../lib/demo.mjs";

export default function MeaningPage() {
  const { meaning } = evaluateDemo();
  return <main>
    <nav><a href="/">← Customer view</a></nav>
    <header><span className="eyebrow">VIEW MEANING</span><h1>Decision details</h1>
      <p>Profile: {meaning.profile}</p></header>
    <section><h2>Evaluated nodes</h2>
      <ul>{meaning.nodes.map((node, index) => <li key={`${node.identifier}-${index}`}>
        <strong>{node.render_allowed ? "ALLOW" : "SUPPRESS"}</strong> {node.identifier ?? node.node_type}
        <p>Declared purpose: {node.purpose ?? "unspecified"}</p>
        <p>Policy: {node.policy_id}</p>
      </li>)}</ul>
    </section>
    <p className="hash">Receipt SHA-256: <code>{meaning.integrity.receipt_sha256}</code></p>
  </main>;
}
