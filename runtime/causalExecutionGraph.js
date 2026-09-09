import crypto from "node:crypto";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
}

function sameStrings(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right)) return false;
  const a = [...left].sort();
  const b = [...right].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export function createCausalEvent({ kind, payload = {}, parents = [] } = {}) {
  if (!kind) throw new Error("Causal event requires kind");
  const body = {
    protocol: "aml-causal-event/1",
    kind,
    parents: [...new Set(parents)].sort(),
    payload: stable(payload)
  };
  return { ...body, event_hash: digest(body) };
}

export function createCausalExecutionGraph(events = []) {
  const byHash = Object.fromEntries(events.map((event) => [event.event_hash, event]));
  const roots = events.filter((event) => event.parents.length === 0).map((event) => event.event_hash).sort();
  const heads = events.filter((candidate) => !events.some((event) => event.parents.includes(candidate.event_hash))).map((event) => event.event_hash).sort();
  return { protocol: "aml-causal-graph/1", roots, heads, events: byHash };
}

export function verifyCausalExecutionGraph(graph) {
  if (!graph || graph.protocol !== "aml-causal-graph/1") return { valid: false, reason: "invalid_protocol" };
  if (!graph.events || typeof graph.events !== "object" || Array.isArray(graph.events)) return { valid: false, reason: "invalid_events" };
  if (!Array.isArray(graph.roots) || !Array.isArray(graph.heads)) return { valid: false, reason: "invalid_topology" };

  const entries = Object.entries(graph.events);
  const known = new Set(entries.map(([hash]) => hash));

  try {
    for (const [mapHash, event] of entries) {
      if (!event || typeof event !== "object" || Array.isArray(event)) return { valid: false, reason: "invalid_event", event_hash: mapHash };
      if (event.event_hash !== mapHash) return { valid: false, reason: "event_key_mismatch", event_hash: event.event_hash ?? null, map_hash: mapHash };
      if (!Array.isArray(event.parents)) return { valid: false, reason: "invalid_parents", event_hash: mapHash };
      const { event_hash, ...body } = event;
      if (digest(body) !== event_hash) return { valid: false, reason: "event_hash_mismatch", event_hash };
      for (const parent of event.parents) {
        if (!known.has(parent)) return { valid: false, reason: "missing_parent", event_hash, parent };
      }
    }

    const visiting = new Set();
    const visited = new Set();
    const visit = (hash) => {
      if (visiting.has(hash)) return false;
      if (visited.has(hash)) return true;
      visiting.add(hash);
      for (const parent of graph.events[hash].parents) if (!visit(parent)) return false;
      visiting.delete(hash);
      visited.add(hash);
      return true;
    };
    for (const hash of known) if (!visit(hash)) return { valid: false, reason: "cycle_detected", event_hash: hash };

    const expectedRoots = entries.filter(([, event]) => event.parents.length === 0).map(([hash]) => hash).sort();
    const referenced = new Set(entries.flatMap(([, event]) => event.parents));
    const expectedHeads = entries.map(([hash]) => hash).filter((hash) => !referenced.has(hash)).sort();

    if (!sameStrings(graph.roots, expectedRoots)) return { valid: false, reason: "roots_mismatch" };
    if (!sameStrings(graph.heads, expectedHeads)) return { valid: false, reason: "heads_mismatch" };

    return { valid: true, reason: null, event_count: entries.length, roots: expectedRoots, heads: expectedHeads };
  } catch {
    return { valid: false, reason: "invalid_graph" };
  }
}
