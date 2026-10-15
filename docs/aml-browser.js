// ĀML browser engine v1.1
// Dependency-free ES module used by the GitHub Pages playground.
// It mirrors the repository lexer/parser/AMT/render-decision path without filesystem APIs.

export function tokenize(source) {
  const tokens = [];
  let i = 0, line = 1, column = 1;
  const keywords = new Set(["transmission","engram","coherence_gate","mirror","condition","behavior","render","runtime","attention","memory","purpose"]);
  const add = (type, value, l = line, c = column) => tokens.push({ type, value, line: l, column: c });
  const advance = () => { const ch = source[i++]; if (ch === "\n") { line++; column = 1; } else column++; return ch; };
  const peek = (o = 0) => source[i + o];

  while (i < source.length) {
    const ch = peek();
    if (/\s/.test(ch)) { advance(); continue; }
    if (ch === "/" && peek(1) === "/") { while (i < source.length && peek() !== "\n") advance(); continue; }
    if (ch === "/" && peek(1) === "*") { advance(); advance(); while (i < source.length) { if (peek() === "*" && peek(1) === "/") { advance(); advance(); break; } advance(); } continue; }
    if (ch === "{") { add("LEFT_BRACE", "{"); advance(); continue; }
    if (ch === "}") { add("RIGHT_BRACE", "}"); advance(); continue; }
    if (ch === ":") { add("COLON", ":"); advance(); continue; }
    if ([">","<","=","!"].includes(ch)) { const l=line,c=column; let value=advance(); if (peek()==="=") value += advance(); add("OPERATOR", value, l, c); continue; }
    if (ch === '"') {
      const l = line, c = column; let value = ""; advance();
      while (i < source.length && peek() !== '"') {
        if (peek() !== "\\") { value += advance(); continue; }
        advance();
        const escaped = advance();
        const escapes = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (escaped === "u") {
          let hex = "";
          for (let digit = 0; digit < 4; digit++) hex += advance() ?? "";
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`Invalid unicode escape at line ${l}, column ${c}`);
          value += String.fromCharCode(parseInt(hex, 16));
        } else if (Object.hasOwn(escapes, escaped)) value += escapes[escaped];
        else throw new Error(`Invalid string escape at line ${l}, column ${c}`);
      }
      if (peek() !== '"') throw new Error(`Unterminated string at line ${l}, column ${c}`);
      advance(); add("STRING", value, l, c); continue;
    }
    if (/[0-9-]/.test(ch)) {
      const l = line, c = column;
      const literal = source.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)?.[0];
      if (!literal || !Number.isFinite(Number(literal))) throw new Error(`Invalid number at line ${l}, column ${c}`);
      for (let digit = 0; digit < literal.length; digit++) advance();
      add("NUMBER", Number(literal), l, c); continue;
    }
    if (/[A-Za-z_Āā]/.test(ch)) {
      const l = line, c = column; let value = "";
      while (i < source.length && /[A-Za-z0-9_Āā]/.test(peek())) value += advance();
      add(keywords.has(value) ? "KEYWORD" : "IDENTIFIER", value, l, c); continue;
    }
    throw new Error(`Unexpected character "${ch}" at line ${line}, column ${column}`);
  }
  add("EOF", null);
  return tokens;
}

export function parse(tokens) {
  let current = 0;
  const peek = (o = 0) => tokens[current + o];
  const previous = () => tokens[current - 1];
  const isAtEnd = () => peek().type === "EOF";
  const advance = () => { if (!isAtEnd()) current++; return previous(); };
  const check = (type, value = null) => { const t = peek(); return !!t && t.type === type && (value === null || t.value === value); };
  const match = (type, value = null) => { if (!check(type, value)) return false; advance(); return true; };
  const consume = (type, message, value = null) => { if (check(type, value)) return advance(); const t = peek(); throw new Error(`${message} at line ${t?.line ?? "unknown"}, column ${t?.column ?? "unknown"}`); };

  function parseAtomicValue(nameToken) {
    if (check("STRING") || check("NUMBER") || check("IDENTIFIER") || check("KEYWORD")) return advance().value;
    const t = peek(); throw new Error(`Expected property value for "${nameToken.value}" at line ${t.line}, column ${t.column}`);
  }

  function parseProperty(nameToken) {
    const left = parseAtomicValue(nameToken);
    if (check("OPERATOR")) {
      const operator = advance().value;
      const right = parseAtomicValue(nameToken);
      return { type:"Property", name:nameToken.value, value:`${left} ${operator} ${right}`, expression:{left,operator,right} };
    }
    return { type: "Property", name: nameToken.value, value:left };
  }

  function parseBlockOrProperty() {
    const nameToken = advance();
    if (match("COLON")) return parseProperty(nameToken);
    let identifier = null;
    if (check("IDENTIFIER") || check("STRING")) identifier = advance().value;
    consume("LEFT_BRACE", `Expected "{" after ${nameToken.value}`);
    const children = [];
    while (!check("RIGHT_BRACE") && !isAtEnd()) children.push(parseStatement());
    consume("RIGHT_BRACE", `Expected "}" to close ${nameToken.value}`);
    return { type: "Block", name: nameToken.value, identifier, children };
  }

  function parseStatement() {
    if (check("KEYWORD") || check("IDENTIFIER")) return parseBlockOrProperty();
    const t = peek(); throw new Error(`Unexpected token "${t.value}" at line ${t.line}, column ${t.column}`);
  }

  const body = [];
  while (!isAtEnd()) body.push(parseStatement());
  return { type: "Program", body };
}

function mapBlockType(name) {
  return ({ transmission:"TransmissionNode", engram:"EngramNode", coherence_gate:"CoherenceGateNode", mirror:"MirrorNode", condition:"ConditionNode", behavior:"BehaviorNode", render:"RenderNode", runtime:"RuntimeNode", attention:"AttentionNode", memory:"MemoryNode", garden:"GardenNode" })[name] || "SemanticBlockNode";
}

function transformNode(node) {
  if (node.type === "Property") return { type:"MeaningProperty", name:node.name, value:node.value };
  const properties = {};
  for (const child of node.children || []) if (child.type === "Property") properties[child.name] = child.value;
  const base = {
    type: mapBlockType(node.name), name: node.name, identifier: node.identifier,
    children: (node.children || []).map(transformNode), properties
  };
  base.meaning = base.type === "TransmissionNode" ? "semantic execution root" : base.type === "EngramNode" ? "persistent meaning structure" : base.type === "CoherenceGateNode" ? "runtime coherence regulator" : base.type === "MirrorNode" ? "reflective interaction structure" : base.type === "ConditionNode" ? "runtime evaluation condition" : base.type === "BehaviorNode" ? "adaptive rendering behavior" : "semantic structure";
  base.render_metadata = {
    purpose: properties.purpose || null,
    memory_role: properties.memory_role || null,
    user_effect: properties.user_effect || null,
    attention_cost: typeof properties.attention_cost === "number" ? properties.attention_cost : null,
    restoration_value: typeof properties.restoration_value === "number" ? properties.restoration_value : null
  };
  return base;
}

export function buildAMT(ast) {
  return { type:"AbstractMeaningTree", version:"1.0", root:ast.body.map(transformNode) };
}

export function ethicalRenderGate(element) {
  const attention_cost = element.animation_intensity * .20 + element.cognitive_load * .30 + element.interaction_interruptions * .25 + element.reading_complexity * .15 + element.visual_noise * .10;
  const restoration_value = element.clarity * .30 + element.usefulness * .25 + element.emotional_regulation * .20 + element.continuity * .15 + element.aesthetic_coherence * .10;
  const render_allowed = restoration_value >= attention_cost;
  return { attention_cost, restoration_value, render_allowed, fallback_triggered: !render_allowed, timestamp: new Date().toISOString() };
}

function createDecision(node) {
  const m = node.render_metadata || {};
  const element = {
    purpose:m.purpose, memory_role:m.memory_role, user_effect:m.user_effect,
    attention_cost:typeof m.attention_cost === "number" ? m.attention_cost : 0,
    restoration_value:typeof m.restoration_value === "number" ? m.restoration_value : 0,
    animation_intensity:1, cognitive_load:m.attention_cost || 1, interaction_interruptions:1, reading_complexity:1, visual_noise:1,
    clarity:m.restoration_value || 1, usefulness:m.restoration_value || 1, emotional_regulation:m.restoration_value || 1, continuity:m.restoration_value || 1, aesthetic_coherence:m.restoration_value || 1
  };
  const gate = ethicalRenderGate(element);
  const attention = typeof m.attention_cost === "number" ? m.attention_cost : gate.attention_cost;
  const restoration = typeof m.restoration_value === "number" ? m.restoration_value : gate.restoration_value;
  const allowed = restoration >= attention;
  return {
    node_type:node.type, name:node.name, identifier:node.identifier, purpose:m.purpose || null,
    memory_role:m.memory_role || null, user_effect:m.user_effect || null,
    attention_cost:attention, restoration_value:restoration,
    calculated_attention_cost:gate.attention_cost, calculated_restoration_value:gate.restoration_value,
    render_allowed:allowed, fallback_triggered:!allowed, timestamp:new Date().toISOString()
  };
}

export function evaluateRenderDecisions(amt) {
  const decisions = [];
  const policyDeclarations = ["consent_required", "collects_personal_data", "motion_required",
    "reduced_motion_alternative", "contrast_safe", "cognitive_load"];
  const numericPolicyFields = ["attention_cost", "restoration_value", "cognitive_load"];
  const walk = (node, parentIndex) => {
    let nextParentIndex = parentIndex;
    const m = node.render_metadata || {};
    const properties = node.properties || {};
    for (const key of numericPolicyFields) {
      const value = properties[key];
      if (Object.hasOwn(properties, key) &&
          (typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
        throw new TypeError(`property ${key} must be a non-negative finite number.`);
      }
    }
    const explicitPolicy = m.purpose || m.memory_role || m.user_effect ||
      typeof m.attention_cost === "number" || typeof m.restoration_value === "number" ||
      policyDeclarations.some(key => Object.hasOwn(properties, key));
    if (node.type !== "MeaningProperty" && (node.type !== "TransmissionNode" || explicitPolicy)) {
      const decision = createDecision(node);
      if (parentIndex !== null && !decisions[parentIndex].render_allowed && decision.render_allowed) {
        decision.render_allowed = false;
        decision.fallback_triggered = true;
      }
      nextParentIndex = decisions.length;
      decisions.push(decision);
    }
    for (const child of node.children || []) walk(child, nextParentIndex);
  };
  for (const node of amt.root) walk(node, null);
  return decisions;
}

export function compileSourceBrowser(source) {
  const tokens = tokenize(source);
  const ast = parse(tokens);
  const amt = buildAMT(ast);
  const renderDecisions = evaluateRenderDecisions(amt);
  return { tokens, ast, amt, renderDecisions };
}
