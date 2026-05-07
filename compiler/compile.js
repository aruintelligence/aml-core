import fs from "fs";
import path from "path";
import { ethicalRenderGate } from "../runtime/ethicalRenderGate.js";

const inputPath = process.argv[2] || "examples/transmission-061.aml";
const outputDir = "dist";

const aml = fs.readFileSync(inputPath, "utf8");

function extractString(source, key) {
  const match = source.match(new RegExp(`${key}:\\s*"([^"]+)"`));
  return match ? match[1] : "";
}

function extractNumber(source, key) {
  const match = source.match(new RegExp(`${key}:\\s*([0-9.]+)`));
  return match ? Number(match[1]) : 0;
}

function compileAML(source) {
  const element = {
    title: extractString(source, "title"),
    author: extractString(source, "author"),
    value: extractString(source, "value"),
    purpose: extractString(source, "purpose"),
    memory_role: extractString(source, "memory_role"),
    user_effect: extractString(source, "user_effect"),

    attention_cost: extractNumber(source, "attention_cost"),
    restoration_value: extractNumber(source, "restoration_value"),

    animation_intensity: 1,
    cognitive_load: 2,
    interaction_interruptions: 1,
    reading_complexity: 3,
    visual_noise: 2,

    clarity: 9,
    usefulness: 8,
    emotional_regulation: 8,
    continuity: 9,
    aesthetic_coherence: 9
  };

  const decision = ethicalRenderGate(element);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${element.title}</title>
</head>
<body>
<section
  data-purpose="${element.purpose}"
  data-memory-role="${element.memory_role}"
  data-user-effect="${element.user_effect}"
  data-attention-cost="${decision.attention_cost}"
  data-restoration-value="${decision.restoration_value}"
>
  <h1>${element.title}</h1>
  <p><strong>Author:</strong> ${element.author}</p>
  <h2>${element.value}</h2>
  <pre>${JSON.stringify(decision, null, 2)}</pre>
</section>
</body>
</html>`;

  return { html, decision };
}

fs.mkdirSync(outputDir, { recursive: true });

const compiled = compileAML(aml);

fs.writeFileSync(path.join(outputDir, "index.html"), compiled.html);
fs.writeFileSync(
  path.join(outputDir, "render_decision.json"),
  JSON.stringify(compiled.decision, null, 2)
);

console.log("ĀML compile complete.");
console.log("Output written to dist/");
