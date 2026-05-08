#!/usr/bin/env node

// compiler/aml-compiler.js
// ĀML™ v1.0 — Minimal Working Compiler
// Converts a simple .aml file into semantic HTML and render_decision.json.

import fs from "fs";
import path from "path";

const DEFAULT_INPUT = "examples/simple.aml";
const DEFAULT_OUTPUT = "dist";

function readSource(inputPath) {
  if (!fs.existsSync(inputPath)) {
    throw new Error(`AML source file not found: ${inputPath}`);
  }

  return fs.readFileSync(inputPath, "utf8");
}

function extractValue(source, key) {
  const pattern = new RegExp(`${key}\\s*:\\s*\\n\\s*"([^"]*)"`, "i");
  const match = source.match(pattern);
  return match ? match[1] : null;
}

function extractNumber(source, key) {
  const pattern = new RegExp(`${key}\\s*:\\s*\\n\\s*([0-9.]+)`, "i");
  const match = source.match(pattern);
  return match ? Number(match[1]) : null;
}

function parseAML(source) {
  const transmissionMatch = source.match(/transmission\s+"([^"]+)"/i);
  const engramMatch = source.match(/engram\s+([A-Za-z0-9_]+)/i);

  const attentionCost = extractNumber(source, "attention_cost") ?? 0;
  const restorationValue = extractNumber(source, "restoration_value") ?? 0;

  return {
    transmission: transmissionMatch ? transmissionMatch[1] : "untitled",
    title: extractValue(source, "title") || "Untitled AML Document",
    engram: engramMatch ? engramMatch[1] : "anonymousElement",
    value: extractValue(source, "value") || "",
    purpose: extractValue(source, "purpose") || "",
    attention_cost: attentionCost,
    restoration_value: restorationValue
  };
}

function evaluateRender(node) {
  const renderAllowed = node.restoration_value >= node.attention_cost;
  const degraded =
    !renderAllowed &&
    node.restoration_value >= node.attention_cost - 2.25;

  const renderingMode = renderAllowed
    ? "allowed"
    : degraded
      ? "degraded"
      : "suppressed";

  return {
    element: node.engram,
    transmission: node.transmission,
    purpose: node.purpose,
    attention_cost: node.attention_cost,
    restoration_value: node.restoration_value,
    render_allowed: renderAllowed,
    rendering_mode: renderingMode,
    fallback_triggered: !renderAllowed,
    reason: renderAllowed
      ? "Restoration value meets or exceeds attention cost."
      : degraded
        ? "Element failed the gate but remains visible in degraded mode."
        : "Element suppressed because attention cost exceeds restoration value.",
    timestamp: new Date().toISOString()
  };
}

function generateHTML(node, decision) {
  const status = decision.rendering_mode.toUpperCase();

  return `<!DOCTYPE html>
<html lang
