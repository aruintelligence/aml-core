import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const SKIP_DIRS = new Set([".git", "node_modules", "dist"]);

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) out.push(full);
  }
  return out;
}

function stripTarget(raw) {
  let target = raw.trim();
  if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
  const titleMatch = target.match(/^([^\s]+)\s+["'][^"']*["']$/);
  if (titleMatch) target = titleMatch[1];
  try { target = decodeURIComponent(target); } catch {}
  return target;
}

function isIgnored(target) {
  return !target ||
    target.startsWith("#") ||
    /^(?:https?:|mailto:|tel:|data:|javascript:)/i.test(target);
}

function resolveLocal(file, target) {
  const noFragment = target.split("#")[0].split("?")[0];
  if (!noFragment) return null;
  return path.resolve(path.dirname(file), noFragment);
}

const broken = [];
const files = walk(ROOT);

for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  const markdownLinks = /!?(?:\[[^\]]*\])\(([^)]+)\)/g;
  let match;
  while ((match = markdownLinks.exec(text))) {
    const target = stripTarget(match[1]);
    if (isIgnored(target)) continue;
    const resolved = resolveLocal(file, target);
    if (resolved && !fs.existsSync(resolved)) {
      broken.push({
        file: path.relative(ROOT, file),
        target,
        resolved: path.relative(ROOT, resolved)
      });
    }
  }
}

if (broken.length) {
  console.error(`Found ${broken.length} broken local Markdown link(s):`);
  for (const item of broken) {
    console.error(`- ${item.file}: ${item.target} -> ${item.resolved}`);
  }
  process.exit(1);
}

console.log(`Local Markdown link check passed across ${files.length} Markdown files.`);
