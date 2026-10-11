import { readFileSync, writeFileSync } from "node:fs";
import { makeStudioBundle } from "../pilots/action-boundary/studio-bundle.mjs";

const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url), "utf8"));
const example = makeStudioBundle(vectors.cases.find(row => row.name === "changed_destination").proposal, vectors.policy);
const content = JSON.stringify(example, null, 2) + "\n";
const path = new URL("../examples/action-studio/changed-destination.json", import.meta.url);
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== content) throw new Error("Action Studio example is stale");
  console.log("Action Studio example matches the reference calculation.");
} else {
  writeFileSync(path, content);
}
