import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

function createAtlas() {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map(match => match[1]).find(source => source.includes('const atlas=document.querySelector("#research-atlas")'));
  assert.ok(script, "atlas script exists");
  const on = element => ({ ...element, handlers: {}, addEventListener(type, fn) { this.handlers[type] = fn; } });
  const labs = [
    { textContent: "MCP tool callback", dataset: { topic: "calls" }, hidden: false },
    { textContent: "BCC recipient manifest", dataset: { topic: "recipients" }, hidden: false },
    { textContent: "Real screen field study", dataset: { topic: "screens" }, hidden: false },
  ];
  const filters = ["all", "calls", "recipients", "screens"].map(topic =>
    on({ dataset: { topic }, setAttribute(name, value) { this[name] = value; } }));
  const suggestions = ["BCC", "replay", "MCP", "real screen"].map(value => on({ dataset: { atlasSuggestion: value } }));
  const heading = { textContent: "" };
  const empty = { hidden: true, querySelector(selector) { assert.equal(selector, "h3"); return heading; } };
  const search = on({ value: "", focus() { this.focused = true; } });
  const count = { textContent: "" };
  const message = { textContent: "" };
  const showAll = on({ hidden: true });
  const copy = on({ textContent: "" });
  const elements = { "#research-atlas": null, "#atlas-search": search, "#atlas-count": count,
    "#atlas-empty": empty, "#atlas-empty-message": message, "#atlas-show-all": showAll, "#atlas-copy": copy };
  const atlas = { open: false, querySelectorAll(selector) {
    return selector === ".atlas-list .scope-teaser" ? labs :
      selector === ".atlas-filters button" ? filters : suggestions;
  }, scrollIntoView() {} };
  elements["#research-atlas"] = atlas;
  const location = { pathname: "/aml-core/", origin: "https://example.test", hash: "" };
  const window = { location, history: { replaceState(_state, _title, url) { location.hash = url.hash; } }, addEventListener() {} };
  vm.runInNewContext(script, { document: { querySelector(selector) { return elements[selector]; } }, window,
    URL, navigator: {}, requestAnimationFrame(fn) { fn(); } });
  return { labs, filters, suggestions, heading, empty, search, count, message, showAll, location };
}

test("atlas empty state finds matches across paths without losing search", () => {
  const ui = createAtlas();
  ui.filters[2].handlers.click();
  ui.search.value = "MCP";
  ui.search.handlers.input();
  assert.equal(ui.count.textContent, "0 labs shown");
  assert.equal(ui.empty.hidden, false);
  assert.equal(ui.heading.textContent, "Matches live in another path");
  assert.equal(ui.showAll.hidden, false);
  ui.showAll.handlers.click();
  assert.equal(ui.search.value, "MCP");
  assert.equal(ui.count.textContent, "1 lab shown");
  assert.equal(ui.labs[0].hidden, false);
  assert.equal(ui.location.hash, "#research-atlas");
});

test("atlas suggestions recover from an unknown term", () => {
  const ui = createAtlas();
  ui.search.value = "nothing matches";
  ui.search.handlers.input();
  assert.equal(ui.heading.textContent, "No exact match yet");
  assert.equal(ui.showAll.hidden, true);
  ui.suggestions[0].handlers.click();
  assert.equal(ui.search.value, "BCC");
  assert.equal(ui.count.textContent, "1 lab shown");
  assert.equal(ui.search.focused, true);
});
