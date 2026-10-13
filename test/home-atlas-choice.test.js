import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

test("atlas topic keyboard selection updates URL and preserves the search", () => {
  const page = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  const script = page.match(/<script>\s*(const atlas=document\.querySelector[\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);
  assert.match(page, /class="atlas-filters" role="radiogroup" aria-label="Filter research labs"/);
  assert.match(page, /data-topic="screens" aria-checked="false" tabindex="-1"/);

  let focused;
  function control(topic) {
    return {
      dataset: { topic }, listeners: {}, attributes: {},
      addEventListener(name, fn) { this.listeners[name] = fn; },
      setAttribute(name, value) { this.attributes[name] = value; },
      focus() { focused = this; },
      key(key) {
        let prevented = false;
        this.listeners.keydown({ key, preventDefault() { prevented = true; } });
        return prevented;
      },
    };
  }
  const buttons = ["all", "calls", "recipients", "screens"].map(control);
  const labs = [
    { dataset: { topic: "calls" }, textContent: "Replay a tool call" },
    { dataset: { topic: "recipients" }, textContent: "Recipient case" },
    { dataset: { topic: "screens" }, textContent: "Captured screen" },
  ];
  const atlas = {
    open: false,
    querySelectorAll(selector) {
      if (selector === ".atlas-filters button") return buttons;
      if (selector === ".atlas-list .scope-teaser") return labs;
      return [];
    },
    scrollIntoView() {},
  };
  const search = { value: "", addEventListener(name, fn) { this[name] = fn; } };
  const empty = { hidden: true, querySelector() { return { textContent: "" }; } };
  const fields = Object.fromEntries(["atlas-count", "atlas-empty-message", "atlas-show-all", "atlas-copy"]
    .map(id => [`#${id}`, control(id)]));
  const document = { querySelector(selector) {
    return selector === "#research-atlas" ? atlas : selector === "#atlas-search" ? search :
      selector === "#atlas-empty" ? empty : fields[selector];
  } };
  const location = { pathname: "/aml-core/", origin: "https://example.test", hash: "#research-atlas" };
  const window = {
    location, history: { replaceState(_state, _title, url) { location.hash = url.hash; } },
    addEventListener(name, fn) { this[name] = fn; },
  };
  runInNewContext(script, { document, window, URL, navigator: {}, requestAnimationFrame: fn => fn() });
  assert.equal(atlas.open, true);
  assert.equal(buttons[0].key("ArrowRight"), true);
  assert.equal(focused, buttons[1]);
  assert.equal(location.hash, "#atlas-calls");
  assert.deepEqual(buttons.map(x => x.attributes["aria-checked"]), ["false", "true", "false", "false"]);
  assert.deepEqual(buttons.map(x => x.tabIndex), [-1, 0, -1, -1]);
  assert.equal(fields["#atlas-count"].textContent, "1 lab shown");

  search.value = "replay";
  search.input();
  buttons[1].key("End");
  assert.equal(location.hash, "#atlas-screens");
  assert.equal(search.value, "replay", "topic choice does not clear the local search");
  assert.equal(fields["#atlas-count"].textContent, "0 labs shown");
  location.hash = "#atlas-recipients";
  window.hashchange();
  assert.equal(search.value, "", "a direct shared topic starts with an empty search");
  assert.equal(buttons[2].attributes["aria-checked"], "true");
  assert.equal(buttons[2].tabIndex, 0);
  assert.equal(fields["#atlas-count"].textContent, "1 lab shown");
});
