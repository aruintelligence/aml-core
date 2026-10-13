import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

test("field candidates expose one selected choice and update the continuity result", () => {
  const page = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  const script = page.match(/<script>\s*(const fieldViewer=[\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);
  assert.match(page, /class="field-switch" role="radiogroup" aria-label="Choose a candidate"/);
  assert.match(page, /data-field-candidate="adverse" aria-checked="false" tabindex="-1"/);

  let focused;
  const buttons = ["safe", "adverse"].map(fieldCandidate => ({
    dataset: { fieldCandidate }, listeners: {}, attributes: {},
    addEventListener(name, callback) { this.listeners[name] = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
    focus() { focused = this; },
    click() { this.listeners.click(); },
    key(key) {
      let prevented = false;
      this.listeners.keydown({ key, preventDefault() { prevented = true; } });
      return prevented;
    },
  }));
  const fields = Object.fromEntries(["field-top-count", "field-scroll-count", "field-result"]
    .map(id => [`#${id}`, { textContent: "" }]));
  const viewer = { dataset: { candidate: "safe" }, querySelectorAll() { return buttons; } };
  const document = { querySelector(selector) { return selector === "#field-viewer" ? viewer : fields[selector]; } };
  runInNewContext(script, { document });

  assert.equal(buttons[0].key("ArrowRight"), true);
  assert.equal(focused, buttons[1]);
  assert.equal(viewer.dataset.candidate, "adverse");
  assert.deepEqual(buttons.map(x => x.attributes["aria-checked"]), ["false", "true"]);
  assert.deepEqual(buttons.map(x => x.tabIndex), [-1, 0]);
  assert.equal(fields["#field-scroll-count"].textContent, "0 call paths");
  assert.match(fields["#field-result"].textContent, /Continuity guard rejects/);
  assert.equal(buttons[1].key("Home"), true);
  assert.equal(focused, buttons[0]);
  assert.deepEqual(buttons.map(x => x.attributes["aria-checked"]), ["true", "false"]);
  assert.equal(fields["#field-scroll-count"].textContent, "1 call path");
  assert.equal(buttons[0].key("End"), true);
  assert.equal(focused, buttons[1]);
});
