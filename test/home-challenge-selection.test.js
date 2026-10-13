import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

test("challenge choices support one selected answer, keyboard navigation, and reset", () => {
  const page = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  const script = page.match(/<script>\s*(const probePreview=\{[\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "challenge script exists");
  assert.match(page, /class="probe-switch" role="radiogroup"/);
  assert.match(page, /class="predict-choices" role="radiogroup" aria-labelledby="predict-label"/);
  assert.match(page, /data-check="gates" aria-checked="false" tabindex="-1"/);

  let focused;
  function element(dataset = {}) {
    return {
      dataset, tabIndex: -1, hidden: false, listeners: {}, attributes: {},
      setAttribute(name, value) { this.attributes[name] = value; },
      addEventListener(name, listener) { this.listeners[name] = listener; },
      focus() { focused = this; },
      click() { this.listeners.click(); },
      key(key) {
        let prevented = false;
        this.listeners.keydown({ key, preventDefault() { prevented = true; } });
        return prevented;
      },
    };
  }
  const probes = [element({ probe: "gate" }), element({ probe: "source" })];
  const predictions = ["hash", "compiler", "gates"].map(check => element({ check }));
  const fields = Object.fromEntries([
    "ledger-mode", "ledger-pivot", "ledger-result", "predict-feedback", "challenge-link",
    "ledger-change", "ledger-checks",
  ].map(id => [`#${id}`, element()]));
  const document = {
    querySelectorAll(selector) {
      return selector === ".probe-switch button" ? probes : predictions;
    },
    querySelector(selector) { return fields[selector]; },
  };
  runInNewContext(script, { document });

  assert.equal(probes[0].key("ArrowRight"), true);
  assert.equal(focused, probes[1]);
  assert.deepEqual(probes.map(x => x.attributes["aria-checked"]), ["false", "true"]);
  assert.deepEqual(probes.map(x => x.tabIndex), [-1, 0]);
  assert.equal(fields["#challenge-link"].href, "check-run.html?example=challenge&probe=source");
  assert.equal(predictions[0].key("End"), true);
  assert.equal(focused, predictions[2]);
  assert.deepEqual(predictions.map(x => x.attributes["aria-checked"]), ["false", "false", "true"]);
  assert.equal(fields["#predict-feedback"].dataset.correct, "false");
  assert.equal(fields["#ledger-result"].hidden, false);

  probes[0].click();
  assert.deepEqual(predictions.map(x => x.attributes["aria-checked"]), ["false", "false", "false"]);
  assert.deepEqual(predictions.map(x => x.tabIndex), [0, -1, -1]);
  assert.equal(fields["#predict-feedback"].hidden, true);
  assert.equal(fields["#ledger-result"].hidden, true);
  predictions[2].click();
  assert.equal(fields["#predict-feedback"].dataset.correct, "true");
  assert.deepEqual(predictions.map(x => x.tabIndex), [-1, -1, 0]);
  probes[0].click();
  assert.equal(fields["#predict-feedback"].hidden, false, "reselecting the same change keeps its answer");
  assert.equal(fields["#ledger-result"].hidden, false);
  assert.equal(predictions[2].key("ArrowRight"), true);
  assert.equal(focused, predictions[0]);
  assert.deepEqual(predictions.map(x => x.attributes["aria-checked"]), ["true", "false", "false"]);
});
