# ĀML Plain JavaScript Starter

Use ĀML in a normal browser page without cloning the compiler or installing Node.

```html
<!doctype html>
<html>
<body>
  <pre id="out"></pre>
  <script type="module">
    import { compileSourceBrowser } from "https://aruintelligence.github.io/aml-core/aml-browser.js";

    const source = `transmission "hello" {
      message "welcome" {
        purpose: "Explain the page"
        attention_cost: 1
        restoration_value: 2
      }
    }`;

    const result = compileSourceBrowser(source);
    document.querySelector("#out").textContent = JSON.stringify(result.renderDecisions, null, 2);
  </script>
</body>
</html>
```

This is the lowest-friction AML entry point: browser-native ES modules, no package manager required.

For production use, pin a specific AML release rather than relying indefinitely on `main`-equivalent hosted assets.