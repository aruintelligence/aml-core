const $ = id => document.getElementById(id);
let report, screenId = "top", scenario = "observed";
const names = { sales_banner: "Sales banner", nav_phone: "Navigation number", dock_call: "Fixed call dock", dock_email: "Fixed email dock" };
const ids = ["sales_banner", "nav_phone", "dock_call", "dock_email"];

function render() {
  const screen = report.evidence.screenshots.find(row => row.id === screenId);
  const image = $("capture");
  image.src = "./" + screen.screenshot.replace(/^docs\//, "");
  image.alt = `Preserved ${screenId} viewport of ${report.site_url}; colored outlines mark public contact links`;
  $("capture-caption").textContent = `${screenId === "top" ? "Top of page" : "After scrolling"} · ${screen.captured_at} · scrollY ${screen.scroll_y}`;
  const result = scenario === "candidate" ? report.candidate : scenario === "probe" ? report.over_suppression_probe : null;
  const current = result?.screens.find(row => row.id === screenId);
  const visible = current ? current.visible_after_candidate : screen.visible;
  const channels = current?.channels || { call: visible.filter(id => report.evidence.observed_elements.find(el => el.id === id)?.channel === "call").length,
    email: visible.filter(id => report.evidence.observed_elements.find(el => el.id === id)?.channel === "email").length };
  const verdict = $("verdict");
  const status = current?.continuity || "observed";
  verdict.className = "verdict " + status;
  $("verdict-value").textContent = status === "observed" ? "OBSERVED" : status === "pass" ? "PASS" : "FAIL";
  $("verdict-detail").textContent = status === "observed" ? "Original public links in this preserved viewport." :
    status === "pass" ? "At least one call and one email path remain in this observed viewport." :
      `Missing ${current.missing.join(" and ")} after local candidate suppression.`;
  $("call-count").textContent = channels.call;
  $("email-count").textContent = channels.email;
  $("call-card").classList.toggle("missing", channels.call === 0);
  $("email-card").classList.toggle("missing", channels.email === 0);
  const overlay = $("outlines"); overlay.replaceChildren();
  const list = $("elements"); list.replaceChildren();
  for (const [i, id] of ids.entries()) {
    if (!screen.visible.includes(id)) continue;
    const choice = result?.decisions.find(row => row.element_id === id);
    const state = choice?.decision || "observed";
    const box = screen.boxes[id], [x,y,w,h] = box;
    const mark = document.createElement("div"); mark.className = "outline"; mark.dataset.state = state;
    mark.style.left = `${100*x/report.evidence.screenshot_pixels.width}%`;
    mark.style.top = `${100*y/report.evidence.screenshot_pixels.height}%`;
    mark.style.width = `${100*w/report.evidence.screenshot_pixels.width}%`;
    mark.style.height = `${100*h/report.evidence.screenshot_pixels.height}%`;
    const number = document.createElement("span"); number.textContent = i+1; mark.append(number); overlay.append(mark);
    const element = report.evidence.observed_elements.find(row => row.id === id);
    const row = document.createElement("div"); row.className = "element";
    const badge = document.createElement("span"); badge.className = "number"; badge.textContent = i+1;
    const body = document.createElement("div"); body.className = "name"; body.textContent = names[id];
    const detail = document.createElement("span"); detail.className = "detail"; detail.textContent =
      `${element.channel.toUpperCase()} · ${element.observed_label}${choice ? ` · cost ${choice.attention_cost}, value ${choice.restoration_value}` : ""}`;
    body.append(detail);
    const decision = document.createElement("span"); decision.className = "state " + state;
    decision.textContent = state.toUpperCase();
    row.append(badge,body,decision); list.append(row);
  }
  document.querySelectorAll("[data-screen]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.screen === screenId)));
  document.querySelectorAll("[data-scenario]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.scenario === scenario)));
}

document.querySelectorAll("[data-screen]").forEach(button => button.addEventListener("click", () => { screenId = button.dataset.screen; render(); }));
document.querySelectorAll("[data-scenario]").forEach(button => button.addEventListener("click", () => { scenario = button.dataset.scenario; render(); }));
try {
  const response = await fetch("./field-contact-continuity-report.json");
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  report = await response.json();
  if (report.protocol !== "aml-field-contact-continuity-report/1") throw new Error("Unsupported report");
  render();
} catch (error) {
  $("verdict-value").textContent = "UNAVAILABLE";
  $("verdict-detail").textContent = `The checked-in field report could not be loaded: ${error.message}`;
  document.querySelectorAll("[data-screen],[data-scenario]").forEach(button => button.disabled = true);
}
