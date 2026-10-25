// Runs the device-detail chart script against a stub DOM. Usage: node chart_script.js <script.js>
const fs = require("fs");
const vm = require("vm");

function classList() {
  const s = new Set();
  return { add: (...c) => c.forEach((x) => s.add(x)), remove: (...c) => c.forEach((x) => s.delete(x)), contains: (c) => s.has(c) };
}
function el(extra) {
  const on = {};
  return Object.assign({ classList: classList(), dataset: {}, addEventListener: (t, f) => { on[t] = f; }, fire: (t, e) => on[t] && on[t](e) }, extra);
}
function makeCard(metrics) {
  const select = el({ options: metrics.map((m) => ({ value: m })), value: metrics[0] });
  const buttons = ["1h", "6h", "24h", "7d", "30d", "90d"].map((r) => { const b = el(); b.dataset.range = r; return b; });
  const parts = { "#chart-metric": select, "#history-chart": el(), "#chart-empty": el() };
  return { select, buttons, querySelector: (s) => parts[s] || null, querySelectorAll: () => buttons, click: (r) => buttons.find((b) => b.dataset.range === r).fire("click") };
}

let card = makeCard(["temp/boiler", "temp/room"]);
const settle = [];
const pending = [];
const rendered = [];
function Chart(canvas, config) { rendered.push(config.data.labels[0]); }
Chart.prototype.destroy = function () {};
const sandbox = {
  document: { querySelector: (s) => (s === "[data-chart-card]" ? card : null), addEventListener: (t, f) => { if (t === "htmx:before:settle") settle.push(f); } },
  localStorage: { getItem: () => null, setItem: () => {} },
  window: { innerWidth: 1024 },
  console: { error: () => {} },
  setTimeout,
  Chart,
  fetch: (url) => new Promise((resolve) => pending.push({ url, resolve })),
};
sandbox.Array = Array;
vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), sandbox);

const flush = () => new Promise((r) => setImmediate(r));
function respond(i) {
  const p = pending[i];
  p.resolve({ ok: true, json: () => Promise.resolve({ labels: [p.url], avg: [1], max: [1], min: [1] }) });
}
function fail(msg) { console.log(msg); process.exit(1); }

(async () => {
  if (pending.length !== 1) fail("first bind fetched " + pending.length + " times, want 1");
  card.click("1h");
  card.click("7d");
  respond(2); await flush();
  respond(1); await flush();
  respond(0); await flush();
  const last = rendered[rendered.length - 1] || "";
  if (!last.includes("range=7d")) fail("fast 1h then 7d ended on " + last);

  card.select.value = "temp/room";
  card.select.fire("change", { target: card.select });
  card.select.value = "temp/boiler";
  card.select.fire("change", { target: card.select });
  respond(4); await flush();
  respond(3); await flush();
  if (!rendered[rendered.length - 1].includes("metric=temp%2Fboiler")) fail("metric switch ended on " + rendered[rendered.length - 1]);

  const before = pending.length;
  settle.forEach((f) => f());
  if (pending.length !== before + 1) fail("preserved swap fetched " + (pending.length - before) + " times, want 1");
  respond(pending.length - 1); await flush();
  if (!rendered[rendered.length - 1].includes("range=7d")) fail("refetch lost the range: " + rendered[rendered.length - 1]);
})();
