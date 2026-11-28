// Runs static/js/theme.js against a stub DOM. Usage: node theme_script.js <script.js>
const fs = require("fs");
const vm = require("vm");

const src = fs.readFileSync(process.argv[2], "utf8");
function fail(msg) { console.log(msg); process.exit(1); }

function boot(opts) {
  const attrs = {};
  const listeners = {};
  const winListeners = {};
  const mqListeners = [];
  const store = Object.assign({}, opts.store);
  const events = [];
  const buttons = ["light", "dark", "system"].map((v) => {
    const a = { "data-theme-option": v };
    return { getAttribute: (k) => a[k], setAttribute: (k, x) => { a[k] = x; }, attrs: a };
  });
  const mq = { matches: !!opts.osDark, addEventListener: (t, f) => mqListeners.push(f) };
  const storage = opts.brokenStorage
    ? { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); }, removeItem: () => { throw new Error("denied"); } }
    : { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: (k) => { delete store[k]; } };
  const document = {
    documentElement: { getAttribute: (k) => attrs[k], setAttribute: (k, v) => { attrs[k] = v; } },
    querySelectorAll: (s) => (s === "[data-theme-option]" ? buttons : []),
    addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); },
    dispatchEvent: (e) => { events.push(e.detail); (listeners[e.type] || []).forEach((f) => f(e)); },
  };
  const window = {
    matchMedia: (q) => { if (q !== "(prefers-color-scheme: dark)") fail("unexpected media query " + q); return mq; },
    addEventListener: (t, f) => { (winListeners[t] = winListeners[t] || []).push(f); },
  };
  function CustomEvent(type, init) { this.type = type; this.detail = init && init.detail; }
  const sandbox = { window, document, localStorage: storage, CustomEvent };
  window.localStorage = storage;
  vm.runInNewContext(src, sandbox);
  return {
    theme: () => attrs["data-theme"],
    choice: () => attrs["data-theme-choice"],
    pressed: () => buttons.filter((b) => b.attrs["aria-pressed"] === "true").map((b) => b.attrs["data-theme-option"]),
    os: (dark) => { mq.matches = dark; mqListeners.forEach((f) => f({ matches: dark })); },
    ready: () => (listeners.DOMContentLoaded || []).forEach((f) => f()),
    storageEvent: (v) => { store["thesada-theme"] = v; (winListeners.storage || []).forEach((f) => f({ key: "thesada-theme", newValue: v })); },
    set: (v) => window.setTheme(v),
    store,
    events,
  };
}

// Nothing stored: System, following the OS, live.
let p = boot({ osDark: true });
if (p.theme() !== "dark" || p.choice() !== "system") fail("fresh load on a dark OS gave " + p.theme() + "/" + p.choice());
p.os(false);
if (p.theme() !== "light") fail("System did not follow the OS to light");
p.ready();
if (p.pressed().join() !== "system") fail("pressed buttons " + p.pressed());

// Explicit choices persist and ignore the OS.
p.set("dark");
if (p.theme() !== "dark" || p.store["thesada-theme"] !== "dark") fail("Dark not applied or not stored");
p.os(false);
if (p.theme() !== "dark") fail("Dark followed the OS");
if (p.pressed().join() !== "dark") fail("pressed after Dark " + p.pressed());
p.set("light");
p.os(true);
if (p.theme() !== "light") fail("Light followed the OS");
const last = p.events[p.events.length - 1];
if (!last || last.theme !== "light" || last.choice !== "light") fail("theme event missing or wrong: " + JSON.stringify(last));
p.set("system");
if (p.theme() !== "dark" || "thesada-theme" in p.store) fail("System did not clear storage or follow the OS");
p.set("purple");
if (p.choice() !== "system") fail("unknown choice accepted");

// A stored choice wins on the next load, another tab's change syncs.
p = boot({ osDark: true, store: { "thesada-theme": "light" } });
if (p.theme() !== "light" || p.choice() !== "light") fail("stored Light lost on load");
p.storageEvent("dark");
if (p.theme() !== "dark") fail("change in another tab not applied");

// Junk or blocked storage falls back to System.
p = boot({ osDark: false, store: { "thesada-theme": "neon" } });
if (p.choice() !== "system" || p.theme() !== "light") fail("junk storage gave " + p.choice());
p = boot({ osDark: true, brokenStorage: true });
if (p.theme() !== "dark") fail("blocked storage broke System");
p.set("light");
if (p.theme() !== "light") fail("blocked storage blocked the switch");
