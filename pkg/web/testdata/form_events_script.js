// Runs the layout's shared listeners against a stub DOM. Usage: node form_events_script.js <script.js>
const fs = require("fs");
const vm = require("vm");

const on = {};
let confirmAnswer = true;
let confirms = 0;
vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), {
  document: {
    addEventListener: (t, f) => { on[t] = f; },
    querySelectorAll: () => [],
  },
  window: { confirm: () => { confirms++; return confirmAnswer; } },
  navigator: {}, Date, Map, Number, isNaN, setInterval: () => 0,
});
const fail = (m) => { console.error(m); process.exit(1); };
if (!on.change) fail("no change listener");

let submitted = 0;
const form = { requestSubmit() { submitted++; } };
const box = { form, hasAttribute: (n) => n === "data-autosubmit" };
on.change({ target: box });
if (submitted !== 1) fail("data-autosubmit checkbox submitted " + submitted + " times, want 1");
on.change({ target: { form, hasAttribute: () => false } });
if (submitted !== 1) fail("a plain input submitted its form");

let prevented = false;
const del = { getAttribute: (n) => (n === "data-confirm" ? "Remove this rule?" : null) };
confirmAnswer = false;
on.submit({ target: del, preventDefault() { prevented = true; } });
if (confirms !== 1 || !prevented) fail("a declined data-confirm still submitted");
