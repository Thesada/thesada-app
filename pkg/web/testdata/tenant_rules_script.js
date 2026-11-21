// Runs the tenant rules editor against a stub Blockly and DOM. Usage: node tenant_rules_script.js <script.js>
const fs = require("fs");
const vm = require("vm");
const src = fs.readFileSync(process.argv[2], "utf8");

async function run(name, opts) {
  const made = [];
  const block = (type) => {
    made.push(type);
    return {
      moveBy() {}, initSvg() {}, render() {}, setFieldValue() {}, previousConnection: {},
      getInput: () => ({ connection: { connect() {} } }),
    };
  };
  const el = (extra) => Object.assign({ dataset: {}, textContent: "", className: "", addEventListener() {} }, extra);
  const els = {
    "tenant-rules": el({ dataset: { device: "d1", canEdit: String(opts.canEdit), csrf: "tok" } }),
    "rules-status": el(), "lua-preview": el(), "blockly-workspace": el(), toolbox: el(), "btn-preview": el(),
  };
  if (opts.saveButton) els["btn-save"] = el();
  const fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.endsWith("/workspace") ? { managed: opts.managed, exists: false } : {}),
    text: () => Promise.resolve('{"lua":"-- lua"}'),
  });
  const Blockly = {
    Blocks: {}, FieldDropdown: function () {}, FieldTextInput: function () {}, FieldNumber: function () {},
    inject: () => ({ newBlock: block }),
    serialization: { workspaces: { save: () => ({}), load() {} } },
  };
  vm.runInNewContext(src, {
    document: { getElementById: (id) => els[id] || null }, Blockly, fetch, JSON, Date, Promise, setTimeout,
    window: { confirm: () => true },
  });
  await new Promise((r) => setTimeout(r, 20));
  const seeded = made.includes("thesada_tenant_rules");
  if (seeded !== opts.wantRoot) {
    throw new Error(name + ": root block seeded = " + seeded + ", want " + opts.wantRoot);
  }
}

(async () => {
  await run("operator on a managed slot", { managed: true, canEdit: true, saveButton: true, wantRoot: true });
  await run("tenant admin on a managed slot", { managed: true, canEdit: true, saveButton: false, wantRoot: false });
  await run("viewer", { managed: false, canEdit: false, saveButton: false, wantRoot: false });
  await run("new tenant workspace", { managed: false, canEdit: true, saveButton: true, wantRoot: true });
})().catch((err) => { console.error(err.message); process.exit(1); });
