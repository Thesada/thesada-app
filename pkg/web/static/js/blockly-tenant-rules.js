// Tenant rules editor (#2). Blocks only: the server turns the workspace into
// Lua, so this file never generates or sends code.
(function () {
  "use strict";

  var root = document.getElementById("tenant-rules");
  if (!root) return;
  var base = "/devices/" + root.dataset.device + "/rules";
  var canEdit = root.dataset.canEdit === "true";
  var csrfToken = root.dataset.csrf;
  var statusEl = document.getElementById("rules-status");
  var preview = document.getElementById("lua-preview");

  function status(msg, ok) {
    statusEl.textContent = msg;
    statusEl.className = "text-sm " + (ok ? "text-emerald-700" : "text-rose-700");
  }

  function defineBlocks() {
    Blockly.Blocks.thesada_tenant_rules = {
      init: function () {
        this.appendDummyInput().appendField("Rules on this device");
        this.appendStatementInput("RULES").setCheck("TenantRule");
        this.setColour(230);
        this.setDeletable(false);
      },
    };
    Blockly.Blocks.thesada_tenant_rule = {
      init: function () {
        this.appendDummyInput()
          .appendField("when")
          .appendField(new Blockly.FieldDropdown([
            ["temperature", "temperature"], ["current", "current"], ["battery %", "battery"],
          ]), "METRIC")
          .appendField("on")
          .appendField(new Blockly.FieldTextInput(""), "SENSOR")
          .appendField("is")
          .appendField(new Blockly.FieldDropdown([["below", "below"], ["above", "above"]]), "OP")
          .appendField(new Blockly.FieldNumber(2, -1000000, 1000000, 0.01), "VALUE");
        this.appendDummyInput()
          .appendField("for")
          .appendField(new Blockly.FieldNumber(5, 1, 1000, 1), "SUSTAIN_N")
          .appendField("readings or")
          .appendField(new Blockly.FieldNumber(0, 0, 1440, 1), "SUSTAIN_MIN")
          .appendField("minutes");
        this.appendDummyInput()
          .appendField("notify")
          .appendField(new Blockly.FieldTextInput("Alert"), "MSG")
          .appendField("code")
          .appendField(new Blockly.FieldTextInput("alert"), "CODE")
          .appendField("cooldown")
          .appendField(new Blockly.FieldNumber(15, 1, 1440, 1), "COOLDOWN_MIN")
          .appendField("min");
        this.setPreviousStatement(true, "TenantRule");
        this.setNextStatement(true, "TenantRule");
        this.setColour(20);
        this.setTooltip("Leave the name empty to watch every sensor. Battery ignores the name.");
      },
    };
  }

  function seed(ws) {
    var r = ws.newBlock("thesada_tenant_rules");
    r.moveBy(20, 20);
    r.initSvg();
    r.render();
    var rule = ws.newBlock("thesada_tenant_rule");
    rule.setFieldValue("Outdoor", "SENSOR");
    rule.setFieldValue("Freeze risk", "MSG");
    rule.setFieldValue("freeze", "CODE");
    rule.initSvg();
    rule.render();
    r.getInput("RULES").connection.connect(rule.previousConnection);
  }

  function workspaceJSON(ws) {
    return JSON.stringify(Blockly.serialization.workspaces.save(ws));
  }

  function post(path, body) {
    return fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify(body),
    }).then(function (res) {
      return res.text().then(function (t) {
        if (!res.ok) throw new Error(t.trim() || res.statusText);
        return JSON.parse(t);
      });
    });
  }

  function poll(id, deadline) {
    return fetch(base + "/push/result?id=" + encodeURIComponent(id)).then(function (r) {
      return r.json();
    }).then(function (res) {
      if (res.status === "pending") {
        if (Date.now() > deadline) throw new Error("no answer from the device yet, check again later");
        return new Promise(function (ok) { setTimeout(ok, 1500); }).then(function () {
          return poll(id, deadline);
        });
      }
      if (res.status !== "done") throw new Error(res.error || res.status);
      return res;
    });
  }

  defineBlocks();
  var ws = Blockly.inject(document.getElementById("blockly-workspace"), {
    toolbox: document.getElementById("toolbox"),
    media: "/static/js/blockly/media/",
    readOnly: !canEdit,
    trashcan: canEdit,
    scrollbars: true,
    zoom: { controls: true, startScale: 0.9 },
  });

  function showPreview() {
    return post("/preview", { workspace_json: workspaceJSON(ws) }).then(function (res) {
      preview.textContent = res.lua;
      return res;
    });
  }

  fetch(base + "/workspace").then(function (r) { return r.json(); }).then(function (res) {
    if (res.managed) {
      status("The operator manages the rules on this device.", false);
      return;
    }
    if (res.exists) {
      Blockly.serialization.workspaces.load(JSON.parse(res.workspace_json), ws);
    } else if (canEdit) {
      seed(ws);
    }
    return showPreview();
  }).catch(function (err) { status(err.message, false); });

  var btnPreview = document.getElementById("btn-preview");
  if (btnPreview) btnPreview.addEventListener("click", function () {
    showPreview().then(function () { status("Preview updated", true); })
      .catch(function (err) { status(err.message, false); });
  });

  var btnSave = document.getElementById("btn-save");
  if (btnSave) btnSave.addEventListener("click", function () {
    post("/workspace", { workspace_json: workspaceJSON(ws) }).then(function () {
      return showPreview();
    }).then(function () { status("Saved", true); })
      .catch(function (err) { status(err.message, false); });
  });

  var btnPush = document.getElementById("btn-push");
  if (btnPush) btnPush.addEventListener("click", function () {
    if (!window.confirm("Send the saved rules to the device and reload them?")) return;
    btnPush.disabled = true;
    status("Sending to the device", true);
    post("/push", {}).then(function (res) {
      return poll(res.request_id, Date.now() + (res.timeout_seconds || 60) * 1000);
    }).then(function () {
      status("Rules are live on the device", true);
    }).catch(function (err) {
      status(err.message, false);
    }).finally(function () { btnPush.disabled = false; });
  });
})();
