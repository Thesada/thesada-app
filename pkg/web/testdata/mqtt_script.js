// Runs the admin MQTT page script against a stub DOM and WebSocket. Usage: node mqtt_script.js <script.js>
const fs = require("fs");
const vm = require("vm");

function el(extra) {
  const on = {};
  return Object.assign({
    value: "", checked: false, textContent: "", className: "", children: [], innerHTML: "",
    classList: { toggle: () => {} },
    appendChild(c) { this.children.push(c); }, removeChild() { this.children.shift(); },
    addEventListener: (t, f) => { on[t] = f; }, fire: (t, e) => on[t] && on[t](e || { preventDefault() {} }),
  }, extra);
}
const els = {};
const byId = (id) => els[id] || (els[id] = el());
byId("mqtt-pattern").value = "thesada/acme/#";
byId("mqtt-pub-qos").value = "0";

const sockets = [];
function WebSocket(url) {
  this.url = url;
  this.readyState = WebSocket.CONNECTING;
  this.sent = [];
  sockets.push(this);
}
WebSocket.CONNECTING = 0; WebSocket.OPEN = 1; WebSocket.CLOSING = 2; WebSocket.CLOSED = 3;
WebSocket.prototype.send = function (m) {
  if (this.readyState !== WebSocket.OPEN) throw new Error("send on socket in state " + this.readyState);
  this.sent.push(JSON.parse(m));
};
WebSocket.prototype.close = function () { this.readyState = WebSocket.CLOSING; };
const open = (s) => { s.readyState = WebSocket.OPEN; s.onopen && s.onopen(); };
const closed = (s, code) => { s.readyState = WebSocket.CLOSED; s.onclose && s.onclose({ code }); };

vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), {
  document: { getElementById: byId, createElement: () => el() },
  location: { protocol: "https:", host: "app.test" },
  WebSocket, JSON, Date, parseInt,
});

function fail(msg) { console.log(msg); process.exit(1); }
const status = () => byId("mqtt-status").textContent;

if (sockets.length !== 1) fail("page load opened " + sockets.length + " sockets, want 1");
byId("mqtt-subscribe").fire("click");
byId("mqtt-subscribe").fire("click");
if (sockets.length !== 1) fail("subscribe while connecting opened " + sockets.length + " sockets, want 1");
const a = sockets[0];
open(a);
if (status() !== "connected") fail("after open status is " + status());

// Format JSON bounces the socket; the old one's close lands after the new one opens.
byId("mqtt-format-json").checked = true;
byId("mqtt-format-json").fire("change");
if (sockets.length !== 2) fail("format bounce opened " + (sockets.length - 1) + " sockets, want 1");
const b = sockets[1];
open(b);
closed(a, 1000);
if (status() !== "connected") fail("old socket's close set status to " + status());
byId("mqtt-pub-topic").value = "thesada/acme/x";
byId("mqtt-publish").fire("click");
if (!b.sent.some((m) => m.type === "publish")) fail("publish did not reach the current socket");

// A stale 4000 close must not reconnect over the current socket.
closed(a, 4000);
if (sockets.length !== 2) fail("stale 4000 close opened another socket");

// The current socket's 4000 still reconnects.
closed(b, 4000);
if (sockets.length !== 3) fail("lifetime close did not reconnect");
