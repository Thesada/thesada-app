// Light, Dark or System, stored on this device. Loaded in head before the
// stylesheet so the first paint already has the right theme.
(function () {
  var KEY = "thesada-theme";
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var choice = valid(read()) ? read() : "system";

  function valid(v) { return v === "light" || v === "dark" || v === "system"; }
  function read() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }

  function apply() {
    var theme = choice === "dark" || (choice === "system" && mq && mq.matches) ? "dark" : "light";
    root.setAttribute("data-theme", theme);
    root.setAttribute("data-theme-choice", choice);
    document.querySelectorAll("[data-theme-option]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-option") === choice));
    });
    document.dispatchEvent(new CustomEvent("thesada:theme", { detail: { choice: choice, theme: theme } }));
  }

  window.setTheme = function (v) {
    if (!valid(v)) return;
    choice = v;
    try {
      if (v === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, v);
    } catch (e) {}
    apply();
  };

  if (mq) mq.addEventListener("change", function () { if (choice === "system") apply(); });
  window.addEventListener("storage", function (ev) {
    if (ev.key !== KEY) return;
    choice = valid(ev.newValue) ? ev.newValue : "system";
    apply();
  });
  document.addEventListener("DOMContentLoaded", apply);
  apply();
})();
