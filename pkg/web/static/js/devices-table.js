(function () {
  var sortState = {};
  // Hidden columns for this page when localStorage throws.
  var memoryOff = {};

  function tools(name) {
    return document.querySelector('[data-devices-tools="' + name + '"]');
  }

  function prefsKey(name) {
    var el = tools(name);
    var user = el ? el.getAttribute("data-user") || "" : "";
    return "thesada.table." + name + "." + user;
  }

  function storedOff(name) {
    if (Object.prototype.hasOwnProperty.call(memoryOff, name)) return memoryOff[name];
    try {
      var raw = localStorage.getItem(prefsKey(name));
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      return parsed && parsed.off ? parsed.off : [];
    } catch (e) {
      return null;
    }
  }

  function saveOff(name, off) {
    memoryOff[name] = off.slice();
    try {
      localStorage.setItem(prefsKey(name), JSON.stringify({ off: off }));
    } catch (e) {
      // Storage can be disabled or full. memoryOff still holds the choice.
    }
  }

  function tableOf(name) {
    return document.querySelector('table[data-devices-table="' + name + '"]');
  }

  function applyColumns(name, table) {
    var off = storedOff(name);
    if (!off) return;
    var hidden = {};
    off.forEach(function (col) { hidden[col] = true; });
    table.querySelectorAll("[data-col]").forEach(function (el) {
      el.classList.toggle("hidden", !!hidden[el.getAttribute("data-col")]);
    });
  }

  function syncMenu(name, table) {
    var menu = document.querySelector('[data-col-menu="' + name + '"]');
    if (!menu) return;
    if (!menu.children.length) {
      table.querySelectorAll("th[data-col]").forEach(function (th) {
        var col = th.getAttribute("data-col");
        var label = document.createElement("label");
        label.className = "flex items-center gap-2 text-sm text-slate-700";
        var box = document.createElement("input");
        box.type = "checkbox";
        box.setAttribute("data-col-toggle", col);
        label.appendChild(box);
        label.appendChild(document.createTextNode(th.getAttribute("data-label") || col));
        menu.appendChild(label);
      });
    }
    menu.querySelectorAll("[data-col-toggle]").forEach(function (box) {
      var th = table.querySelector('th[data-col="' + box.getAttribute("data-col-toggle") + '"]');
      box.checked = !(th && th.classList.contains("hidden"));
    });
  }

  function applyFilter(name, table) {
    var input = document.querySelector('[data-devices-filter="' + name + '"]');
    var q = input ? input.value.trim().toLowerCase() : "";
    var shown = 0;
    var total = 0;
    table.querySelectorAll("tbody tr[data-filter]").forEach(function (tr) {
      total++;
      var hay = (tr.getAttribute("data-filter") || "").toLowerCase();
      var hide = q.length > 0 && hay.indexOf(q) === -1;
      tr.hidden = hide;
      if (hide) {
        var box = tr.querySelector("input.bulk-row");
        if (box && box.checked) {
          box.checked = false;
          box.dispatchEvent(new Event("change"));
        }
      } else {
        shown++;
      }
    });
    var count = document.querySelector('[data-filter-count="' + name + '"]');
    if (count) count.textContent = q ? shown + " of " + total : "";
  }

  function cellKey(tr, col) {
    var td = tr.querySelector('td[data-col="' + col + '"]');
    if (!td) return "";
    if (td.hasAttribute("data-sort")) return td.getAttribute("data-sort");
    return (td.textContent || "").trim().toLowerCase();
  }

  function applySort(name, table) {
    var state = sortState[name];
    table.querySelectorAll("th[data-col]").forEach(function (th) {
      th.removeAttribute("aria-sort");
    });
    if (!state) return;
    var th = table.querySelector('th[data-col="' + state.col + '"]');
    if (th) th.setAttribute("aria-sort", state.dir === "desc" ? "descending" : "ascending");
    var tbody = table.querySelector("tbody");
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr[data-filter]"));
    rows.sort(function (a, b) {
      var av = cellKey(a, state.col);
      var bv = cellKey(b, state.col);
      if (av === "" && bv === "") return 0;
      if (av === "") return 1;
      if (bv === "") return -1;
      var numeric = /^-?\d+$/.test(av) && /^-?\d+$/.test(bv);
      var cmp;
      if (numeric) {
        var an = Number(av);
        var bn = Number(bv);
        cmp = an < bn ? -1 : an > bn ? 1 : 0;
      } else {
        cmp = av < bv ? -1 : av > bv ? 1 : 0;
      }
      return state.dir === "desc" ? -cmp : cmp;
    });
    rows.forEach(function (tr) { tbody.appendChild(tr); });
  }

  function localizeTimes(table) {
    table.querySelectorAll("time[datetime]").forEach(function (el) {
      var d = new Date(el.getAttribute("datetime"));
      if (!isNaN(d)) el.textContent = d.toLocaleString();
    });
  }

  function ensureSortButtons(table) {
    table.querySelectorAll("th[data-col]").forEach(function (th) {
      if (th.hasAttribute("data-nosort") || th.querySelector("button")) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "bg-transparent p-0 m-0 uppercase cursor-pointer text-inherit font-inherit";
      btn.textContent = (th.textContent || "").trim();
      th.textContent = "";
      th.appendChild(btn);
    });
  }

  function apply(name) {
    var table = tableOf(name);
    if (!table) return;
    ensureSortButtons(table);
    applyColumns(name, table);
    syncMenu(name, table);
    applyFilter(name, table);
    applySort(name, table);
    localizeTimes(table);
  }

  function eachTable(fn) {
    document.querySelectorAll("table[data-devices-table]").forEach(function (table) {
      fn(table.getAttribute("data-devices-table"));
    });
  }

  document.addEventListener("click", function (ev) {
    var th = ev.target.closest && ev.target.closest("th[data-col]");
    if (!th || th.hasAttribute("data-nosort")) return;
    var table = th.closest("table[data-devices-table]");
    if (!table) return;
    var name = table.getAttribute("data-devices-table");
    var col = th.getAttribute("data-col");
    var prev = sortState[name];
    var dir = prev && prev.col === col && prev.dir === "asc" ? "desc" : "asc";
    sortState[name] = { col: col, dir: dir };
    apply(name);
  });

  document.addEventListener("input", function (ev) {
    var t = ev.target;
    if (!t || !t.getAttribute) return;
    var name = t.getAttribute("data-devices-filter");
    if (name) apply(name);
  });

  document.addEventListener("change", function (ev) {
    var t = ev.target;
    if (!t || !t.getAttribute) return;
    var col = t.getAttribute("data-col-toggle");
    if (!col) return;
    var menu = t.closest("[data-col-menu]");
    if (!menu) return;
    var name = menu.getAttribute("data-col-menu");
    var table = tableOf(name);
    if (!table) return;
    var off = [];
    menu.querySelectorAll("[data-col-toggle]").forEach(function (box) {
      if (!box.checked) off.push(box.getAttribute("data-col-toggle"));
    });
    saveOff(name, off);
    apply(name);
  });

  document.addEventListener("htmx:afterSwap", function (ev) {
    var target = ev.detail && ev.detail.target;
    if (!target || !target.querySelector) return;
    var table = target.matches && target.matches("table[data-devices-table]")
      ? target
      : target.querySelector("table[data-devices-table]");
    if (table) apply(table.getAttribute("data-devices-table"));
  });

  function boot() { eachTable(apply); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
