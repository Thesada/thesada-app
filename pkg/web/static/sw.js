// App shell only. Device pages and the API are never stored: a stale
// reading shown as current is worse than the offline page.
const CACHE = "thesada-shell-v1";
const SHELL = [
  "/static/css/app.css",
  "/static/js/htmx.min.js",
  "/static/js/chart.umd.min.js",
  "/static/offline.html",
  "/static/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/apple-touch-icon.png",
];

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (cache) {
    return cache.addAll(SHELL);
  }));
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (key) {
      return key !== CACHE;
    }).map(function (key) {
      return caches.delete(key);
    }));
  }).then(function () {
    return self.clients.claim();
  }));
});

self.addEventListener("fetch", function (event) {
  var url = new URL(event.request.url);
  if (url.origin !== self.location.origin || event.request.method !== "GET") return;
  if (SHELL.indexOf(url.pathname) !== -1) {
    event.respondWith(caches.match(event.request).then(function (hit) {
      return hit || fetch(event.request);
    }));
    return;
  }
  if (event.request.mode === "navigate") {
    event.respondWith(fetch(event.request).catch(function () {
      return caches.match("/static/offline.html");
    }));
  }
});
