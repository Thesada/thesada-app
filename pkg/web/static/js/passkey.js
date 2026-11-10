// Passkey sign-in and enrollment. The server sends WebAuthn options with
// base64url byte fields, this file turns them into ArrayBuffers and back.
(function () {
  "use strict";

  function b64urlToBuf(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfToken(root) {
    var el = root.querySelector('input[name="_csrf"]');
    return el ? el.value : "";
  }

  function postJSON(url, body, root) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken(root) },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        data.__status = res.status;
        return data;
      });
    });
  }

  function showError(root, msg) {
    var el = root.querySelector("[data-passkey-error]");
    if (el) {
      el.textContent = msg;
      el.hidden = false;
    }
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  function requestOptions(opts) {
    var pk = opts.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return { publicKey: pk };
  }

  function creationOptions(opts) {
    var pk = opts.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return { publicKey: pk };
  }

  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64url(r.authenticatorData),
        clientDataJSON: bufToB64url(r.clientDataJSON),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
  }

  function attestationJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(r.attestationObject),
        clientDataJSON: bufToB64url(r.clientDataJSON),
        transports: r.getTransports ? r.getTransports() : []
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
  }

  function follow(root, data, fallback) {
    if (data.redirect) {
      window.location.assign(data.redirect);
      return;
    }
    showError(root, data.error || fallback);
  }

  function login(root) {
    var btn = root.querySelector("[data-passkey-login]");
    if (!btn) return;
    if (!supported()) {
      showError(root, "This browser cannot use passkeys.");
      btn.disabled = true;
      return;
    }
    btn.addEventListener("click", function () {
      btn.disabled = true;
      postJSON("/login/passkey/begin", {}, root).then(function (opts) {
        if (!opts.publicKey) return follow(root, opts, "Could not start the passkey check.");
        return navigator.credentials.get(requestOptions(opts)).then(function (cred) {
          return postJSON("/login/passkey/finish", assertionJSON(cred), root);
        }).then(function (data) {
          follow(root, data, "That passkey was not accepted.");
        });
      }).catch(function () {
        showError(root, "The passkey check was cancelled.");
      }).then(function () {
        btn.disabled = false;
      });
    });
  }

  function enroll(root) {
    var form = root.querySelector("[data-passkey-add]");
    if (!form) return;
    if (!supported()) {
      showError(root, "This browser cannot add passkeys.");
      form.querySelector("button").disabled = true;
      return;
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var btn = form.querySelector("button");
      var password = form.querySelector('input[name="password"]').value;
      var name = form.querySelector('input[name="name"]').value;
      btn.disabled = true;
      postJSON("/settings/passkeys/begin", { password: password }, root).then(function (opts) {
        if (!opts.publicKey) return follow(root, opts, "Could not start passkey setup.");
        return navigator.credentials.create(creationOptions(opts)).then(function (cred) {
          return postJSON("/settings/passkeys/finish", { name: name, credential: attestationJSON(cred) }, root);
        }).then(function (data) {
          follow(root, data, "That key could not be added.");
        });
      }).catch(function () {
        showError(root, "Passkey setup was cancelled.");
      }).then(function () {
        btn.disabled = false;
      });
    });
  }

  document.querySelectorAll("[data-passkey]").forEach(function (root) {
    login(root);
    enroll(root);
  });
})();
