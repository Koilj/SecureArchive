/**
 * 01-core.js
 * Bootstrap of the SecureData frontend runtime:
 *   - API / agent URL resolution, authFetch / fetchWithTimeout
 *   - Base64 helpers, WebAuthn credential (de)serialization
 *   - Passkey login / invite activation / bootstrap flows
 *   - Login screen markup + mode switching + sign-out
 *   - Passkey management (list / add / remove)
 *   - User management (CRUD + auth audit log)
 *   - UI primitives: toast, uiConfirm / uiPrompt / uiAlert, notices
 *   - Session panel + humanizeErrorText
 *   - agentEval / agentSubmit RPC wrappers
 *
 * Flat global scope. Must be loaded FIRST - all later modules reference
 * helpers and state defined here (API_URL, AUTH_SESSION, UI_STATE, etc.).
 */

const API_URL = (function resolveApiUrl() {
  const saved = (localStorage.getItem("securedataApiUrl") || "").trim();
  if (saved) return saved.replace(/\/+$/, "");
  const proto = window.location.protocol || "http:";
  const host = window.location.hostname || "127.0.0.1";
  return `${proto}//${host}:5500`;
})();

// ============================================================
// PROFILE SESSION LAYER
// ============================================================
const AUTH_SESSION_START = "authSessionStart";
const BROWSER_RSA_PREFIX = "securedataBrowserRsaV2";
const BROWSER_RSA_LEGACY_PREFIX = "securedataBrowserRsaV1";
const LOCAL_KEY_DB_NAME = "securedataLocalKeys";
const LOCAL_KEY_DB_VERSION = 1;
const LOCAL_KEY_STORE = "rsaKeys";
const LOCAL_KEY_WEBCRYPTO_MARKER = "SECUREDATA-RSA-OAEP-SHA256";
const LOCAL_KEY_ECDH_MARKER = "SECUREDATA-ECDH-P256-HKDF-SHA256";
const LOCAL_KEY_OAEP_CIPHERTEXT_PREFIX = "SDC1:OAEP-SHA256:";
const LOCAL_KEY_ENVELOPE_V2_PREFIX = "SDC2:KEY:";
const CONTENT_ENVELOPE_V2_TYPE = "securedata.content-envelope";
const CONTENT_ENVELOPE_V2_ALG = "AES-256-GCM";
const KEY_ENVELOPE_V2_ALG = "ECDH-P256-HKDF-SHA256-AES-256-GCM";
const LOCAL_UNLOCK_PREFIX = "securedataLocalUnlockV1";
const LOCAL_ARGON2_TIME = 3;
const LOCAL_ARGON2_MEM_KIB = 65536;
const LOCAL_ARGON2_HASH_LEN = 32;
const RECOVERY_BUNDLE_FORMAT = "securedata-recovery-bundle";
const RECOVERY_BUNDLE_VERSION = 2;
const RECOVERY_ARGON2_TIME = 3;
const RECOVERY_ARGON2_MEM_KIB = 131072;
const RECOVERY_ARGON2_HASH_LEN = 32;
const RECOVERY_ARGON2_PARALLELISM = 1;
const RECOVERY_PROTECTION = "Argon2id+AES-256-GCM+ECDH-P256-key-envelope";
const RECOVERY_ESCROW_FORMAT = "securedata-local-export-escrow";
const RECOVERY_DEVICE_ESCROW_FORMAT = "securedata-device-export-escrow";
const BACKEND_TIMEOUT_MS = 15000;
const AGENT_TIMEOUT_MS = 25000;
const ARGON2_TIMEOUT_MS = 15000;
const WEBAUTHN_RECENT_AUTH_WINDOW_MS = 5 * 60 * 1000;
const AUTH_CSRF_SESSION_KEY = "securedata.csrfToken.v1";

let AUTH_SESSION = null;
let LOCAL_KEY_UNLOCKED = false;
let _RECOVERY_GATE_PROMISE = null;
let _RECOVERY_GATE_RESOLVE = null;
let _RECOVERY_GATE_BUSY = false;
let _CSRF_REFRESH_PROMISE = null;

function _safeSessionStorageGet(key) {
  try {
    return window.sessionStorage ? String(window.sessionStorage.getItem(key) || "") : "";
  } catch {
    return "";
  }
}

function _safeSessionStorageSet(key, value) {
  try {
    if (!window.sessionStorage) return;
    const text = String(value || "");
    if (text) window.sessionStorage.setItem(key, text);
    else window.sessionStorage.removeItem(key);
  } catch { }
}

function currentCsrfToken() {
  const fromSession = AUTH_SESSION && AUTH_SESSION.csrf_token ? String(AUTH_SESSION.csrf_token) : "";
  if (fromSession) return fromSession;
  try {
    const fromWindow = window.AUTH_SESSION && window.AUTH_SESSION.csrf_token ? String(window.AUTH_SESSION.csrf_token) : "";
    if (fromWindow) return fromWindow;
  } catch { }
  return _safeSessionStorageGet(AUTH_CSRF_SESSION_KEY);
}

function clearCsrfToken() {
  if (AUTH_SESSION) {
    try { delete AUTH_SESSION.csrf_token; } catch { AUTH_SESSION.csrf_token = ""; }
  }
  try {
    if (window.AUTH_SESSION) delete window.AUTH_SESSION.csrf_token;
  } catch { }
  _safeSessionStorageSet(AUTH_CSRF_SESSION_KEY, "");
}

function setAuthSession(nextSession, options = {}) {
  const preserveCsrf = !(options && options.preserveCsrf === false);
  if (!nextSession) {
    AUTH_SESSION = null;
    try { window.AUTH_SESSION = null; } catch { }
    _safeSessionStorageSet(AUTH_CSRF_SESSION_KEY, "");
    return AUTH_SESSION;
  }

  const next = Object.assign({}, nextSession);
  const previousToken = preserveCsrf ? currentCsrfToken() : "";
  if (!next.csrf_token && previousToken) next.csrf_token = previousToken;
  _safeSessionStorageSet(AUTH_CSRF_SESSION_KEY, next.csrf_token || "");
  AUTH_SESSION = next;
  try {
    window.AUTH_SESSION = JSON.parse(JSON.stringify(AUTH_SESSION));
  } catch {
    window.AUTH_SESSION = AUTH_SESSION;
  }
  return AUTH_SESSION;
}

function authHeaders() {
  const headers = {};
  const token = currentCsrfToken();
  if (token) headers["X-CSRF-Token"] = token;
  return headers;
}

// ---------------------------------------------------------------------------
// Session-scoped fetch cancellation + developer-log race guard.
//
// Previously a log entry written by user A could land in user B's bucket:
//   1. User A triggers `await fetch(...)` via some refresh task.
//   2. User A logs out / user B signs in.
//   3. A's fetch resolves AFTER the session flip. Its `.then/.catch` calls
//      `log("...")`, which reads the *current* `AUTH_SESSION.username` (B)
//      and happily writes the entry under B's bucket. Cross-user leakage.
//
// Defence in depth:
//   (a) Every fetch (via `fetchWithTimeout` / `authFetch`) is wired to a
//       shared session AbortController. On login / activate / logout we
//       swap the controller, aborting all in-flight requests so A's
//       continuations resolve with a session-changed error instead of
//       running as if they were B.
//   (b) `log()` drops writes for a short window around every auth
//       transition so microtask continuations triggered synchronously by
//       the abort cannot squeeze a log entry under the wrong user.
// ---------------------------------------------------------------------------
let _SESSION_FETCH_CTRL = null;
let _AUTH_EPOCH = 0;
let _LOG_DROP_UNTIL_MS = 0;

function _currentSessionSignal() {
  if (!_SESSION_FETCH_CTRL) _SESSION_FETCH_CTRL = new AbortController();
  return _SESSION_FETCH_CTRL.signal;
}

function _bumpAuthEpoch(reason) {
  _AUTH_EPOCH++;
  _LOG_DROP_UNTIL_MS = Date.now() + 1500;
  try {
    if (_SESSION_FETCH_CTRL) _SESSION_FETCH_CTRL.abort(new DOMException("session-changed:" + (reason || ""), "AbortError"));
  } catch { }
  _SESSION_FETCH_CTRL = new AbortController();
}

function _mergeSignals(primary, secondary) {
  // Chain a user-provided AbortSignal with our session signal so callers
  // can still pass their own without losing session-level cancellation.
  if (!primary) return secondary;
  if (!secondary) return primary;
  const ctrl = new AbortController();
  const forward = (src) => {
    if (!src) return;
    if (src.aborted) { ctrl.abort(src.reason); return; }
    src.addEventListener("abort", () => ctrl.abort(src.reason), { once: true });
  };
  forward(primary);
  forward(secondary);
  return ctrl.signal;
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new DOMException("timeout", "AbortError")), Math.max(1000, Number(timeoutMs) || 30000));
  const combinedSignal = _mergeSignals(ctrl.signal, _mergeSignals(_currentSessionSignal(), opts && opts.signal));
  try {
    return await fetch(url, Object.assign({}, opts, { signal: combinedSignal }));
  } catch (err) {
    const msg = String((err && err.message) || "").toLowerCase();
    const reasonStr = String((err && err.reason && err.reason.message) || "").toLowerCase();
    if (reasonStr.startsWith("session-changed") || msg.includes("session-changed")) {
      const sc = new Error("session changed");
      sc.name = "SessionChangedError";
      throw sc;
    }
    const isAbort = err && (err.name === "AbortError" || msg.includes("abort"));
    if (isAbort) {
      throw new Error(`Request timeout: ${url}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function _headersToPlainObject(headers) {
  const out = {};
  if (!headers) return out;
  if (headers instanceof Headers) {
    headers.forEach((value, key) => { out[key] = value; });
    return out;
  }
  return Object.assign(out, headers);
}

function _isCsrfSafeMethod(method) {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

async function ensureCsrfTokenForUnsafeMethod(method) {
  if (_isCsrfSafeMethod(method)) return "";
  const existing = currentCsrfToken();
  if (existing) return existing;
  const hasSessionContext = !!(AUTH_SESSION || (() => {
    try { return window.AUTH_SESSION; } catch { return null; }
  })());
  if (!hasSessionContext) return "";
  return await refreshCsrfTokenFromSession();
}

async function refreshCsrfTokenFromSession() {
  if (!_CSRF_REFRESH_PROMISE) {
    _CSRF_REFRESH_PROMISE = (async () => {
      const res = await fetchWithTimeout(`${API_URL}/auth/session`, {
        method: "GET",
        credentials: "include"
      }, BACKEND_TIMEOUT_MS);
      const data = await res.json().catch(() => null);
      if (res.ok && data && data.ok && data.authenticated && data.session) {
        setAuthSession(data.session);
        try {
          if (typeof applyAuthSession === "function") applyAuthSession();
        } catch { }
      }
      return currentCsrfToken();
    })().finally(() => {
      _CSRF_REFRESH_PROMISE = null;
    });
  }
  return await _CSRF_REFRESH_PROMISE;
}

async function waitForArgon2Ready(timeoutMs = 5000) {
  const started = Date.now();
  while ((Date.now() - started) < Math.max(500, Number(timeoutMs) || 5000)) {
    if (window.argon2 && window.argon2.hash && window.argon2.ArgonType) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("ARGON2_BLOCKED_BY_CSP");
}

async function withTimeout(promise, timeoutMs, timeoutCode) {
  return await Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(timeoutCode || "TIMEOUT")), Math.max(1000, Number(timeoutMs) || 10000)))
  ]);
}

async function authFetch(url, opts = {}, timeoutMs = BACKEND_TIMEOUT_MS) {
  const method = String((opts && opts.method) || "GET").toUpperCase();
  await ensureCsrfTokenForUnsafeMethod(method);
  const buildOptions = () => {
    const next = Object.assign({}, opts);
    const csrfHeaders = _isCsrfSafeMethod(method) ? {} : authHeaders();
    next.headers = Object.assign({}, _headersToPlainObject(opts.headers), csrfHeaders);
    next.credentials = "include";
    return next;
  };
  let response = await fetchWithTimeout(url, buildOptions(), timeoutMs);
  if (!_isCsrfSafeMethod(method) && response && response.status === 403) {
    let errPayload = null;
    try {
      errPayload = typeof response.clone === "function"
        ? await response.clone().json().catch(() => null)
        : null;
    } catch { }
    if (errPayload && String(errPayload.error || "").toLowerCase().includes("csrf validation failed")) {
      clearCsrfToken();
      await refreshCsrfTokenFromSession();
      response = await fetchWithTimeout(url, buildOptions(), timeoutMs);
    }
  }
  return response;
}

function b64urlToBytes(text) {
  const raw = String(text || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = raw + "=".repeat((4 - (raw.length % 4)) % 4);
  return _base64ToBytes(padded);
}

function bytesToB64url(bytes) {
  return _bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function coerceCreationOptions(publicKey) {
  const next = Object.assign({}, publicKey || {});
  next.challenge = b64urlToBytes(next.challenge);
  if (next.user && next.user.id) next.user = Object.assign({}, next.user, { id: b64urlToBytes(next.user.id) });
  next.excludeCredentials = Array.isArray(next.excludeCredentials) ? next.excludeCredentials.map((item) => Object.assign({}, item, { id: b64urlToBytes(item.id) })) : [];
  return next;
}

function coerceRequestOptions(publicKey) {
  const next = Object.assign({}, publicKey || {});
  next.challenge = b64urlToBytes(next.challenge);
  next.allowCredentials = Array.isArray(next.allowCredentials) ? next.allowCredentials.map((item) => Object.assign({}, item, { id: b64urlToBytes(item.id) })) : [];
  return next;
}

function serializeCredential(cred) {
  if (!cred) return null;
  const response = cred.response || {};
  const out = {
    id: cred.id || "",
    type: cred.type || "public-key",
    response: {}
  };
  if (response.clientDataJSON) out.response.clientDataJSON = bytesToB64url(new Uint8Array(response.clientDataJSON));
  if (response.attestationObject) out.response.attestationObject = bytesToB64url(new Uint8Array(response.attestationObject));
  if (response.authenticatorData) out.response.authenticatorData = bytesToB64url(new Uint8Array(response.authenticatorData));
  if (response.signature) out.response.signature = bytesToB64url(new Uint8Array(response.signature));
  if (response.userHandle) out.response.userHandle = bytesToB64url(new Uint8Array(response.userHandle));
  if (typeof response.getTransports === "function") out.transports = response.getTransports();
  return out;
}

async function webauthnCreateDiagnostics() {
  const parts = [];
  try { parts.push(`origin=${window.location.origin}`); } catch { }
  try { parts.push(`hostname=${window.location.hostname}`); } catch { }
  try { parts.push(`secureContext=${window.isSecureContext ? "yes" : "no"}`); } catch { }
  try {
    if (window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      parts.push(`platformUV=${available ? "yes" : "no"}`);
    } else {
      parts.push("platformUV=unsupported");
    }
  } catch (err) {
    parts.push(`platformUV=error:${(err && err.name) ? err.name : "unknown"}`);
  }
  try {
    const uaData = navigator.userAgentData;
    if (uaData && Array.isArray(uaData.brands)) {
      parts.push(`browser=${uaData.brands.map((b) => `${b.brand}/${b.version}`).join(",")}`);
    } else {
      parts.push(`ua=${String(navigator.userAgent || "").slice(0, 140)}`);
    }
  } catch { }
  return parts.join("; ");
}

async function describeWebAuthnCreateError(err) {
  const name = err && err.name ? String(err.name) : "";
  const message = err && err.message ? String(err.message) : String(err || "");
  const code = err && typeof err.code !== "undefined" ? String(err.code) : "";
  const diag = await webauthnCreateDiagnostics();
  return `${name ? `${name}: ` : ""}${message}${code ? ` (code ${code})` : ""}${diag ? ` [${diag}]` : ""}`;
}

function webauthnRecentlyVerified() {
  if (!(AUTH_SESSION && AUTH_SESSION.webauthn_verified_at)) return false;
  const ts = Date.parse(String(AUTH_SESSION.webauthn_verified_at || ""));
  if (!Number.isFinite(ts)) return false;
  return (Date.now() - ts) <= WEBAUTHN_RECENT_AUTH_WINDOW_MS;
}

async function ensureRecentWebAuthnAuth({ reason = "This action requires passkey confirmation." } = {}) {
  if (webauthnRecentlyVerified()) return true;
  await uiAlert({ title: "Passkey confirmation", body: reason, tone: "info" });
  const optionsRes = await authFetch(`${API_URL}/auth/reauth/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  const optionsData = await optionsRes.json().catch(() => null);
  if (!optionsRes.ok || !optionsData || !optionsData.ok) {
    throw new Error((optionsData && optionsData.error) ? optionsData.error : "Passkey confirmation failed");
  }
  const assertion = await navigator.credentials.get({ publicKey: coerceRequestOptions(optionsData.publicKey || {}) });
  const verifyRes = await authFetch(`${API_URL}/auth/reauth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: optionsData.challenge_id,
      credential: serializeCredential(assertion)
    })
  });
  const verifyData = await verifyRes.json().catch(() => null);
  if (!verifyRes.ok || !verifyData || !verifyData.ok) {
    throw new Error((verifyData && verifyData.error) ? verifyData.error : "Passkey confirmation failed");
  }
  setAuthSession(verifyData.session || AUTH_SESSION);
  applyAuthSession();
  loadProfileData();
  return true;
}

function setLoginStatus(text, tone = "muted") {
  const el = document.getElementById("loginStatus");
  if (!el) return;
  if (!text) {
    el.classList.add("d-none");
    el.textContent = "";
    return;
  }
  el.className = `small mb-2 text-${tone}`;
  el.textContent = text;
}

async function handleLogin(e) {
  if (e) e.preventDefault();
  setLoginMode("login");
  const usernameEl = document.getElementById("loginUsername");
  const errorEl = document.getElementById("loginError");
  const btnEl = document.getElementById("loginSubmit");
  const prevBtnHtml = btnEl ? btnEl.innerHTML : "";
  if (!usernameEl) return;

  const username = (usernameEl.value || "").trim();

  if (errorEl) {
    errorEl.classList.add("d-none");
    errorEl.textContent = "";
  }
  setLoginStatus("");

  if (!username) {
    if (errorEl) {
      errorEl.textContent = "Введите логин.";
      errorEl.classList.remove("d-none");
    }
    return;
  }

  if (btnEl) btnEl.disabled = true;
  if (btnEl) btnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Signing in…';

  // Slow-warning timer: if the browser dialog takes > 4s (typical sign of QR /
  // cross-device flow), show an explicit hint instead of a silent hang.
  let slowHintTimer = 0;
  const armSlowHint = () => {
    slowHintTimer = window.setTimeout(() => {
      setLoginStatus(
        "Waiting for your phone… keep the device nearby and unlocked. Bluetooth pairing can take 10-20 seconds the first time.",
        "warning"
      );
    }, 4000);
  };
  const disarmSlowHint = () => {
    if (slowHintTimer) {
      clearTimeout(slowHintTimer);
      slowHintTimer = 0;
    }
  };

  try {
    setLoginStatus("Requesting challenge from server…");
    const optionsRes = await authFetch(`${API_URL}/auth/login/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });
    const optionsData = await optionsRes.json().catch(() => null);
    if (!optionsRes.ok || !optionsData || !optionsData.ok) {
      throw new Error((optionsData && optionsData.error) ? optionsData.error : "Login options failed");
    }
    setLoginStatus("Waiting for passkey authorization…");
    armSlowHint();
    const assertion = await navigator.credentials.get({ publicKey: coerceRequestOptions(optionsData.publicKey || {}) });
    disarmSlowHint();
    setLoginStatus("Verifying signature…");
    const verifyRes = await authFetch(`${API_URL}/auth/login/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        challenge_id: optionsData.challenge_id,
        credential: serializeCredential(assertion)
      })
    });
    const data = await verifyRes.json().catch(() => null);
    if (!verifyRes.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Passkey login failed");
    }
    _bumpAuthEpoch("login");
    setAuthSession(data.session || null, { preserveCsrf: false });
    CURRENT_USER = (AUTH_SESSION && AUTH_SESSION.username) ? AUTH_SESSION.username : username;
    // Wipe shared guest/legacy dev-log buckets so this user never inherits
    // log entries written by someone else on this device.
    try { purgeDeveloperLogLegacyKeys(); } catch { }
    try { purgeDeveloperLogGuestBucket(); } catch { }
    setLoginStatus("Preparing secure workspace…");
    applyAuthSession();
    await connectProfile();
    setLoginStatus("");
  } catch (err) {
    disarmSlowHint();
    _bumpAuthEpoch("login-failed");
    setAuthSession(null);
    CURRENT_USER = "";
    if (errorEl) {
      errorEl.textContent = humanizeErrorText((err && err.message) ? err.message : String(err));
      errorEl.classList.remove("d-none");
    }
    setLoginStatus("");
  } finally {
    disarmSlowHint();
    if (btnEl) btnEl.disabled = false;
    if (btnEl) btnEl.innerHTML = prevBtnHtml || '<i class="bi bi-box-arrow-in-right"></i> Sign In with Passkey';
  }
}

async function handleFirstLoginBootstrap(e) {
  if (e) e.preventDefault();
  const errEl = document.getElementById("loginError");
  try {
    setLoginMode("register");
    const res = await authFetch(`${API_URL}/auth/bootstrap-ticket`, { method: "POST" });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Bootstrap ticket failed");
    }
    const inviteInput = document.getElementById("loginInviteToken");
    if (inviteInput) inviteInput.value = data.invite_token || "";
    showToast("Bootstrap ticket issued. Continue with device activation below.", "info");
  } catch (err) {
    if (errEl) {
      errEl.textContent = humanizeErrorText((err && err.message) ? err.message : String(err));
      errEl.classList.remove("d-none");
    }
  }
}

async function handleInviteActivation(e) {
  if (e) e.preventDefault();
  setLoginMode("register");
  const inviteEl = document.getElementById("loginInviteToken");
  const errorEl = document.getElementById("loginError");
  const btnEl = document.getElementById("activateSubmit");
  const prevBtnHtml = btnEl ? btnEl.innerHTML : "";
  const inviteToken = (inviteEl && inviteEl.value || "").trim();
  if (!inviteToken) {
    if (errorEl) {
      errorEl.textContent = "Paste an invite/enrollment ticket first.";
      errorEl.classList.remove("d-none");
    }
    return;
  }
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("d-none");
  }
  if (btnEl) btnEl.disabled = true;
  if (btnEl) btnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Activating device…';
  setLoginStatus("");

  // Same slow-scan warning as Sign-In - warn after 4s if the browser's
  // passkey dialog hasn't been resolved (typical sign of cross-device QR).
  let slowHintTimer = 0;
  const armSlowHint = () => {
    slowHintTimer = window.setTimeout(() => {
      setLoginStatus(
        "Waiting for your phone… keep the device nearby and unlocked. Bluetooth pairing can take 10-20 seconds the first time.",
        "warning"
      );
    }, 4000);
  };
  const disarmSlowHint = () => {
    if (slowHintTimer) { clearTimeout(slowHintTimer); slowHintTimer = 0; }
  };

  try {
    setLoginStatus("Validating invite ticket…");
    const optionsRes = await authFetch(`${API_URL}/auth/activate/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ invite_token: inviteToken })
    });
    const optionsData = await optionsRes.json().catch(() => null);
    if (!optionsRes.ok || !optionsData || !optionsData.ok) {
      throw new Error((optionsData && optionsData.error) ? optionsData.error : "Activation options failed");
    }

    const username = optionsData.user && optionsData.user.username ? optionsData.user.username : "";
    const org = optionsData.user && optionsData.user.org ? optionsData.user.org : "org1";
    const userHandle = optionsData.user && optionsData.user.user_handle ? optionsData.user.user_handle : "";
    if (username) setActiveProfile(username);
    setLoginStatus("Preparing local keys (data encryption, Fabric signing)…");
    await ensureLocalKeyReady({ interactive: false, allowCreate: true });
    await ensureFabricIdentityReady({ allowCreate: true });
    const fabricCsrPem = await buildFabricEnrollmentCsrPem(username, org);
    setLoginStatus("Create a passkey for this device — follow your browser's prompt.");
    armSlowHint();
    let attestation = null;
    try {
      attestation = await navigator.credentials.create({ publicKey: coerceCreationOptions(optionsData.publicKey || {}) });
    } catch (err) {
      throw new Error(await describeWebAuthnCreateError(err));
    }
    disarmSlowHint();
    setLoginStatus("Enrolling on Fabric CA and registering the passkey…");
    const finishRes = await authFetch(`${API_URL}/auth/activate/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        invite_token: inviteToken,
        challenge_id: optionsData.challenge_id,
        credential: serializeCredential(attestation),
        content_public_key: myPublicKey,
        content_key_fingerprint: myKeyFingerprint || await computePublicKeyFingerprint(myPublicKey),
        fabric_csr_pem: fabricCsrPem
      })
    });
    const data = await finishRes.json().catch(() => null);
    if (!finishRes.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Device activation failed");
    }
    await setFabricCertificatePem(data.fabric_certificate || "", userHandle);
    _bumpAuthEpoch("activate");
    setAuthSession(data.session || null, { preserveCsrf: false });
    CURRENT_USER = (AUTH_SESSION && AUTH_SESSION.username) ? AUTH_SESSION.username : username;
    try { purgeDeveloperLogLegacyKeys(); } catch { }
    try { purgeDeveloperLogGuestBucket(); } catch { }
    setLoginStatus("Preparing secure workspace…");
    applyAuthSession();
    await connectProfile();
    setLoginStatus("");
  } catch (err) {
    disarmSlowHint();
    if (errorEl) {
      errorEl.textContent = humanizeErrorText((err && err.message) ? err.message : String(err));
      errorEl.classList.remove("d-none");
    }
    setLoginStatus("");
  } finally {
    disarmSlowHint();
    if (btnEl) btnEl.disabled = false;
    if (btnEl) btnEl.innerHTML = prevBtnHtml || '<i class="bi bi-key"></i> Activate This Device';
  }
}

async function handleLogout() {
  // Bump FIRST so any in-flight fetches of the previous user are aborted
  // before we null out AUTH_SESSION. Without this, A's fetch could resolve
  // into a catch-block that writes a log entry under whichever user
  // happens to be active at that moment.
  _bumpAuthEpoch("logout");
  try {
    await authFetch(`${API_URL}/auth/logout`, { method: "POST" });
  } catch { }
  setAuthSession(null);
  CURRENT_USER = "";
  LOCAL_KEY_UNLOCKED = false;
  IDENTITY = { clientID: "", mspID: "", role: "", department: "" };
  myPublicKey = null;
  myPrivateKey = null;
  myKeyFingerprint = "";
  FABRIC_IDENTITY = { privateKey: null, publicSpkiB64: "", certificatePem: "", userHandle: "" };
  RECOVERY_EXPORT_CACHE = { dataEncryption: null, fabricSigning: null, createdAt: "" };
  PASSKEY_CACHE = [];
  IPFS_STATUS_BY_CID = {};
  pendingRequests.clear();
  Object.keys(lastRequestTs).forEach((key) => delete lastRequestTs[key]);
  Object.keys(lastRequestStatus).forEach((key) => delete lastRequestStatus[key]);
  Object.keys(ASSET_CACHE).forEach((key) => delete ASSET_CACHE[key]);
  UI_STATE = { meClientID: null, myAssetsById: {}, pendingByAsset: {}, myReqStatusByAsset: {}, dashboardCounts: {} };
  localStorage.removeItem(AUTH_SESSION_START);
  hideUserForm();
  renderDeveloperLog();
  showLoginScreen();
}

async function checkExistingSession() {
  try {
    const res = await authFetch(`${API_URL}/auth/session`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok || !data.authenticated || !data.session) {
      setAuthSession(null);
      showLoginScreen();
      return;
    }
    // Fresh page load finds a valid session cookie - treat this as a new
    // auth transition so any stale localStorage bucket is clean and the
    // dev-log drop window is open briefly in case a previous tab left
    // pending async work behind (unlikely but cheap insurance).
    _bumpAuthEpoch("resume");
    setAuthSession(data.session, { preserveCsrf: false });
    applyAuthSession();
    await connectProfile();
  } catch (err) {
    setAuthSession(null);
    showLoginScreen();
  }
}

function _resetRecoveryGatePromise(result) {
  const resolve = _RECOVERY_GATE_RESOLVE;
  _RECOVERY_GATE_PROMISE = null;
  _RECOVERY_GATE_RESOLVE = null;
  _RECOVERY_GATE_BUSY = false;
  if (typeof resolve === "function") {
    try { resolve(result); } catch { }
  }
}

function recoveryBundleGateRequired() {
  return !!(AUTH_SESSION && AUTH_SESSION.recovery_bundle_required && !AUTH_SESSION.recovery_bundle_created);
}

function setRecoveryGateStatus(text, tone = "muted") {
  const el = document.getElementById("recoveryGateStatus");
  if (!el) return;
  if (!text) {
    el.className = "small text-muted recovery-gate-status";
    el.textContent = "";
    return;
  }
  el.className = `small recovery-gate-status text-${tone}`;
  el.textContent = text;
}

function showLoginScreen() {
  if (_RECOVERY_GATE_PROMISE) _resetRecoveryGatePromise(false);
  renderLoginScreen();
  setLoginMode("login");
  hideRecoveryGateScreen();
  hideMainApp();
  setLoginStatus("");
  const login = document.getElementById("loginScreen");
  if (login) login.style.display = "flex";
  const errorEl = document.getElementById("loginError");
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("d-none");
  }
  authFetch(`${API_URL}/auth/bootstrap-status`)
    .then((res) => res.json().catch(() => null))
    .then((data) => {
      const btn = document.getElementById("bootstrapSubmit");
      if (btn) btn.classList.toggle("d-none", !(data && data.ok && data.bootstrap_needed));
    })
    .catch(() => { });
}

function hideLoginScreen() {
  const login = document.getElementById("loginScreen");
  if (login) login.style.display = "none";
}

function hideMainApp() {
  const main = document.getElementById("mainApp");
  if (main) main.style.display = "none";
  const bar = document.getElementById("sessionBar");
  if (bar) bar.style.display = "none";
}

function showRecoveryGateScreen() {
  renderRecoveryGateScreen();
  hideLoginScreen();
  hideMainApp();
  const gate = document.getElementById("recoveryGateScreen");
  if (gate) gate.style.display = "flex";
  setRecoveryGateStatus("");
}

function hideRecoveryGateScreen() {
  const gate = document.getElementById("recoveryGateScreen");
  if (gate) gate.style.display = "none";
  setRecoveryGateStatus("");
}

function showMainApp() {
  hideLoginScreen();
  hideRecoveryGateScreen();
  const main = document.getElementById("mainApp");
  if (main) main.style.display = "block";
  const bar = document.getElementById("sessionBar");
  if (bar) bar.style.display = "flex";
}

async function handleRecoveryGateCreate() {
  if (_RECOVERY_GATE_BUSY) return;
  const btn = document.getElementById("recoveryGateCreateBtn");
  const prevHtml = btn ? btn.innerHTML : "";
  try {
    _RECOVERY_GATE_BUSY = true;
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Creating recovery bundle…';
    }
    setRecoveryGateStatus("Choose a recovery passphrase and complete the protected export for this account.");
    const created = await createRecoveryBundle({ mandatory: true });
    if (!created) {
      setRecoveryGateStatus("Recovery bundle is still required. Complete the protected export to continue.", "danger");
      return;
    }
    setRecoveryGateStatus("Recovery bundle created. Opening your workspace…", "success");
    _resetRecoveryGatePromise(true);
  } catch (err) {
    setRecoveryGateStatus(humanizeErrorText((err && err.message) ? err.message : String(err)), "danger");
  } finally {
    _RECOVERY_GATE_BUSY = false;
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = prevHtml || '<i class="bi bi-shield-check"></i> Create Recovery Bundle';
    }
  }
}

async function runMandatoryRecoveryBundleGate() {
  if (!recoveryBundleGateRequired()) {
    hideRecoveryGateScreen();
    return true;
  }
  if (_RECOVERY_GATE_PROMISE) {
    showRecoveryGateScreen();
    return _RECOVERY_GATE_PROMISE;
  }
  showRecoveryGateScreen();
  _RECOVERY_GATE_PROMISE = new Promise((resolve) => {
    _RECOVERY_GATE_RESOLVE = resolve;
  });
  return _RECOVERY_GATE_PROMISE;
}

function applyAuthSession() {
  const s = AUTH_SESSION || {};
  CURRENT_USER = s.username || "";
  try {
    window.AUTH_SESSION = AUTH_SESSION ? JSON.parse(JSON.stringify(AUTH_SESSION)) : null;
  } catch {
    window.AUTH_SESSION = AUTH_SESSION || null;
  }

  if (s.session_started_at) {
    localStorage.setItem(AUTH_SESSION_START, s.session_started_at);
  }

  const badge = document.getElementById("activeProfileBadge");
  if (badge) {
    const parts = [s.username || "—"];
    if (s.org) parts.push(String(s.org).toUpperCase());
    badge.textContent = parts.join(" · ");
  }

  const sessName = document.getElementById("sessBarName");
  if (sessName) sessName.textContent = s.display_name || s.username || "—";
  const sessRole = document.getElementById("sessBarRole");
  if (sessRole) {
    sessRole.textContent = s.role || "—";
    sessRole.className = roleBadgeClass(s.role || "");
  }
  const sessDept = document.getElementById("sessBarDept");
  if (sessDept) sessDept.textContent = s.department || "—";
  const sessFabric = document.getElementById("sessBarFabric");
  if (sessFabric) {
    const bits = [];
    if (s.org) bits.push(String(s.org).toUpperCase());
    if (s.msp_id) bits.push(s.msp_id);
    sessFabric.textContent = bits.join(" · ");
  }

  // Per-role tab visibility is owned by applyRoleVisibility() in
  // 04-identity-drawer.js. Do NOT toggle role-managed tabs from here.
  renderDeveloperLog();
}

function roleBadgeClass(role) {
  const map = { "Admin": "bg-danger", "SecurityService": "bg-warning text-dark", "Researcher": "bg-info text-dark", "MLService": "bg-secondary", "RiskService": "bg-danger", "Viewer": "bg-light text-dark" };
  return "badge " + (map[role] || "bg-secondary");
}

function statusBadgeHTML(status) {
  const map = { "active": "status-active", "blocked": "status-blocked", "deactivated": "status-deactivated", "pending": "status-pending", "revoked": "status-deactivated" };
  return `<span class="badge ${map[status] || "bg-secondary"}">${status}</span>`;
}

function showProfileTab() {
  showSettingsTab();
  loadProfileData();
  loadPasskeys({ silent: true }).catch(() => { });
}

function loadProfileData() {
  if (!AUTH_SESSION) return;
  const u = AUTH_SESSION;
  const el = (id) => document.getElementById(id);
  const setTextSafe = (id, value) => {
    const node = el(id);
    if (!node) return;
    node.textContent = (value === undefined || value === null || value === "") ? "—" : String(value);
  };
  const setHtmlSafe = (id, value) => {
    const node = el(id);
    if (!node) return;
    setSanitizedHtml(node, value);
  };
  const recoveryRequired = !!u.recovery_bundle_required;
  const recoveryCreated = !!u.recovery_bundle_created;
  const passkeyCount = Number(u.passkey_count || 0);

  setTextSafe("profUsername", u.username);
  setTextSafe("profDisplayName", u.display_name || u.username);
  const profRole = el("profRole");
  if (profRole) {
    profRole.textContent = u.role || "—";
    profRole.className = roleBadgeClass(u.role);
  }
  setTextSafe("profDepartment", u.department || "—");
  setTextSafe("profEmail", "—");
  setTextSafe("profFabric", u.client_id || "—");
  setHtmlSafe("profStatus", statusBadgeHTML(u.status || "active"));
  setTextSafe("profCreated", u.created_at || "—");
  setTextSafe("profLastLogin", u.last_login || "—");
  setTextSafe("profLoginCount", (u.login_count === undefined || u.login_count === null) ? "—" : String(u.login_count));

  setTextSafe("profSessionStart", u.session_started_at || localStorage.getItem(AUTH_SESSION_START) || "—");
  setTextSafe("profSessionFabric", u.org ? `${String(u.org).toUpperCase()} / ${u.msp_id || "—"}` : "—");
  setTextSafe("profSessionAgent", `${API_URL}/fabric`);
  setTextSafe("profPermissions", "WebAuthn login plus device-local Fabric signing and device-local data decryption");
  if (el("profLoginMethod")) el("profLoginMethod").textContent = "Passkey / WebAuthn";
  if (el("profPasskeyCount")) el("profPasskeyCount").textContent = passkeyCount > 0 ? `${passkeyCount} registered` : "No passkeys on record";
  if (el("profContentKeyState")) el("profContentKeyState").textContent = myPublicKey ? "Present on this device (non-exportable working key)" : "Missing on this device";
  if (el("profFabricKeyState")) el("profFabricKeyState").textContent = (FABRIC_IDENTITY && FABRIC_IDENTITY.privateKey) ? "Present on this device (non-exportable working key)" : "Missing on this device";
  if (el("profRecoveryState")) {
    if (recoveryCreated) {
      el("profRecoveryState").textContent = "Created and recorded on-ledger";
    } else if (recoveryRequired) {
      el("profRecoveryState").textContent = "Required before relying on this account";
    } else {
      el("profRecoveryState").textContent = "Not recorded yet";
    }
  }
  if (el("profRecoveryCreated")) el("profRecoveryCreated").textContent = u.recovery_bundle_created_at || "—";
  renderPasskeyList();
}

function renderPasskeyList() {
  const box = document.getElementById("profPasskeyList");
  if (!box) return;
  if (!Array.isArray(PASSKEY_CACHE) || PASSKEY_CACHE.length === 0) {
    box.innerHTML = `<div class="settings-empty-state">No passkeys loaded yet for this device.</div>`;
    return;
  }
  box.innerHTML = PASSKEY_CACHE.map((item) => {
    const label = item.label || item.credentialID || "Passkey";
    const created = item.createdAt || "—";
    const used = item.lastUsedAt || "never";
    const credId = encodeURIComponent(item.credentialID || "");
    return `
      <div class="settings-passkey-card d-flex justify-content-between align-items-start gap-3">
        <div>
          <div class="fw-semibold">${escapeHtml(label)}</div>
          <div class="small text-muted">Created: ${escapeHtml(created)}</div>
          <div class="small text-muted">Last used: ${escapeHtml(used)}</div>
        </div>
        <button class="btn btn-sm btn-outline-danger" type="button" onclick="removePasskey('${credId}')">
          <i class="bi bi-trash"></i> Remove
        </button>
      </div>
    `;
  }).join("");
}

async function loadPasskeys({ silent = false } = {}) {
  try {
    const res = await authFetch(`${API_URL}/auth/passkeys`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) throw new Error((data && data.error) ? data.error : "Unable to load passkeys");
    PASSKEY_CACHE = Array.isArray(data.passkeys) ? data.passkeys : [];
    if (AUTH_SESSION) {
      AUTH_SESSION.passkey_count = Number(data.count || PASSKEY_CACHE.length || 0);
      applyAuthSession();
    }
    loadProfileData();
    return PASSKEY_CACHE;
  } catch (err) {
    if (!silent) showToast(humanizeErrorText((err && err.message) ? err.message : String(err)), "warning");
    return [];
  }
}

async function registerAdditionalPasskey() {
  try {
    await ensureRecentWebAuthnAuth({ reason: "Registering a new passkey requires a fresh passkey confirmation first." });
    const label = await uiPrompt({
      title: "Register passkey",
      label: "Device label",
      placeholder: "e.g. Work laptop",
      value: "",
      okText: "Continue",
      cancelText: "Cancel"
    });
    if (label === null) return false;
    const optionsRes = await authFetch(`${API_URL}/auth/passkeys/register/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const optionsData = await optionsRes.json().catch(() => null);
    if (!optionsRes.ok || !optionsData || !optionsData.ok) {
      throw new Error((optionsData && optionsData.error) ? optionsData.error : "Passkey registration failed");
    }
    let attestation = null;
    try {
      attestation = await navigator.credentials.create({ publicKey: coerceCreationOptions(optionsData.publicKey || {}) });
    } catch (err) {
      throw new Error(await describeWebAuthnCreateError(err));
    }
    const finishRes = await authFetch(`${API_URL}/auth/passkeys/register/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: optionsData.challenge_id,
        label: String(label || "").trim(),
        credential: serializeCredential(attestation)
      })
    });
    const finishData = await finishRes.json().catch(() => null);
    if (!finishRes.ok || !finishData || !finishData.ok) {
      throw new Error((finishData && finishData.error) ? finishData.error : "Passkey registration failed");
    }
    setAuthSession(finishData.session || AUTH_SESSION);
    PASSKEY_CACHE = Array.isArray(finishData.passkeys) ? finishData.passkeys : PASSKEY_CACHE;
    await _refreshAuthSessionState();
    loadProfileData();
    showToast("New passkey registered for this account.", "success");
    return true;
  } catch (err) {
    showToast(humanizeErrorText((err && err.message) ? err.message : String(err)), "danger");
    return false;
  }
}

async function removePasskey(encodedCredentialId) {
  try {
    const credentialId = decodeURIComponent(String(encodedCredentialId || ""));
    const confirmed = await uiConfirm({
      title: "Remove passkey",
      body: "This removes the selected passkey from the WebAuthn identity. Make sure another passkey is still available before continuing.",
      okText: "Remove",
      cancelText: "Cancel",
      okClass: "btn-danger"
    });
    if (!confirmed) return false;
    await ensureRecentWebAuthnAuth({ reason: "Removing a passkey requires a fresh passkey confirmation first." });
    const res = await authFetch(`${API_URL}/auth/passkeys/${encodeURIComponent(credentialId)}`, { method: "DELETE" });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Passkey removal failed");
    }
    setAuthSession(data.session || AUTH_SESSION);
    PASSKEY_CACHE = PASSKEY_CACHE.filter((item) => String(item.credentialID || "") !== credentialId);
    await _refreshAuthSessionState();
    loadProfileData();
    showToast("Passkey removed from this account.", "success");
    return true;
  } catch (err) {
    showToast(humanizeErrorText((err && err.message) ? err.message : String(err)), "danger");
    return false;
  }
}

function esc(s) {
  return typeof escapeHtml === "function"
    ? escapeHtml(String(s || ""))
    : String(s || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function loadUsersList() {
  const tbody = document.getElementById("usersTableBody");
  if (!tbody) return;
  if (!(AUTH_SESSION && AUTH_SESSION.role === "SecurityService")) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">Users are visible only to SecurityService.</td></tr>';
    return;
  }
  tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">Loading…</td></tr>';
  try {
    const res = await authFetch(`${API_URL}/auth/users`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Load users failed");
    }
    const users = Array.isArray(data.users) ? data.users : [];
    if (!users.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No users registered yet.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map((u) => {
      const blocked = u.status === "blocked";
      const inviteStatus = String(u.invite_status || "").toLowerCase();
      let actionBtn = '<span class="text-muted">—</span>';
      if (u.user_id) {
        actionBtn = `<button class="btn btn-sm ${blocked ? "btn-outline-success" : "btn-outline-danger"}" onclick="userAction('${blocked ? "unblock" : "block"}','${jsQuote(u.user_id)}','${jsQuote(u.username)}')">${blocked ? "Unblock" : "Block"}</button>`;
      } else if (u.status === "pending") {
        actionBtn = `
          <div class="d-flex flex-wrap gap-1">
            <button class="btn btn-sm btn-outline-primary" onclick="inviteAction('reissue','${jsQuote(u.username)}')">Reissue</button>
            <button class="btn btn-sm btn-outline-warning" onclick="inviteAction('revoke','${jsQuote(u.username)}')">Revoke</button>
            <button class="btn btn-sm btn-outline-danger" onclick="inviteAction('delete','${jsQuote(u.username)}')">Delete</button>
          </div>
        `;
      } else if (inviteStatus === "revoked") {
        actionBtn = `
          <div class="d-flex flex-wrap gap-1">
            <button class="btn btn-sm btn-outline-primary" onclick="inviteAction('reissue','${jsQuote(u.username)}')">Reissue</button>
            <button class="btn btn-sm btn-outline-danger" onclick="inviteAction('delete','${jsQuote(u.username)}')">Delete</button>
          </div>
        `;
      }
      const recoveryLabel = u.recovery_bundle_created
        ? `Recovery: ${esc(u.recovery_bundle_created_at || "created")}`
        : (u.user_id ? "Recovery missing" : "Recovery pending activation");
      const fabricProfile = u.user_id
        ? `<code>${esc(u.user_id || "—")}</code><div class="text-muted small">${esc(u.msp_id || "—")}</div>`
        : `<span class="text-muted">Pending activation</span>${u.invite_expires_at ? `<div class="text-muted small">Expires ${esc(u.invite_expires_at)}</div>` : ""}`;
      return `
        <tr>
          <td><b>${esc(u.username)}</b></td>
          <td>${esc(u.display_name || u.username)}</td>
          <td><span class="${roleBadgeClass(u.role)}">${esc(u.role || "—")}</span></td>
          <td>${esc(u.department || "—")}</td>
          <td>${fabricProfile}</td>
          <td>${statusBadgeHTML(u.status || "active")}<div class="text-muted small mt-1">${recoveryLabel}</div></td>
          <td>${esc(u.last_login || "—")}</td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-3">${esc(humanizeErrorText((err && err.message) ? err.message : String(err)))}</td></tr>`;
  }
}

function showCreateUserForm() {
  const card = document.getElementById("userFormCard");
  if (card) card.classList.remove("d-none");
  const title = document.getElementById("userFormTitle");
  if (title) title.innerHTML = '<i class="bi bi-person-plus"></i> Create User';
  const err = document.getElementById("ufError");
  if (err) { err.classList.add("d-none"); err.textContent = ""; }
  ["ufUsername", "ufDepartment"].forEach((id) => {
    const node = document.getElementById(id);
    if (node) node.value = "";
  });
  const role = document.getElementById("ufRole");
  if (role) role.value = "Researcher";
  const org = document.getElementById("ufOrg");
  if (org) org.value = "org1";
}

function hideUserForm() {
  const card = document.getElementById("userFormCard");
  if (card) card.classList.add("d-none");
}

async function submitUserForm() {
  const errEl = document.getElementById("ufError");
  if (errEl) { errEl.classList.add("d-none"); errEl.textContent = ""; }

  const payload = {
    username: document.getElementById("ufUsername")?.value || "",
    role: document.getElementById("ufRole")?.value || "Researcher",
    department: document.getElementById("ufDepartment")?.value || "",
    org: document.getElementById("ufOrg")?.value || "org1"
  };

  try {
    const res = await authFetch(`${API_URL}/auth/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) {
      throw new Error((data && data.error) ? data.error : "Create user failed");
    }

    const created = (data && data.user) ? data.user : {};
    showToast(`Invite issued for ${created.username || payload.username}`, "success");
    hideUserForm();
    await loadUsersList();
    try {
      if (navigator.clipboard && created.invite_token) {
        await navigator.clipboard.writeText(created.invite_token);
      }
    } catch { }

    await uiPrompt({
      title: "Invite Ticket",
      label: "Share this enrollment ticket over a secure channel. If it is lost, use Reissue instead of reusing the old ticket.",
      value: created.invite_token || "",
      okText: "Close",
      cancelText: "",
      multiline: true
    });
  } catch (error) {
    if (errEl) {
      errEl.textContent = humanizeErrorText((error && error.message) ? error.message : String(error));
      errEl.classList.remove("d-none");
    }
  }
}

async function userAction(action, userId, username) {
  try {
    if (!userId) throw new Error("Missing user ID");
    if (action === "block") {
      await agentSubmit("BlockUser", [userId, `blocked by SecurityService for ${username}`]);
      showToast(`User ${username} blocked`, "warning");
    } else if (action === "unblock") {
      await agentSubmit("UnblockUser", [userId]);
      showToast(`User ${username} unblocked`, "success");
    } else {
      throw new Error("Unsupported action");
    }
    await loadUsersList();
    try { await secLoadUsers(); } catch { }
  } catch (err) {
    showToast(humanizeErrorText((err && err.message) ? err.message : String(err)), "danger");
  }
}

async function inviteAction(action, username) {
  const normalized = String(username || "").trim();
  if (!normalized) {
    showToast("Missing username", "danger");
    return;
  }
  try {
    if (action === "reissue") {
      const ok = await uiConfirm({
        title: "Reissue invite",
        body: "A new invite ticket with a new identifier, expiration time, and secret will be issued immediately. Any previous invite for this pending user will stop working at once.",
        okText: "Reissue invite",
        cancelText: "Cancel",
        okClass: "btn-primary"
      });
      if (!ok) return;
      const res = await authFetch(`${API_URL}/auth/users/${encodeURIComponent(normalized)}/reissue`, { method: "POST" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || !data.ok || !data.user) {
        throw new Error((data && data.error) ? data.error : "Invite reissue failed");
      }
      const created = data.user;
      try {
        if (navigator.clipboard && created.invite_token) {
          await navigator.clipboard.writeText(created.invite_token);
        }
      } catch { }
      await uiPrompt({
        title: "New Invite Ticket",
        label: "Share this new enrollment ticket through a secure channel. The previous ticket is already invalid.",
        value: created.invite_token || "",
        okText: "Close",
        cancelText: "",
        multiline: true
      });
      showToast(`Invite reissued for ${normalized}`, "success");
    } else if (action === "revoke") {
      const reason = await uiPrompt({
        title: "Revoke invite",
        label: "Optional reason",
        placeholder: "Why is this invite being revoked?",
        value: "",
        multiline: true,
        okText: "Revoke",
        cancelText: "Cancel"
      });
      if (reason === null) return;
      const ok = await uiConfirm({
        title: "Revoke pending invite",
        body: "The current invite ticket will stop working immediately. The user record will remain pending so you can reissue a fresh invite later.",
        okText: "Revoke invite",
        cancelText: "Cancel",
        okClass: "btn-warning"
      });
      if (!ok) return;
      const res = await authFetch(`${API_URL}/auth/users/${encodeURIComponent(normalized)}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason || "" })
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || !data.ok) {
        throw new Error((data && data.error) ? data.error : "Invite revoke failed");
      }
      showToast(`Invite revoked for ${normalized}`, "warning");
    } else if (action === "delete") {
      const ok = await uiConfirm({
        title: "Delete pending user",
        body: "This removes the pending user record and invite data. Use this only when the account was never activated.",
        okText: "Delete pending user",
        cancelText: "Cancel",
        okClass: "btn-danger"
      });
      if (!ok) return;
      const res = await authFetch(`${API_URL}/auth/users/${encodeURIComponent(normalized)}`, { method: "DELETE" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || !data.ok) {
        throw new Error((data && data.error) ? data.error : "Pending user delete failed");
      }
      showToast(`Pending user ${normalized} deleted`, "success");
    } else {
      throw new Error("Unsupported invite action");
    }
    await loadUsersList();
    try { await loadAuthAudit(); } catch { }
  } catch (err) {
    showToast(humanizeErrorText((err && err.message) ? err.message : String(err)), "danger");
  }
}

async function loadAuthAudit() {
  const tbody = document.getElementById("authAuditBody");
  if (!tbody) return;
  if (!(AUTH_SESSION && AUTH_SESSION.role === "SecurityService")) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Auth audit is visible only to SecurityService.</td></tr>';
    return;
  }
  tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Loading…</td></tr>';
  try {
    const res = await authFetch(`${API_URL}/auth/audit`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.ok) throw new Error((data && data.error) ? data.error : "Failed to load auth audit");
    const items = Array.isArray(data.items) ? data.items : [];
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No auth events yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map((item) => `
      <tr>
        <td>${esc(item.time || "—")}</td>
        <td><span class="badge ${auditEventBadge(item.event)}">${esc(item.event || "—")}</span></td>
        <td>${esc(item.user || "—")}</td>
        <td>${esc(item.actor || "—")}</td>
        <td>${esc(item.details || "—")}</td>
        <td>${esc(item.ip || "—")}</td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-3">${esc(humanizeErrorText((err && err.message) ? err.message : String(err)))}</td></tr>`;
  }
}

function auditEventBadge(eventName) {
  const e = String(eventName || "").toLowerCase();
  if (e.includes("failed")) return "bg-danger";
  if (e.includes("password")) return "bg-warning text-dark";
  if (e.includes("created")) return "bg-info text-dark";
  if (e.includes("logout")) return "bg-secondary";
  return "bg-success";
}

function setLoginMode(mode = "login") {
  const normalized = mode === "register" ? "register" : "login";
  const login = document.getElementById("loginScreen");
  if (login) login.dataset.mode = normalized;
  const signInPanel = document.getElementById("loginModeSignIn");
  const registerPanel = document.getElementById("loginModeRegister");
  const signInBtn = document.getElementById("loginModeBtnSignIn");
  const registerBtn = document.getElementById("loginModeBtnRegister");
  if (signInPanel) signInPanel.classList.toggle("d-none", normalized !== "login");
  if (registerPanel) registerPanel.classList.toggle("d-none", normalized !== "register");
  if (signInBtn) signInBtn.className = normalized === "login" ? "btn btn-primary" : "btn btn-outline-secondary";
  if (registerBtn) registerBtn.className = normalized === "register" ? "btn btn-primary" : "btn btn-outline-secondary";
}

function renderLoginScreen() {
  const login = document.getElementById("loginScreen");
  if (!login) return;
  if (login.dataset.ready === "1") return;
  login.innerHTML = `
    <div class="card login-card fade-up">
      <div class="card-body p-4 p-lg-5">
        <div class="login-shell">
          <div class="login-hero">
            <div class="section-kicker">Secure research data repository</div>
            <div class="login-logo mb-3">SecureData Archive</div>
            <div class="text-muted mb-3">Sign in with passkeys, keep private keys on-device, and work with protected research assets under governed access and full audit visibility.</div>
            <div class="small text-muted">Choose the access path that matches this browser and your account state:</div>
            <div class="login-steps">
              <div class="login-step">
                <b>Protected storage</b>
                Research files remain encrypted, classified, and controlled across repository infrastructure.
              </div>
              <div class="login-step">
                <b>Governed collaboration</b>
                Access requests, approvals, downloads, and security actions are tracked for audit review.
              </div>
              <div class="login-step">
                <b>Device-held identities</b>
                Passkeys, Fabric signing keys, and content-decryption keys stay on this device rather than in a server wallet.
              </div>
            </div>
          </div>
          <div>
            <div class="d-flex flex-wrap gap-2 mb-3 login-mode-switch">
              <button id="loginModeBtnSignIn" class="btn btn-primary" type="button">Sign In</button>
              <button id="loginModeBtnRegister" class="btn btn-outline-secondary" type="button">Register Device</button>
            </div>
            <div id="loginError" class="alert alert-danger py-2 d-none small"></div>
            <div id="loginStatus" class="small text-muted mb-2 d-none"></div>
            <div id="loginModeSignIn" class="login-panel">
              <div class="login-panel-title">Sign in to the repository</div>
              <div class="login-panel-help">Use this when the current browser or device has already been activated for your account.</div>
              <form id="loginForm">
                <div class="mb-3">
                  <label class="form-label fw-semibold">Username</label>
                  <input id="loginUsername" class="form-control" autocomplete="username webauthn" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="e.g. SecurityService">
                  <div class="form-text">If your passkey lives on a phone, the browser will display a QR code. First cross-device scan typically takes <b>10-20&nbsp;seconds</b> while the Bluetooth channel is established &mdash; keep your phone nearby and unlocked.</div>
                </div>
                <div class="d-grid gap-2">
                  <button id="loginSubmit" class="btn btn-primary" type="submit"><i class="bi bi-box-arrow-in-right"></i> Continue with Passkey</button>
                </div>
              </form>
            </div>
            <div id="loginModeRegister" class="login-panel d-none">
              <div class="login-panel-title">Activate this workspace</div>
              <div class="login-panel-help">Paste the enrollment ticket issued by SecurityService to activate this browser/device and create the local identities required for secure work.</div>
              <div class="mb-3">
                <label class="form-label fw-semibold">Invite / Enrollment Ticket</label>
                <textarea id="loginInviteToken" class="form-control" rows="3" placeholder="Paste the invite token issued by SecurityService"></textarea>
                <div class="form-text">
                  If you plan to create the passkey on a phone, your browser will present a QR code after you click <b>Activate This Device</b>.
                  The first cross-device scan typically takes <b>10-20&nbsp;seconds</b> while the Bluetooth channel is established &mdash; keep your phone nearby and unlocked.
                </div>
              </div>
              <div class="small text-muted mb-3">Use this mode only for first-time activation on the current browser/device. The workspace remains locked until the mandatory recovery bundle is created and downloaded.</div>
              <div class="d-grid gap-2">
                <button id="activateSubmit" class="btn btn-outline-dark" type="button"><i class="bi bi-key"></i> Activate this device</button>
                <button id="bootstrapSubmit" class="btn btn-outline-secondary" type="button"><i class="bi bi-shield-lock"></i> Bootstrap SecurityService</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
  const form = document.getElementById("loginForm");
  if (form) form.addEventListener("submit", handleLogin);
  const activateBtn = document.getElementById("activateSubmit");
  if (activateBtn) activateBtn.addEventListener("click", handleInviteActivation);
  const bootstrapBtn = document.getElementById("bootstrapSubmit");
  if (bootstrapBtn) bootstrapBtn.addEventListener("click", handleFirstLoginBootstrap);
  const signInModeBtn = document.getElementById("loginModeBtnSignIn");
  if (signInModeBtn) signInModeBtn.addEventListener("click", () => setLoginMode("login"));
  const registerModeBtn = document.getElementById("loginModeBtnRegister");
  if (registerModeBtn) registerModeBtn.addEventListener("click", () => setLoginMode("register"));
  login.dataset.ready = "1";
}

function renderRecoveryGateScreen() {
  const gate = document.getElementById("recoveryGateScreen");
  if (!gate) return;
  const username = escapeHtml((AUTH_SESSION && AUTH_SESSION.username) ? AUTH_SESSION.username : "—");
  const displayName = escapeHtml((AUTH_SESSION && (AUTH_SESSION.display_name || AUTH_SESSION.username)) ? (AUTH_SESSION.display_name || AUTH_SESSION.username) : "Repository account");
  const role = escapeHtml((AUTH_SESSION && AUTH_SESSION.role) ? AUTH_SESSION.role : "Pending identity sync");
  gate.innerHTML = `
    <div class="card recovery-gate-card fade-up">
      <div class="card-body p-4 p-lg-5">
        <div class="recovery-gate-shell">
          <div>
            <div class="section-kicker">Account protection required</div>
            <div class="login-logo mb-3">Create the recovery bundle before entering the workspace</div>
            <div class="text-muted mb-4">This account cannot continue into SecureData Archive until the encrypted recovery bundle has been created and downloaded for offline storage.</div>
            <div class="recovery-gate-list">
              <div class="recovery-gate-item"><b>What it protects</b><span>The bundle contains the device-held data decryption key, Fabric signing key, and Fabric certificate encrypted with a separate recovery passphrase.</span></div>
              <div class="recovery-gate-item"><b>Why it is mandatory</b><span>Without the bundle, a device loss or browser reset can permanently block access to protected research assets.</span></div>
              <div class="recovery-gate-item"><b>What to do next</b><span>Choose a recovery passphrase, download the file, and store it offline before continuing.</span></div>
            </div>
          </div>
          <div class="recovery-gate-panel">
            <div class="settings-label">Active account</div>
            <div class="recovery-gate-identity mb-1">${displayName}</div>
            <div class="small text-muted mb-2">Username: <code>${username}</code></div>
            <div class="small text-muted mb-4">Role: ${role}</div>
            <div class="recovery-gate-callout mb-3">To proceed further, you need to create a recovery package.</div>
            <div id="recoveryGateStatus" class="small text-muted recovery-gate-status mb-3"></div>
            <div class="d-grid">
              <button id="recoveryGateCreateBtn" class="btn btn-primary" type="button"><i class="bi bi-shield-check"></i> Create Recovery Bundle</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
  const createBtn = document.getElementById("recoveryGateCreateBtn");
  if (createBtn) createBtn.addEventListener("click", handleRecoveryGateCreate);
}

document.addEventListener("DOMContentLoaded", () => {
  const settingsTab = document.getElementById("tab-settings");
  if (settingsTab) settingsTab.addEventListener("shown.bs.tab", () => {
    try { if (typeof refreshIdentity === "function") refreshIdentity(true); } catch { }
    loadProfileData();
    loadPasskeys({ silent: true }).catch(() => { });
  });
  const usersTab = document.getElementById("tab-users");
  if (usersTab) usersTab.addEventListener("shown.bs.tab", () => { loadUsersList(); loadAuthAudit(); });
  const recoveryInput = document.getElementById("recoveryBundleFileInput");
  if (recoveryInput) {
    recoveryInput.addEventListener("change", async (event) => {
      const file = event && event.target && event.target.files ? event.target.files[0] : null;
      try {
        await restoreFromRecoveryBundleFile(file);
      } finally {
        try { recoveryInput.value = ""; } catch { }
      }
    });
  }
});

// Unified Go agent: a single port multiplexes all service identities.
// MLService is accessed via X-Agent-Role on the same port from the
// backend; the browser never talks to a second agent process.
const AGENTS = {
  "SecurityService": "http://127.0.0.1:8090"
};

function agentBase() {
  return `${API_URL}/fabric`;
}

function requireAgentBase() {
  return String(agentBase() || "").trim();
}

// ============================
// Active agent profile
// ============================
function getActiveProfile() {
  return (AUTH_SESSION && AUTH_SESSION.username) ? AUTH_SESSION.username : (CURRENT_USER || "");
}

function setActiveProfile(p) {
  CURRENT_USER = p;
  const badge = document.getElementById("activeProfileBadge");
  if (badge) badge.textContent = p;
  try { renderSessionPanel(); } catch { }
  try { renderNotices(); } catch { }
  renderDeveloperLog();
}

async function editToken() {
  showToast("Session auth is handled by the backend.", "info");
}

async function handleUnauthorizedOnce() {
  _bumpAuthEpoch("unauthorized");
  setAuthSession(null);
  showLoginScreen();
  throw new Error("unauthorized");
}

function agentAuthHeaders() {
  return { "Content-Type": "application/json" };
}


const ASSET_CACHE = {};

// Prevent XSS in dynamic table rendering
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"'`=\/]/g, (s) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "`": "&#x60;",
    "=": "&#x3D;",
    "/": "&#x2F;",
    "\\": "&#x5C;"
  }[s] || s));
}

// Escape string for single-quoted JS literal in inline handlers
function jsQuote(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029")
    .replace(/</g, "\\x3C")
    .replace(/>/g, "\\x3E")
    .replace(/&/g, "\\x26");
}

function clearElement(node) {
  if (!node) return;
  while (node.firstChild) node.removeChild(node.firstChild);
}

function appendTextWithBreaks(node, value) {
  if (!node) return;
  clearElement(node);
  const lines = String(value ?? "").split(/\r?\n/);
  lines.forEach((line, index) => {
    if (index > 0) node.appendChild(document.createElement("br"));
    node.appendChild(document.createTextNode(line));
  });
}

function sanitizeHtmlFragment(html) {
  const template = document.createElement("template");
  template.innerHTML = String(html ?? "");
  const blockedTags = new Set(["SCRIPT", "IFRAME", "OBJECT", "EMBED", "BASE", "LINK", "META"]);
  const walk = document.createTreeWalker(template.content, NodeFilter.SHOW_ELEMENT);
  const remove = [];
  while (walk.nextNode()) {
    const el = walk.currentNode;
    if (blockedTags.has(el.tagName)) {
      remove.push(el);
      continue;
    }
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      const value = String(attr.value || "").trim().toLowerCase();
      if (name.startsWith("on") || value.startsWith("javascript:") || value.startsWith("data:text/html")) {
        el.removeAttribute(attr.name);
      }
    }
  }
  remove.forEach((node) => node.remove());
  return template.content;
}

function setSanitizedHtml(node, html) {
  if (!node) return;
  clearElement(node);
  node.appendChild(sanitizeHtmlFragment(html));
}

function setRoleClass(role) {
  const r = (role || "").trim();
  document.body.dataset.role = r || "unknown";
}

function toggleEl(id, show) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle("d-none", !show);
}

function setAssetsFilter(mode) {
  const sel = document.getElementById("assetFilterSelect");
  if (sel && mode) sel.value = mode;
  applyAssetSearchFilter();
  showMainTab("#pane-assets");
}

async function refreshAssetViews() {
  await Promise.allSettled([loadFiles(), loadDashboard()]);
  syncUploadResultCard();
}



// ============================
// UI helpers (no native prompt/confirm/alert in "product" UI)
// ============================
function uiHasBootstrap() {
  return !!(window.bootstrap && bootstrap.Modal);
}

function showToast(message, tone = "info") {
  // tone: "success" | "danger" | "warning" | "info"
  const wrap = document.getElementById("toastContainer");
  if (!wrap) return;
  const id = "t" + Math.random().toString(16).slice(2);
  const safeTone = ["primary", "secondary", "success", "danger", "warning", "info", "light", "dark"].includes(tone) ? tone : "info";
  const el = document.createElement("div");
  el.id = id;
  el.className = `toast align-items-center text-bg-${safeTone} border-0`;
  el.setAttribute("role", "alert");
  el.setAttribute("aria-live", "assertive");
  el.setAttribute("aria-atomic", "true");
  const row = document.createElement("div");
  row.className = "d-flex";
  const body = document.createElement("div");
  body.className = "toast-body";
  body.textContent = String(message ?? "");
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn-close btn-close-white me-2 m-auto";
  close.setAttribute("data-bs-dismiss", "toast");
  close.setAttribute("aria-label", "Close");
  row.append(body, close);
  el.appendChild(row);
  wrap.appendChild(el);
  const t = bootstrap.Toast.getOrCreateInstance(el, { delay: 3200 });
  el.addEventListener("hidden.bs.toast", () => el.remove());
  t.show();
}

async function uiConfirm({ title = "Confirm", body = "", bodyHtml = null, okText = "Confirm", cancelText = "Cancel", okClass = "btn-primary" } = {}) {
  const fallbackBody = bodyHtml === null || bodyHtml === undefined ? body : String(bodyHtml).replace(/<[^>]+>/g, " ");
  if (!uiHasBootstrap()) return window.confirm(`${title}\n\n${fallbackBody}`);
  return new Promise((resolve) => {
    const mEl = document.getElementById("confirmModal");
    document.getElementById("confirmModalTitle").textContent = title;
    const bodyEl = document.getElementById("confirmModalBody");
    if (bodyHtml !== null && bodyHtml !== undefined) {
      setSanitizedHtml(bodyEl, bodyHtml);
    } else {
      appendTextWithBreaks(bodyEl, body);
    }
    const okBtn = document.getElementById("confirmModalOk");
    const cancelBtn = document.getElementById("confirmModalCancel");
    okBtn.textContent = okText;
    okBtn.className = `btn ${okClass}`;
    cancelBtn.textContent = cancelText || "Cancel";
    cancelBtn.classList.toggle("d-none", !cancelText);

    const modal = bootstrap.Modal.getOrCreateInstance(mEl, { backdrop: "static" });
    let settled = false;

    const cleanup = () => {
      okBtn.onclick = null;
      mEl.removeEventListener("hidden.bs.modal", onHidden);
    };

    const onHidden = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Boolean(mEl.dataset.confirmResult === "ok"));
      delete mEl.dataset.confirmResult;
    };

    okBtn.onclick = () => {
      mEl.dataset.confirmResult = "ok";
      modal.hide();
    };

    mEl.addEventListener("hidden.bs.modal", onHidden);
    delete mEl.dataset.confirmResult;
    modal.show();
  });
}

async function uiPrompt({ title = "Input", label = "", value = "", placeholder = "", help = "", okText = "OK", cancelText = "Cancel", multiline = false, inputType = "text" } = {}) {
  if (!uiHasBootstrap()) return window.prompt(`${title}\n${label}`, value);
  return new Promise((resolve) => {
    const mEl = document.getElementById("promptModal");
    document.getElementById("promptModalTitle").textContent = title;
    document.getElementById("promptModalLabel").textContent = label || "";
    document.getElementById("promptModalHelp").textContent = help || "";

    const inputWrap = document.getElementById("promptModalInputWrap");
    clearElement(inputWrap);
    const inputEl = multiline ? document.createElement("textarea") : document.createElement("input");
    inputEl.id = "promptModalInput";
    inputEl.className = "form-control";
    inputEl.placeholder = String(placeholder || "");
    if (multiline) {
      inputEl.rows = 3;
    } else {
      inputEl.type = inputType === "password" ? "password" : "text";
    }
    inputWrap.appendChild(inputEl);

    inputEl.value = value || "";

    const okBtn = document.getElementById("promptModalOk");
    const cancelBtn = document.getElementById("promptModalCancel");
    okBtn.textContent = okText;
    cancelBtn.textContent = cancelText || "Cancel";
    cancelBtn.classList.toggle("d-none", !cancelText);

    const modal = bootstrap.Modal.getOrCreateInstance(mEl, { backdrop: "static" });
    let settled = false;

    const cleanup = () => {
      okBtn.onclick = null;
      mEl.removeEventListener("hidden.bs.modal", onHidden);
    };

    const onHidden = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Object.prototype.hasOwnProperty.call(mEl.dataset, "promptResult") ? mEl.dataset.promptResult : null);
      delete mEl.dataset.promptResult;
    };

    okBtn.onclick = () => {
      mEl.dataset.promptResult = (inputEl.value || "").trim();
      modal.hide();
    };

    mEl.addEventListener("hidden.bs.modal", onHidden);
    delete mEl.dataset.promptResult;
    modal.show();
    setTimeout(() => inputEl.focus(), 50);
  });
}

async function uiAlert({ title = "Notice", body = "", tone = "info", okText = "OK" } = {}) {
  if (!uiHasBootstrap()) { window.alert(`${title}\n\n${body}`); return; }
  const safeTone = ["primary", "secondary", "success", "danger", "warning", "info", "light", "dark"].includes(tone) ? tone : "info";
  await uiConfirm({
    title,
    bodyHtml: `<div class="alert alert-${safeTone} py-2 mb-0">${escapeHtml(humanizeErrorText(body))}</div>`,
    okText,
    cancelText: "",
    okClass: "btn-primary"
  });
}

async function openAccessRequestModal() {
  if (!uiHasBootstrap()) {
    const reason = await uiPrompt({ title: "Access request", label: "Reason (optional)", placeholder: "Why do you need access?", value: "", multiline: true, okText: "Submit request" });
    return (reason === null) ? null : (reason || "");
  }

  return new Promise((resolve) => {
    const mEl = document.getElementById("accessRequestModal");
    const reasonSel = document.getElementById("accessReasonSelect");
    const detailsEl = document.getElementById("accessReasonDetails");
    if (reasonSel) reasonSel.value = "Research";
    if (detailsEl) detailsEl.value = "";

    const okBtn = document.getElementById("accessRequestSubmit");
    const modal = bootstrap.Modal.getOrCreateInstance(mEl, { backdrop: "static" });

    const cleanup = () => {
      okBtn.onclick = null;
      mEl.removeEventListener("hidden.bs.modal", onHidden);
    };

    const onHidden = () => {
      cleanup();
      resolve(null);
    };

    okBtn.onclick = () => {
      const reason = (reasonSel?.value || "").trim() || "Other";
      const details = (detailsEl?.value || "").trim();
      const msg = details ? `[${reason}] ${details}` : `[${reason}]`;
      cleanup();
      modal.hide();
      resolve(msg);
    };

    mEl.addEventListener("hidden.bs.modal", onHidden);
    modal.show();
    setTimeout(() => reasonSel?.focus(), 50);
  });
}


function humanizeErrorText(text) {
  const t = (text || "").toString();
  const tl = t.toLowerCase();

  if (tl.includes("argon2_blocked_by_csp")) return "Argon2 заблокирован CSP браузера (eval/wasm). Откройте страницу без строгого CSP-расширения или разрешите unsafe-eval/wasm-unsafe-eval для localhost.";
  if (tl.includes("argon2_timeout")) return "Argon2 не ответил вовремя (таймаут). Обычно это из-за CSP/расширения безопасности браузера.";
  if (tl.includes("authentication failure") || tl.includes("notallowederror") || tl.includes("code") && tl.includes("20")) {
    const diag = t.includes("[") ? ` ${t.slice(t.indexOf("[")).trim()}` : "";
    return `Passkey/WebAuthn не смог создать ключ устройства. Откройте именно http://localhost:8000/ в полноценном Chrome/Edge, подтвердите системный passkey/биометрию/PIN и не используйте 127.0.0.1, приватный режим или встроенный браузер IDE.${diag}`;
  }
  if (tl.includes("request timeout:")) return "Таймаут запроса к backend или Fabric execution flow. Проверь, что backend на :5500 и сервисы Fabric доступны.";
  if (tl.includes("failed to fetch")) return "Не удалось связаться с агентом/бекендом. Проверь, что сервис запущен и адрес/порт верный.";
  if (tl.includes("unauthorized") || tl.includes("401")) return "Сессия истекла или вход не выполнен. Войдите снова.";
  if (tl.includes("registeruser") && tl.includes("first")) return "Профиль не зарегистрирован в сети. Открой Settings и выполни Sync Encryption Key.";
  if (tl.includes("abac") && tl.includes("deny")) return "Отклонено политикой доступа (ABAC). Проверь role/department пользователя и категорию ассета.";
  if (tl.includes("approvecategory")) return "Категория ассета ещё не подтверждена. Владелец должен выполнить ApproveCategory.";
  if (tl.includes("approved category must be a concrete category")) return "Подтвердить можно только конкретную категорию, а не Unverified/Unknown.";
  if (tl.includes("suggested category must be actionable")) return "AI пока не дал пригодную категорию для записи в ledger.";
  if (tl.includes("service mlservice is not bound")) return "MLService не привязан. SecurityService должен выполнить BindServiceIdentity.";
  if (tl.includes("caller is not bound") && tl.includes("mlservice")) return "MLService identity не совпадает с привязанным clientID (binding mismatch).";

  return t;
}

function showSettingsTab() {
  try {
    const btn = document.querySelector('button[data-bs-target="#pane-settings"]');
    if (btn && window.bootstrap) bootstrap.Tab.getOrCreateInstance(btn).show();
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch { }
}

function renderSessionPanel() {
  const prof = document.getElementById("sessProfile");
  if (prof) prof.textContent = CURRENT_USER || "—";
  setEl("sessAgentUrl", `${API_URL}/fabric`);
  setHtml("sessTokenState", `<span class="badge bg-success">PASSKEY</span> <span class="text-muted small">WebAuthn session + device-signed Fabric flow</span>`);

  const role = (IDENTITY && IDENTITY.role) ? IDENTITY.role : "—";
  const dept = (IDENTITY && IDENTITY.department) ? IDENTITY.department : "—";
  const msp = (IDENTITY && IDENTITY.mspID) ? IDENTITY.mspID : "";
  setRoleClass(role === "—" ? "" : role);

  const roleEl = document.getElementById("sessRole");
  if (roleEl) {
    roleEl.textContent = role;
    roleEl.className = "badge " + (role === "SecurityService" ? "bg-danger" : "bg-secondary");
  }
  setEl("sessDept", dept);
  setEl("sessClient", (IDENTITY && IDENTITY.clientID) ? IDENTITY.clientID : "—");
  setEl("sessMsp", msp ? ("MSP: " + msp) : "");

  // Registration badge
  const rb = document.getElementById("sessRegBadge");
  const rd = document.getElementById("sessRegDetail");
  if (rb && rd) {
    if (!IDENTITY || !IDENTITY.clientID) {
      rb.className = "badge bg-secondary";
      rb.textContent = "—";
      rd.textContent = "";
    } else if (IDENTITY.registered === true) {
      rb.className = "badge bg-success";
      rb.textContent = "REGISTERED";
      rd.textContent = "On-chain profile exists";
    } else if (IDENTITY.registered === false) {
      rb.className = "badge bg-danger";
      rb.textContent = "NOT REGISTERED";
      rd.textContent = "Activation is incomplete for this device";
    } else {
      rb.className = "badge bg-secondary";
      rb.textContent = "CHECK";
      rd.textContent = "…";
    }
  }

  // Register button state
  const br = document.getElementById("btnSettingsRegister");
  if (br) br.disabled = false;
}

function renderNotices() {
  const reg = (IDENTITY && typeof IDENTITY.registered === "boolean") ? IDENTITY.registered : null;

  const mk = (tone, msg, actionHtml = "") => `
      <div class="alert alert-${tone} py-2 mb-2">
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
          <div>${msg}</div>
          ${actionHtml}
        </div>
      </div>`;

  let assetsMsg = "";

  if (reg === false) {
    const a = `<button class="btn btn-sm btn-outline-success" type="button" onclick="showLoginScreen()"><i class="bi bi-key"></i> Activate device</button>`;
    assetsMsg = mk("danger", "This device is not activated for the current ledger profile. Upload/requests may fail.", a);
  }

  const aEl = document.getElementById("assetsNotice");
  if (aEl) aEl.innerHTML = assetsMsg;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function agentEval(fn, args = [], opts = {}) {
  const timeoutMs = Math.max(1000, Number((opts && opts.timeoutMs) || AGENT_TIMEOUT_MS));
  const r = await authFetch(`${API_URL}/fabric/eval`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ function: fn, args: _normalizeArgs(args) })
  }, timeoutMs);
  const j = await r.json();
  if (!j.ok) throw new Error(j.error || "agent eval failed");
  if (j.needs_signature) {
    const signature_b64 = await signFabricPayloadB64(j.sign_input_b64 || "");
    const r2 = await authFetch(`${API_URL}/fabric/eval`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flow_id: j.flow_id, signature_b64 })
    }, timeoutMs);
    const j2 = await r2.json();
    if (!j2.ok) throw new Error(j2.error || "agent eval failed");
    return j2.result ?? j2.text;
  }
  return j.result ?? j.text;
}

async function agentSubmit(fn, args = [], opts = {}) {
  // Fabric can return MVCC_READ_CONFLICT (status code 11) on concurrent writes.
  // Correct client behavior: retry a few times with backoff.
  const maxAttempts = Math.max(1, Number((opts && opts.maxAttempts) || 3));
  const timeoutMs = Math.max(1000, Number((opts && opts.timeoutMs) || AGENT_TIMEOUT_MS));
  let lastErr = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      let r = await authFetch(`${API_URL}/fabric/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ function: fn, args: _normalizeArgs(args) })
      }, timeoutMs);

      let j = await r.json();
      if (!j.ok) {
        const msg = String(j.error || "agent submit failed");
        if (/MVCC_READ_CONFLICT|status code\s+11|commit with status code 11/i.test(msg) && attempt < maxAttempts) {
          await sleep(200 * attempt);
          continue;
        }
        throw new Error(msg);
      }

      while (j && j.needs_signature) {
        const signature_b64 = await signFabricPayloadB64(j.sign_input_b64 || "");
        r = await authFetch(`${API_URL}/fabric/submit`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flow_id: j.flow_id, signature_b64 })
        }, timeoutMs);
        j = await r.json();
        if (!j.ok) {
          throw new Error(j.error || "agent submit failed");
        }
      }
      return j.result ?? j.text;
    } catch (e) {
      lastErr = e;
      const msg = String(e && e.message ? e.message : e);
      if (/MVCC_READ_CONFLICT|status code\s+11|commit with status code 11/i.test(msg) && attempt < maxAttempts) {
        await sleep(200 * attempt);
        continue;
      }
      throw e;
    }
  }
  throw lastErr || new Error("agent submit failed");
}
