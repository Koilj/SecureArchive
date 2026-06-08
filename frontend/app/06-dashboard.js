/**
 * 06-dashboard.js
 * Cross-profile health, activity, and setup orchestration:
 *   - checkHealth / checkHealthAll - multi-agent probe
 *   - hookTabs, showMainTab, role-aware tab switching
 *   - Audit + Downloads panel (loadActivityView + renderers)
 *   - Dashboard: loadDashboard, loadRiskDashboard, loadEvidenceTrail
 *   - Setup checklist (agents / backend / IPFS / registration / ML binding)
 *   - Dashboard register + MLService bind actions
 *   - Entry point: setTimeout(() => { initSetupChecklistUI();
 *     renderDeveloperLog(); checkExistingSession(); }, 0)
 *
 * MUST be loaded LAST.
 */

    // ============================
// Connection status (health)
// ============================
async function checkHealth(profile) {
    const base = AGENTS[profile];
    try {
        const r = await fetch(base + "/health");
        if (!r.ok) return { ok: false, status: r.status };
        const txt = await r.text();
        return { ok: true, status: r.status, text: txt };
    } catch (e) {
        return { ok: false, status: 0, error: String(e && e.message ? e.message : e) };
    }
}

/**
 * MLService shares the unified agent with SecurityService but is only usable
 * when its cert slot is actually configured inside the agent. We verify that
 * via the backend endpoint (which issues WhoAmI under X-Agent-Role: MLService)
 * so the health badge reflects real readiness, not just "agent port is open".
 */
async function checkMlServiceHealth() {
    try {
        const res = await authFetch(`${API_URL}/agent/service-identity/MLService`);
        const data = await res.json().catch(() => null);
        if (res.ok && data && data.ok && data.client_id) {
            return { ok: true, clientId: data.client_id, mspId: data.msp_id || "" };
        }
        return { ok: false, error: (data && data.error) ? data.error : `HTTP ${res.status}` };
    } catch (e) {
        return { ok: false, error: (e && e.message) ? e.message : String(e) };
    }
}

async function checkHealthAll() {
    const row = document.getElementById("connStatusRow");
    if (!row) return;
    const parts = [];
    try {
        const backend = await fetch(`${API_URL}/health`);
        parts.push(`
          <span class="badge bg-${backend.ok ? "success" : "danger"} me-2" title="${backend.ok ? "backend ok" : ("HTTP " + backend.status)}">
            ${escapeHtml("Backend")} · ${backend.ok ? "UP" : "DOWN"}
          </span>
        `);
    } catch (e) {
        parts.push(`
          <span class="badge bg-danger me-2" title="${escapeHtml(String(e && e.message ? e.message : e))}">
            ${escapeHtml("Backend")} · DOWN
          </span>
        `);
    }
    for (const p of Object.keys(AGENTS)) {
        const h = await checkHealth(p);
        const tone = h.ok ? "success" : "danger";
        const title = h.ok ? "health ok" : (h.error || ("HTTP " + h.status));
        parts.push(`
          <span class="badge bg-${tone} me-2" title="${escapeHtml(title)}">
            ${escapeHtml(p)} · ${h.ok ? "UP" : "DOWN"}
          </span>
        `);
    }
    const ml = await checkMlServiceHealth();
    parts.push(`
      <span class="badge bg-${ml.ok ? "success" : "warning"} me-2" title="${escapeHtml(ml.ok ? ("MLService agent ok · " + (ml.clientId || "")) : (ml.error || "unconfigured"))}">
        ${escapeHtml("MLService")} · ${ml.ok ? "UP" : "CHECK"}
      </span>
    `);
    row.innerHTML = parts.join("");
}

// ============================
// Tab navigation (Assets / Dashboard / Activity / Security / Settings)
// ============================
function hookTabs() {
    const tabEls = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabEls.forEach((el) => {
        el.addEventListener("shown.bs.tab", async (evt) => {
            const id = evt.target && evt.target.id ? evt.target.id : "";
          if (id === "tab-dashboard") await loadDashboard();
            if (id === "tab-activity") await loadActivityView();
          if (id === "tab-security") await loadRiskDashboard();
            if (id === "tab-settings") await checkHealthAll();
        });
    });
}

// Reload whichever tab is currently active. Used by the header refresh button
// so it does something useful regardless of the role-specific default tab.
async function refreshActiveTab() {
    const active = document.querySelector('#mainTabs .nav-link.active');
    const id = active && active.id ? active.id : "";
    try {
        switch (id) {
            case "tab-dashboard": return await loadDashboard(true);
            case "tab-assets":    return await loadFiles();
            case "tab-activity":  return await loadActivityView();
            case "tab-security":  return await loadRiskDashboard();
            case "tab-users":     { try { await loadUsersList(); } catch {} try { await loadAuthAudit(); } catch {} return; }
            case "tab-settings":  return await checkHealthAll();
            default:              return await loadFiles();
        }
    } catch (err) {
        console.error("refreshActiveTab failed", err);
        showToast((err && err.message) ? err.message : "Refresh failed", "danger");
    }
}

async function loadActivityView() {
    const out = document.getElementById("activityOut");
    const outDl = document.getElementById("downloadsOut");
    if (out) out.innerHTML = `<div class="text-muted">Loading…</div>`;
    if (outDl) outDl.innerHTML = `<div class="text-muted">Loading…</div>`;

    // default actor = me
    let me = UI_STATE.meClientID;
    if (!me) {
        try {
            const who = await agentEval("WhoAmI", []);
            me = who.clientID || who.clientId || "";
        } catch {}
    }
    const actorInput = document.getElementById("activityActorId");
    const isSecurity = !!(IDENTITY && IDENTITY.role === "SecurityService");
    if (actorInput) {
      if (isSecurity) {
        if (!actorInput.value) actorInput.value = me || "";
      } else {
        actorInput.value = me || "";
      }
    }

    const actor = isSecurity
      ? (actorInput?.value || me || "").trim()
      : (me || "").trim();
    const typeInput = document.getElementById("activityEventType");
    const eventType = (typeInput?.value || "").trim();

    // Audit events by actor or by type (SecurityService only)
    try {
      let res;
      if (eventType) {
        if (!(IDENTITY && IDENTITY.role === "SecurityService")) {
          throw new Error("Only SecurityService can query audit events by type");
        }
        res = await agentEval("QueryAuditEventsByType", [eventType]);
      } else {
        res = await agentEval("QueryAuditEventsByUser", [actor]);
      }
        const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
        out.innerHTML = renderActivityList(items, "audit");
    } catch (e) {
        out.innerHTML = `<div class="text-warning">Audit query failed: ${escapeHtml(e.message || e)}</div>`;
    }

    // Download audits by user
    const userInput = document.getElementById("downloadsUserId");
    if (userInput) {
      if (isSecurity) {
        if (!userInput.value) userInput.value = actor || "";
      } else {
        userInput.value = actor || "";
      }
    }
    const u = isSecurity
      ? (userInput?.value || actor || "").trim()
      : (actor || "").trim();

    try {
        const res = await agentEval("QueryDownloadAuditsByUser", [u]);
        const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
        outDl.innerHTML = renderActivityList(items, "download");
    } catch (e) {
        outDl.innerHTML = `<div class="text-warning">Download audit query failed: ${escapeHtml(e.message || e)}</div>`;
    }
}

function renderActivityList(items, kind) {
    if (!Array.isArray(items) || items.length === 0) {
        return `<div class="text-muted">No records.</div>`;
    }
    const sorted = items.slice().sort((a,b) => String(b.timestamp || b.Timestamp || "").localeCompare(String(a.timestamp || a.Timestamp || "")));
    let html = `<div class="list-group">`;
    for (const it of sorted) {
        const ts = it.timestamp || it.Timestamp || "";
        const tx = it.txID || it.TxID || "";
        if (kind === "download") {
            const actor = it.actorID || it.ActorID || "";
            const aid = it.assetID || it.AssetID || "";
            html += `<div class="list-group-item">
              <div class="d-flex justify-content-between">
                <div><b>DOWNLOAD</b> <code>${escapeHtml(aid)}</code></div>
                <div class="text-muted small">${escapeHtml(ts)}</div>
              </div>
              <div class="text-muted small">actor: <code>${escapeHtml(actor)}</code></div>
              ${tx ? `<div class="text-muted small">tx: <code>${escapeHtml(tx)}</code></div>` : ``}
            </div>`;
        } else {
            const typ = it.eventType || it.EventType || "EVENT";
            const actor = it.actorID || it.ActorID || "";
            const aid = it.assetID || it.AssetID || "";
            const detail = it.detail || it.Detail || "";
            html += `<div class="list-group-item">
              <div class="d-flex justify-content-between">
                <div><b>${escapeHtml(typ)}</b> ${aid ? `<code>${escapeHtml(aid)}</code>` : ""}</div>
                <div class="text-muted small">${escapeHtml(ts)}</div>
              </div>
              <div class="text-muted small">actor: <code>${escapeHtml(actor)}</code></div>
              ${detail ? `<div class="small mt-1">${escapeHtml(detail)}</div>` : ``}
              ${tx ? `<div class="text-muted small mt-1">tx: <code>${escapeHtml(tx)}</code></div>` : ``}
            </div>`;
        }
    }
    html += `</div>`;
    return html;
}

// Init
    (async () => {
        try {
            hookTabs();
        } catch (e) {
            console.error(e);
            log("❌ Init error: " + e.message);
        }
    })();



/* =========================
   Dashboard / Setup Wizard
   ========================= */

function showMainTab(paneId) {
    const btn = document.querySelector(`button[data-bs-target="${paneId}"]`);
  if (btn) {
    try { new bootstrap.Tab(btn).show(); } catch {}
    try { btn.scrollIntoView({block:"nearest"}); } catch {}
    return;
  }

  const pane = document.querySelector(paneId);
  if (!pane) return;
  document.querySelectorAll(".tab-pane").forEach(el => {
    el.classList.remove("show", "active");
  });
  pane.classList.add("show", "active");
}

function _badge(elId, tone, text, title="") {
    const el = document.getElementById(elId);
    if (!el) return;
    el.className = `badge bg-${tone}`;
    el.textContent = text;
    if (title) el.title = title;
}

function _setText(elId, text) {
    const el = document.getElementById(elId);
    if (el) el.textContent = text;
}

function _setHtml(elId, html) {
    const el = document.getElementById(elId);
    if (el) setSanitizedHtml(el, html);
}

function formatBindingDetail(label, clientId) {
    const safeLabel = escapeHtml(label || "");
    const safeClientId = escapeHtml(clientId || "");
    return `${safeLabel} <code class="binding-code" title="${safeClientId}">${safeClientId}</code>`;
}


function _normalizeArgs(args) {
    return (args || []).map(a => (a === null || a === undefined) ? "" : String(a));
}


// Legacy `agentEvalAs` / `agentSubmitAs` helpers that called a second
// agent process directly on its own port have been removed. In the
// unified-agent setup all service identities share port 8090 and are
// selected with X-Agent-Role; that header also carries AGENT_TOKEN, so
// the browser must route through the backend. Use
// `${API_URL}/agent/service-identity/<role>` for WhoAmI probes and
// `agentSubmit` for anything else.

// Unused, retained below only as a template for future backend-routed helpers.
// eslint-disable-next-line no-unused-vars
async function _agentRelayEval(role, fn, args=[]) {
    const resp = await authFetch(`${API_URL}/agent/service-identity/${encodeURIComponent(role)}`);
    const data = await resp.json().catch(() => null);
    if (!resp.ok) {
        const msg = (data && data.error) ? data.error : ("HTTP " + resp.status);
        throw new Error(msg);
    }
    if (!data || data.ok !== true) {
        throw new Error((data && data.error) ? data.error : "Unexpected response");
    }
    return (data.result !== undefined) ? data.result : (data.text !== undefined ? data.text : null);
}

async function dashCheckAgents() {
    const parts = [];
    for (const p of Object.keys(AGENTS)) {
        try {
            const r = await fetch(AGENTS[p] + "/health");
            const ok = r.ok;
      const tone = ok ? "success" : "danger";
      parts.push(`<span class="badge bg-${tone} me-2" title="${escapeHtml(ok ? "health ok" : ("HTTP "+r.status))}">${escapeHtml(p)} · ${ok ? "UP" : "DOWN"}</span>`);
        } catch (e) {
      const tone = "danger";
      parts.push(`<span class="badge bg-${tone} me-2" title="${escapeHtml(e.message || "error")}">${escapeHtml(p)} · DOWN</span>`);
        }
    }
    const ml = await checkMlServiceHealth();
    const tone = ml.ok ? "success" : "warning";
    const title = ml.ok ? ("MLService agent ok · " + (ml.clientId || "")) : (ml.error || "unconfigured");
    parts.push(`<span class="badge bg-${tone} me-2" title="${escapeHtml(title)}">${escapeHtml("MLService")} · ${ml.ok ? "UP" : "CHECK"}</span>`);
    const row = document.getElementById("dashAgentBadges");
    if (row) row.innerHTML = parts.join("");
}

async function dashCheckBackend() {
    try {
        const r = await fetch(API_URL + "/health");
        const t = await r.text();
        if (r.ok) {
            _badge("dashBackendBadge", "success", "UP", "backend health ok");
            _setText("dashBackendDetail", t.slice(0,120));
        } else {
            _badge("dashBackendBadge", "danger", "DOWN", "HTTP " + r.status);
            _setText("dashBackendDetail", t.slice(0,120));
        }
    } catch (e) {
        _badge("dashBackendBadge", "danger", "DOWN", e.message || "error");
        _setText("dashBackendDetail", e.message || "error");
    }
}

async function dashCheckIpfs() {
    try {
        const r = await fetch(`${API_URL}/health/ipfs`);
        const data = await r.json().catch(() => null);
        const detail = (data && data.detail) ? String(data.detail) : (r.ok ? "IPFS reachable from backend" : ("HTTP " + r.status));
        if (r.ok && data && data.ok) {
            _badge("dashIpfsBadge", "success", "UP", "backend -> ipfs ok");
            _setText("dashIpfsDetail", detail.slice(0,160));
            return;
        }
        _badge("dashIpfsBadge", "danger", "DOWN", (data && data.status) ? ("HTTP " + data.status) : ("HTTP " + r.status));
        _setText("dashIpfsDetail", detail.slice(0,160));
    } catch (e) {
        _badge("dashIpfsBadge", "warning", "CHECK", "Backend health probe failed");
        _setText("dashIpfsDetail", (e && e.message) ? e.message : "Unable to reach backend IPFS probe");
    }
}

async function dashCheckRegistration() {
    const btn = document.getElementById("btnDashRegister");
    if (btn) btn.style.display = "none";
    try {
        // Ensure IDENTITY is ready
        if (!IDENTITY || !IDENTITY.clientID) {
            await refreshIdentity();
        }
        const uid = (IDENTITY && IDENTITY.clientID) ? IDENTITY.clientID : "";
        if (!uid) throw new Error("No clientID");
        await agentEval("GetUserProfile", [uid]);
        _badge("dashRegBadge", "success", "REGISTERED");
        _setText("dashRegDetail", "On-chain profile exists");
    } catch (e) {
        const msg = (e && e.message) ? e.message : "not registered";
        const looksLikeNotFound = /user not found|RegisterUser first|not found/i.test(msg);
        if (looksLikeNotFound) {
            _badge("dashRegBadge", "danger", "NOT REGISTERED");
            _setText("dashRegDetail", "Open Settings to create the on-ledger profile");
            if (btn) btn.style.display = "";
        } else {
            _badge("dashRegBadge", "warning", "CHECK");
            _setText("dashRegDetail", msg);
            if (btn) btn.style.display = "";
        }
    }
}

async function waitForServiceBinding(service, expectedClientId, timeoutMs = 8000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            const binding = await agentEval("GetServiceBinding", [service]);
            const boundClientId = String((binding && (binding.clientID || binding.clientId)) || "").trim();
            if (boundClientId && (!expectedClientId || boundClientId === expectedClientId)) {
                return boundClientId;
            }
        } catch {}
        await sleep(350);
    }
    return "";
}

async function waitForAgentClientId(profile, timeoutMs = 8000) {
    // The unified Go agent multiplexes identities via X-Agent-Role on a
    // single port. The browser must go through the backend so the AGENT_TOKEN
    // stays server-side and we don't ever try to fetch a stale legacy port
    // such as :8091, which surfaces as 'Failed to fetch' with no useful
    // context for the user.
    const deadline = Date.now() + timeoutMs;
    const encoded = encodeURIComponent(profile);
    let lastErr = "";
    while (Date.now() < deadline) {
        try {
            const res = await authFetch(`${API_URL}/agent/service-identity/${encoded}`);
            const data = await res.json().catch(() => null);
            if (res.ok && data && data.ok && data.client_id) {
                return String(data.client_id).trim();
            }
            lastErr = (data && data.error) ? data.error : `HTTP ${res.status}`;
            if (res.status >= 500) {
                // Transient - retry.
            } else if (res.status === 404 || res.status === 400) {
                // Configuration problem: the role is unknown to the backend.
                throw new Error(lastErr);
            }
        } catch (e) {
            lastErr = (e && e.message) ? e.message : String(e);
        }
        await sleep(500);
    }
    throw new Error(lastErr || `Unable to read ${profile} clientID`);
}

async function dashCheckMlBinding() {
    const btn = document.getElementById("btnDashBindMl");
    if (btn) btn.style.display = "none";
    try {
        const mlClientId = await waitForAgentClientId("MLService", 6000);

        const binding = await agentEval("GetServiceBinding", ["MLService"]);
        const boundClientId = String((binding && (binding.clientID || binding.clientId)) || "").trim();
        if (!boundClientId) {
            _badge("dashMlBadge", "danger", "NOT BOUND");
            _setText("dashMlDetail", "MLService is not bound to any identity yet.");
            if (IDENTITY && IDENTITY.role === "SecurityService" && btn) btn.style.display = "";
            return;
        }
        if (boundClientId !== mlClientId) {
            _badge("dashMlBadge", "danger", "MISMATCH");
            _setHtml(
                "dashMlDetail",
                `${formatBindingDetail("Ledger:", boundClientId)}<br>${formatBindingDetail("Agent:", mlClientId)}`
            );
            if (IDENTITY && IDENTITY.role === "SecurityService" && btn) btn.style.display = "";
            return;
        }

        _badge("dashMlBadge", "success", "OK");
        _setHtml("dashMlDetail", formatBindingDetail("Bound to", boundClientId));
    } catch (e) {
        _badge("dashMlBadge", "warning", "CHECK");
        _setText("dashMlDetail", (e && e.message) ? e.message : "error");
        if (IDENTITY && IDENTITY.role === "SecurityService" && btn) btn.style.display = "";
    }
}

async function dashRegisterCurrentUser() {
	    try {
	        const ok = await registerIdentity();
	        if (!ok) return;
	        log("✅ Dashboard: identity sync completed for " + CURRENT_USER);
	        await refreshIdentity();
	        await runSetupChecklist();
	        showMainTab("#pane-assets");
	    } catch (e) {
        log("❌ Dashboard Register error: " + (e && e.message ? e.message : e));
        alert("Register failed: " + (e && e.message ? e.message : e));
    }
}

function humanizeBindError(raw) {
    const msg = String(raw || "").trim();
    if (!msg) return "Unknown error";
    if (/failed to fetch/i.test(msg)) {
        return "Cannot reach the Go agent. Make sure the unified agent is running (AGENT_IDENTITIES=SecurityService,MLService on :8090) and the backend can talk to it.";
    }
    if (/agent did not return a clientID/i.test(msg)) {
        return "The agent responded but did not report an MLService clientID. Check that MLService's Fabric cert is enrolled and visible to the agent.";
    }
    if (/unknown role/i.test(msg)) {
        return "Backend does not recognise this role. Restart the backend after upgrading.";
    }
    if (/unauthorized/i.test(msg)) {
        return "Session expired or not authorised for MLService binding. Sign in again as SecurityService.";
    }
    return msg;
}

async function dashBindMLService() {
    const btn = document.getElementById("btnDashBindMl");
    const prevHtml = btn ? btn.innerHTML : "";
    try {
        if (!(IDENTITY && IDENTITY.role === "SecurityService")) throw new Error("Only SecurityService can bind MLService");
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Binding...';
        }
        const mlClientId = await waitForAgentClientId("MLService", 8000);
        await agentSubmit("BindServiceIdentity", ["MLService", mlClientId]);
        const verifiedClientId = await waitForServiceBinding("MLService", mlClientId, 12000);
        if (!verifiedClientId) throw new Error("Binding verification timed out");
        log("✅ Dashboard: Bound MLService to " + mlClientId);
        await dashCheckMlBinding();
        await runSetupChecklist();
        showMainTab("#pane-security");
    } catch (e) {
        const raw = (e && e.message) ? e.message : String(e);
        const pretty = humanizeBindError(raw);
        log("❌ Dashboard Bind error: " + raw);
        await uiAlert({ title: "Bind MLService failed", body: pretty, tone: "danger" });
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = prevHtml || '<i class="bi bi-link-45deg"></i> Bind MLService';
        }
    }
}

function renderDashRoleCards() {
    const box = document.getElementById("dashRoleGuide");
    if (!box) return;

    const role = (IDENTITY && IDENTITY.role) ? IDENTITY.role.trim() : "";
    const cards = [];

    if (role === "SecurityService") {
        cards.push(`
          <div class="workflow-card">
            <div class="workflow-title"><i class="bi bi-shield-lock"></i> Security workflow</div>
            <div class="workflow-body">Review alerts, investigate evidence, and enforce policy decisions across the repository.</div>
            <div class="workflow-actions">
              <button class="btn btn-sm btn-danger" onclick="showMainTab('#pane-security')"><i class="bi bi-shield-lock"></i> Open Security</button>
              <button class="btn btn-sm btn-outline-danger" onclick="loadRiskDashboard()"><i class="bi bi-activity"></i> Refresh risk</button>
              <button class="btn btn-sm btn-outline-secondary" onclick="showMainTab('#pane-activity')"><i class="bi bi-clock-history"></i> Audit logs</button>
            </div>
            <div class="workflow-note">Tip: use the evidence trail to justify block and unblock decisions.</div>
          </div>
        `);
    } else {
        cards.push(`
          <div class="workflow-card">
            <div class="workflow-title"><i class="bi bi-cloud-arrow-up"></i> Upload flow</div>
            <div class="workflow-body">Upload, review the AI suggestion, approve the category, and only then share governed access.</div>
            <div class="workflow-actions">
              <button class="btn btn-sm btn-outline-success" onclick="showMainTab('#pane-assets')"><i class="bi bi-plus-circle"></i> Upload file</button>
              <button class="btn btn-sm btn-outline-secondary" onclick="setAssetsFilter('needs_review')"><i class="bi bi-check2-square"></i> Review approvals</button>
            </div>
          </div>
          <div class="workflow-card">
            <div class="workflow-title"><i class="bi bi-unlock"></i> Access flow</div>
            <div class="workflow-body">Browse the repository, request access with context, inspect approved details, and download only after access is granted.</div>
            <div class="workflow-actions">
              <button class="btn btn-sm btn-outline-primary" onclick="showMainTab('#pane-dashboard')"><i class="bi bi-grid-1x2"></i> Open dashboard</button>
              <button class="btn btn-sm btn-outline-dark" onclick="showMainTab('#pane-assets')"><i class="bi bi-folder2-open"></i> My uploads</button>
            </div>
          </div>
        `);
    }

    box.innerHTML = cards.join("");
}

function updateDashboardIdentity() {
    _setText("dashProfileName", CURRENT_USER || "—");
    _setText("dashClientId", (IDENTITY && IDENTITY.clientID) ? IDENTITY.clientID : "—");
    _setText("dashMspId", (IDENTITY && IDENTITY.mspID) ? IDENTITY.mspID : "—");
    _setText("dashRole", (IDENTITY && IDENTITY.role) ? IDENTITY.role : "—");
    _setText("dashDept", (IDENTITY && IDENTITY.department) ? IDENTITY.department : "—");
    renderDashRoleCards();
}

async function fetchSecurityAlerts() {
  const types = ["USER_BLOCKED", "ACCESS_REQUEST_DENIED", "ACCESS_DENIED", "KEY_REQUEST_DENIED"];
  const all = [];
  for (const t of types) {
    try {
      const res = await agentEval("QueryAuditEventsByType", [t]);
      const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
      for (const it of items) all.push(it);
    } catch (e) {
      // ignore individual type errors
    }
  }
  return all;
}

function normalizeAuditItem(it) {
  return {
    eventType: it.eventType || it.EventType || "EVENT",
    timestamp: it.timestamp || it.Timestamp || "",
    actorID: it.actorID || it.ActorID || "",
    targetUserID: it.targetUserID || it.TargetUserID || "",
    assetID: it.assetID || it.AssetID || "",
    detail: it.detail || it.Detail || "",
  };
}

function renderDashboardEvents(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return `<div class="text-muted">No recent events.</div>`;
  }
  const sorted = items.slice().sort((a,b) => String(b.timestamp || b.Timestamp || "").localeCompare(String(a.timestamp || a.Timestamp || "")));
  const top = sorted.slice(0, 10).map(raw => {
    const it = normalizeAuditItem(raw);
    return `<div class="list-group-item">
      <div class="d-flex justify-content-between">
      <div><b>${escapeHtml(it.eventType)}</b> ${it.assetID ? `<code>${escapeHtml(it.assetID)}</code>` : ""}</div>
      <div class="text-muted small">${escapeHtml(it.timestamp || "—")}</div>
      </div>
      <div class="text-muted small">actor: <code>${escapeHtml(it.actorID || "—")}</code></div>
      ${it.targetUserID ? `<div class="text-muted small">target: <code>${escapeHtml(it.targetUserID)}</code></div>` : ""}
      ${it.detail ? `<div class="small mt-1">${escapeHtml(it.detail)}</div>` : ""}
    </div>`;
  }).join("");
  return `<div class="list-group list-tight">${top}</div>`;
}

async function loadDashboard() {
  syncDashboardCounters();
  const out = document.getElementById("dashboardFilesTable");
  if (!out) return;

  out.innerHTML = `<tr><td colspan="9" class="text-muted text-center p-3">Loading…</td></tr>`;
  try {
    try { updateDashboardIdentity(); } catch {}
    try { await checkHealthAll(); } catch {}

    let me = UI_STATE.meClientID;
    try {
      const who = await agentEval("WhoAmI", []);
      me = (who && (who.clientID || who.clientId || who.id)) ? (who.clientID || who.clientId || who.id) : me;
    } catch {}

    let assets = await agentEval("GetAllAssetsPublic", []);
    if (!Array.isArray(assets)) assets = [];
    assets = assets.map(normalizeAsset);
    await fetchIpfsStatusesForAssets(assets);

    let myAssetsById = {};
    try {
      let myAssets = await agentEval("GetMyAssets", []);
      if (!Array.isArray(myAssets)) myAssets = [];
      myAssets = myAssets.map(normalizeAsset);
      for (const a of myAssets) {
        if (a && a.ID) myAssetsById[a.ID] = a;
      }
    } catch {}

    let myReqStatusByAsset = {};
    try {
      let myReqs = await agentEval("GetMyRequests", []);
      if (!Array.isArray(myReqs)) myReqs = [];
      for (const r of myReqs) {
        const aid = r.AssetID || r.assetID || r.assetId || r.asset_id;
        const st = (r.Status || r.status || "").toString().toUpperCase();
        if (aid) myReqStatusByAsset[aid] = st;
      }
    } catch {}

    let pendingByAsset = {};
    try {
      let pending = await agentEval("GetPendingRequests", []);
      if (!Array.isArray(pending)) pending = [];
      for (const r of pending) {
        const aid = r.assetID || r.AssetID;
        if (!aid) continue;
        if (!pendingByAsset[aid]) pendingByAsset[aid] = [];
        pendingByAsset[aid].push(r);
      }
    } catch {}

    UI_STATE.meClientID = me;
    UI_STATE.myAssetsById = myAssetsById;
    UI_STATE.pendingByAsset = pendingByAsset;
    UI_STATE.myReqStatusByAsset = myReqStatusByAsset;

    let ownedCount = 0;
    let availableCount = 0;
    let needsReviewCount = 0;
    let pendingTotal = 0;
    const requestsCount = Object.keys(myReqStatusByAsset || {}).length;

    for (const items of Object.values(pendingByAsset || {})) {
      if (Array.isArray(items)) pendingTotal += items.length;
    }

    if (!assets.length) {
      UI_STATE.dashboardCounts = {
        owned: 0,
        available: 0,
        requests: requestsCount,
        needsReview: 0,
        pending: pendingTotal,
        needsReviewSec: 0
      };
      syncDashboardCounters();
      out.innerHTML = `<tr><td colspan="9" class="text-muted text-center p-3">No uploaded files.</td></tr>`;
      return;
    }

    const rows = assets.slice().reverse().map(asset => {
      const isOwner = isAssetOwner(asset, me);
      const officialCat = (asset.Category || asset.category || "").toString();
      const aiSug = (asset.SuggestedCategory || asset.suggestedCategory || "").toString();
      const aiConf = (asset.SuggestedConfidence ?? asset.suggestedConfidence);
      const aiConfTxt = (aiConf !== undefined && aiConf !== null && aiConf !== "")
        ? ` <span class="text-muted small">(${escapeHtml(aiConf)}%)</span>`
        : "";
      const aiCell = isActionableCategory(aiSug) ? `${escapeHtml(aiSug)}${aiConfTxt}` : '<span class="text-muted">—</span>';
      const review = assetNeedsReview(asset);
      const reviewStatus = review
        ? '<span class="badge bg-warning text-dark">Needs review</span>'
        : '<span class="badge bg-success">Approved</span>';
      const storageHtml = ipfsStatusHtml(asset);
      const access = assetAccessState(asset, isOwner);
      const accessHtml = accessBadgeHtml(access.status);
      const aid = jsQuote(asset.ID || "");
      const ownerName = String(asset.Owner || asset.owner || "").trim() || (isOwner ? CURRENT_USER : "—");

      if (isOwner) {
        ownedCount += 1;
        if (review) needsReviewCount += 1;
      } else if (access.canDownload) {
        availableCount += 1;
      }

      let requestAction = "";
      if (!isOwner) {
        if (access.canDownload) {
          requestAction = "";
        } else if (access.status === "PENDING") {
          requestAction = `<button class="btn btn-sm btn-outline-danger" onclick="cancelMyRequest('${aid}')">Cancel request</button>`;
        } else if (["DENIED", "REVOKED", "CANCELLED"].includes(access.status)) {
          requestAction = `<button class="btn btn-sm btn-outline-primary" onclick="reopenMyRequest('${aid}')">Reopen request</button>`;
        } else {
          requestAction = `<button class="btn btn-sm btn-outline-primary" onclick="requestAccess('${aid}')" ${access.canRequest ? "" : "disabled"}>${access.status === "PENDING" ? "Request (pending)" : "Request access"}</button>`;
        }
      }

      const canOpenDetails = isOwner || access.canDownload;
      const canDownload = isOwner || access.canDownload;
      const actions = `
        <div class="dashboard-actions">
          ${canOpenDetails ? `<button class="btn btn-sm btn-outline-secondary" onclick="openAssetDrawer('${aid}')">Details</button>` : ""}
          ${requestAction}
          ${canDownload ? `<button class="btn btn-sm btn-outline-success" onclick="downloadAsset('${aid}')">Download</button>` : ""}
        </div>
      `;

      return `
        <tr>
          <td>${escapeHtml(asset.ID || "")}</td>
          <td>${escapeHtml(asset.Title || asset.title || "")}</td>
          <td>
            <div class="fw-semibold">${escapeHtml(ownerName)}</div>
          </td>
          <td>${escapeHtml(officialCat || "—")}</td>
          <td>${aiCell}</td>
          <td>${storageHtml}</td>
          <td>${reviewStatus}</td>
          <td>${accessHtml}</td>
          <td>${actions}</td>
        </tr>
      `;
    });

    UI_STATE.dashboardCounts = {
      owned: ownedCount,
      available: availableCount,
      requests: requestsCount,
      needsReview: needsReviewCount,
      pending: pendingTotal,
      needsReviewSec: needsReviewCount
    };
    syncDashboardCounters();
    out.innerHTML = rows.join("");
  } catch (e) {
    out.innerHTML = `<tr><td colspan="9" class="text-warning text-center p-3">${escapeHtml(e.message || e)}</td></tr>`;
  }
}

async function loadRiskDashboard() {
  if (!(IDENTITY && IDENTITY.role === "SecurityService")) return;
  const topEl = document.getElementById("riskTopUsers");
  const alertEl = document.getElementById("riskAlerts");
  const blockedEl = document.getElementById("riskBlockedUsers");
  if (topEl) topEl.textContent = "Loading…";
  if (alertEl) alertEl.textContent = "Loading…";
  if (blockedEl) blockedEl.textContent = "Loading…";

  let alertItems = [];
  try {
    alertItems = await fetchSecurityAlerts();
  } catch (e) {
    if (alertEl) alertEl.innerHTML = `<div class="text-warning">${escapeHtml(e.message || e)}</div>`;
  }

  const normalized = alertItems.map(normalizeAuditItem);
  const recent = normalized.slice().sort((a,b) => String(b.timestamp).localeCompare(String(a.timestamp))).slice(0, 8);
  if (alertEl) {
    alertEl.innerHTML = recent.length
      ? `<div class="list-group list-tight">${recent.map(it => `
        <div class="list-group-item">
          <div class="d-flex justify-content-between">
          <div><b>${escapeHtml(it.eventType)}</b> ${it.assetID ? `<code>${escapeHtml(it.assetID)}</code>` : ""}</div>
          <div class="text-muted small">${escapeHtml(it.timestamp || "—")}</div>
          </div>
          ${it.targetUserID ? `<div class="text-muted small">target: <code>${escapeHtml(it.targetUserID)}</code></div>` : ""}
        </div>`).join("")}</div>`
      : `<div class="text-muted">No recent alerts.</div>`;
  }

  const counts = {};
  for (const it of normalized) {
    const key = (it.targetUserID || it.actorID || "").trim();
    if (!key) continue;
    counts[key] = (counts[key] || 0) + 1;
  }
  const top = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 6);
  if (topEl) {
    topEl.innerHTML = top.length
      ? `<div class="list-group list-tight">${top.map(([u,c]) => `
        <div class="list-group-item d-flex justify-content-between">
          <code>${escapeHtml(u)}</code>
          <span class="badge bg-danger">${c}</span>
        </div>`).join("")}</div>`
      : `<div class="text-muted">No suspicious users yet.</div>`;
  }

  try {
    const blocked = await agentEval("ListBlockedUsers", []);
    const list = Array.isArray(blocked) ? blocked : [];
    if (blockedEl) {
      blockedEl.innerHTML = list.length
        ? `<div class="list-group list-tight">${list.slice(0, 8).map(u => `
          <div class="list-group-item">
            <div><b>${escapeHtml(u.username || u.Username || u.userID || u.UserID || "user")}</b></div>
            <div class="text-muted small"><code>${escapeHtml(u.userID || u.UserID || "")}</code></div>
            ${u.blockReason ? `<div class="text-muted small">${escapeHtml(u.blockReason)}</div>` : ""}
          </div>`).join("")}</div>`
        : `<div class="text-muted">No blocked users.</div>`;
    }
    setEl("kpiBlocked", list.length);
  } catch (e) {
    if (blockedEl) blockedEl.innerHTML = `<div class="text-warning">${escapeHtml(e.message || e)}</div>`;
  }

  setEl("kpiDenied", recent.length);
}

async function loadEvidenceTrail() {
  const userId = (document.getElementById("riskEvidenceUserId")?.value || "").trim();
  if (!userId) {
    await uiAlert({title:"Evidence trail", body:"Enter a clientID to investigate.", tone:"warning"});
    return;
  }
  const out = document.getElementById("riskEvidenceOut");
  if (out) out.innerHTML = `<div class="text-muted">Loading…</div>`;

  try {
    const res = await agentEval("QueryAuditEventsByTargetUser", [userId]);
    const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
    const dls = await agentEval("QueryDownloadAuditsByUser", [userId]);
    const dlItems = (dls && (dls.items || dls.Items)) ? (dls.items || dls.Items) : [];

    let html = "";
    if (items.length === 0 && dlItems.length === 0) {
      html = `<div class="text-muted">No evidence found for this user.</div>`;
    } else {
      const auditHtml = items.length
        ? `<div class="list-group list-tight mb-2">${items.slice(0, 10).map(raw => {
          const it = normalizeAuditItem(raw);
          return `<div class="list-group-item">
            <div class="d-flex justify-content-between">
            <div><b>${escapeHtml(it.eventType)}</b> ${it.assetID ? `<code>${escapeHtml(it.assetID)}</code>` : ""}</div>
            <div class="text-muted small">${escapeHtml(it.timestamp || "—")}</div>
            </div>
            ${it.detail ? `<div class="small">${escapeHtml(it.detail)}</div>` : ""}
          </div>`;
        }).join("")}</div>`
        : `<div class="text-muted">No audit events.</div>`;

      const dlHtml = dlItems.length
        ? `<div class="list-group list-tight">${dlItems.slice(0, 10).map(it => {
          const ts = it.timestamp || it.Timestamp || "";
          const aid = it.assetID || it.AssetID || "";
          return `<div class="list-group-item">
            <div class="d-flex justify-content-between">
            <div><b>DOWNLOAD</b> ${aid ? `<code>${escapeHtml(aid)}</code>` : ""}</div>
            <div class="text-muted small">${escapeHtml(ts || "—")}</div>
            </div>
          </div>`;
        }).join("")}</div>`
        : `<div class="text-muted">No downloads.</div>`;

      html = `<div class="fw-semibold mb-1">Audit events</div>${auditHtml}
          <div class="fw-semibold mt-3 mb-1">Downloads</div>${dlHtml}`;
    }
    if (out) setSanitizedHtml(out, html);
  } catch (e) {
    if (out) out.innerHTML = `<div class="text-warning">${escapeHtml(e.message || e)}</div>`;
  }
}

async function runSetupChecklist() {
    await dashCheckAgents();
    await dashCheckBackend();
    await dashCheckIpfs();
    await dashCheckRegistration();
    await dashCheckMlBinding();
}

function initSetupChecklistUI() {
  const btnRefresh = document.getElementById("btnDashRefresh");
  if (btnRefresh) btnRefresh.addEventListener("click", runSetupChecklist);
  const btnReg = document.getElementById("btnDashRegister");
  if (btnReg) btnReg.addEventListener("click", dashRegisterCurrentUser);
  const btnBind = document.getElementById("btnDashBindMl");
  if (btnBind) btnBind.addEventListener("click", dashBindMLService);
  const aInp = document.getElementById("assetSearchInput");
  if (aInp) aInp.addEventListener("input", applyAssetSearchFilter);
  const aSel = document.getElementById("assetFilterSelect");
  if (aSel) aSel.addEventListener("change", applyAssetSearchFilter);
  const aClr = document.getElementById("assetSearchClear");
  if (aClr) aClr.addEventListener("click", () => { if (aInp) aInp.value=""; applyAssetSearchFilter(); });
}

// Run after existing init finishes.
setTimeout(() => {
  try { initSetupChecklistUI(); } catch(e) { console.error(e); }
  try { renderDeveloperLog(); } catch(e) { console.error(e); }
  // Auth: check existing session on load
  checkExistingSession();
}, 0);
