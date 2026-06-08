/**
 * 04-identity-drawer.js
 * Active identity + asset drawer + registration workflows:
 *   - IDENTITY context, syncDashboardCounters, setEl / setHtml
 *   - refreshIdentity (GetMyIdentity / agent introspection)
 *   - applyRoleVisibility - enables/disables UI by Fabric role
 *   - Asset Drawer: overview, audit, downloads, request / approve / rotate
 *   - connectProfile + ensureLocalKeyReady (local data encryption key create / unlock)
 *   - syncBrowserPublicKeyOnLedger + registerIdentity
 */

    // ============================
    // Identity / context
    // ============================
    let IDENTITY = { clientID: "", mspID: "", role: "", department: "" };

    function copyElText(id) {
        const el = document.getElementById(id);
        const txt = (el && (el.textContent || el.innerText) || "").trim();
        if (!txt) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(txt)
                .then(() => log("📋 Copied to clipboard"))
                .catch(() => {});
        } else {
            const ta = document.createElement("textarea");
            ta.value = txt;
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand("copy"); log("📋 Copied to clipboard"); } catch {}
            document.body.removeChild(ta);
        }
    }

    function setEl(id, val) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = (val === undefined || val === null || val === "") ? "—" : String(val);
    }

    function setHtml(id, htmlStr) {
        const el = document.getElementById(id);
        if (!el) return;
        setSanitizedHtml(el, htmlStr);
    }

    function syncDashboardCounters() {
      const c = UI_STATE.dashboardCounts || {};
      setEl("kpiOwned", c.owned ?? 0);
      setEl("kpiAvailable", c.available ?? 0);
      setEl("kpiRequests", c.requests ?? 0);
      setEl("kpiNeedsReview", c.needsReview ?? 0);
      setEl("kpiPending", c.pending ?? 0);
      setEl("kpiNeedsReviewSec", c.needsReviewSec ?? (c.needsReview ?? 0));
    }

	    async function refreshIdentity() {
	        setEl("idAgent", agentBase());
	        let authStatus = "active";
            let recovery = {};
            let passkeyItems = [];
	        try {
	            const who = await agentEval("WhoAmI", []);
	            IDENTITY = {
	                clientID: who.clientID || "",
	                mspID: who.mspID || "",
	                role: who.role || "",
	                department: who.department || "",
	                registered: false,
	                publicKey: "",
	                fingerprint: ""
	            };

            setEl("idClient", IDENTITY.clientID || "—");
            setEl("idMsp", IDENTITY.mspID || "—");
            setEl("idDept", IDENTITY.department || "—");

            const roleEl = document.getElementById("idRole");
            if (roleEl) {
                roleEl.textContent = IDENTITY.role || "—";
                roleEl.className = "badge " + (IDENTITY.role === "SecurityService"
                    ? "bg-danger"
                    : (IDENTITY.role ? "bg-secondary" : "bg-warning text-dark"));
            }

	            // Block status (from on-chain profile; self access is allowed)
	            try {
	                const prof = await agentEval("GetUserProfile", [IDENTITY.clientID]);
	                const onChainKey = String((prof && (prof.publicKey || prof.PublicKey)) || "").trim();
	                const onChainFingerprint = String((prof && (prof.fingerprint || prof.Fingerprint)) || "").trim();
	                recovery = (prof && (prof.recoveryBundle || prof.RecoveryBundle)) || {};
	                const webauthnIdentity = (prof && (prof.webAuthnIdentity || prof.WebAuthnIdentity)) || {};
	                passkeyItems = Array.isArray(webauthnIdentity.credentials)
	                    ? webauthnIdentity.credentials
	                    : (Array.isArray(prof && (prof.webAuthnCredentials || prof.WebAuthnCredentials)) ? (prof.webAuthnCredentials || prof.WebAuthnCredentials) : []);
	                IDENTITY.registered = true;
	                IDENTITY.publicKey = onChainKey;
	                IDENTITY.fingerprint = onChainFingerprint;
	                const blocked = !!(prof && (prof.isBlocked || prof.IsBlocked));
	                if (blocked) {
	                    authStatus = "blocked";
	                    const until = prof.blockedUntil || prof.BlockedUntil || "";
	                    const reason = prof.blockReason || prof.BlockReason || "";
                    setHtml("idBlockLine",
                        `<span class="badge bg-danger">Blocked</span>
                         <span class="text-muted">until</span> <code>${escapeHtml(until || "—")}</code>
                         <span class="text-muted">reason:</span> ${escapeHtml(reason || "—")}`
	                    );
	                } else {
	                    const keyState = onChainKey
		                        ? `<span class="badge bg-success">Encryption public key</span> <span class="text-muted">registered on-ledger</span>`
		                        : `<span class="badge bg-warning text-dark">Encryption public key</span> <span class="text-muted">pending local sync</span>`;
	                    setHtml("idBlockLine", `<span class="badge bg-success">Active</span> <span class="text-muted">On-chain profile OK</span><br>${keyState}`);
	                }
	            } catch (e) {
	                IDENTITY.registered = false;
	                IDENTITY.publicKey = "";
	                IDENTITY.fingerprint = "";
	                setHtml("idBlockLine", `<span class="badge bg-warning text-dark">Profile</span> <span class="text-muted">${escapeHtml(humanizeErrorText(e.message || e))}</span>`);
	            }

	        } catch (e) {
	            IDENTITY = { clientID: "", mspID: "", role: "", department: "", registered: false, publicKey: "", fingerprint: "" };
	            setEl("idClient", "—");
	            setEl("idMsp", "—");
	            setEl("idDept", "—");
	            const roleEl = document.getElementById("idRole");
	            if (roleEl) { roleEl.textContent = "—"; roleEl.className = "badge bg-warning text-dark"; }
	            setHtml("idBlockLine", `<span class="badge bg-warning text-dark">Disconnected</span> <span class="text-muted">${escapeHtml(humanizeErrorText(e.message || e))}</span>`);
	        }

if (AUTH_SESSION) {
	    const recoveryRequired = !!(recovery.required || AUTH_SESSION.recovery_bundle_required);
	    const recoveryCreated = !!(recovery.created || AUTH_SESSION.recovery_bundle_created);
	    const recoveryCreatedAt = recovery.createdAt || AUTH_SESSION.recovery_bundle_created_at || "";
	    AUTH_SESSION.role = IDENTITY.role || AUTH_SESSION.role || "";
	    AUTH_SESSION.department = IDENTITY.department || AUTH_SESSION.department || "";
	    AUTH_SESSION.msp_id = IDENTITY.mspID || AUTH_SESSION.msp_id || "";
    AUTH_SESSION.client_id = IDENTITY.clientID || AUTH_SESSION.client_id || "";
    AUTH_SESSION.status = authStatus;
	    AUTH_SESSION.recovery_bundle_required = recoveryRequired;
	    AUTH_SESSION.recovery_bundle_created = recoveryCreated;
	    AUTH_SESSION.recovery_bundle_created_at = recoveryCreatedAt;
    AUTH_SESSION.passkey_count = passkeyItems.length;
    try { applyAuthSession(); } catch {}
}

// Update Settings panel + notices
try { renderSessionPanel(); } catch {}
try { renderNotices(); } catch {}
        applyRoleVisibility();
        try { if (IDENTITY.role === "SecurityService") runSetupChecklist(); } catch {}
        try { updateDashboardIdentity(); } catch {}

    }

    // Per-role tab visibility policy. The backend still enforces RBAC; this
    // is UX-only and just prevents each user from seeing tabs that are not
    // useful for their role.
    const ROLE_TAB_POLICY = {
        // Full operator.
        SecurityService: {
            show: ["nav-dashboard", "nav-assets", "nav-activity", "nav-security", "nav-users", "nav-settings"],
            defaultTab: "#pane-security",
        },
        // Researchers upload/browse their own data.
        Researcher: {
            show: ["nav-dashboard", "nav-assets", "nav-settings"],
            defaultTab: "#pane-assets",
        },
        // ML service identity - minimal, read-only dashboard-style UI.
        MLService: {
            show: ["nav-dashboard", "nav-settings"],
            defaultTab: "#pane-dashboard",
        },
        // Risk analyst - dashboard + profile/settings.
        RiskService: {
            show: ["nav-dashboard", "nav-settings"],
            defaultTab: "#pane-dashboard",
        },
    };
    // Fallback when the role is unknown / before identity is loaded.
    const ROLE_TAB_POLICY_DEFAULT = {
        show: ["nav-dashboard", "nav-assets", "nav-settings"],
        defaultTab: "#pane-dashboard",
    };

    function applyRoleVisibility() {
        const role = IDENTITY.role || "";
        const isSecurity = (role === "SecurityService");
        document.body.dataset.role = role;

        toggleEl("securityPanel", isSecurity);
        toggleEl("setupChecklistWrap", isSecurity);
        toggleEl("riskDashboard", isSecurity);
        toggleEl("securityNotice", !isSecurity);

        const policy = ROLE_TAB_POLICY[role] || ROLE_TAB_POLICY_DEFAULT;
        const allTabs = ["nav-dashboard", "nav-assets", "nav-activity", "nav-security", "nav-users", "nav-settings"];
        allTabs.forEach((id) => {
            const el = document.getElementById(id);
            if (!el) return;
            const visible = policy.show.includes(id);
            el.classList.toggle("d-none", !visible);
            el.style.display = visible ? "" : "none";
            // Hide the tab button's pane target too, to avoid flash-of-content.
            const btn = el.querySelector("[data-bs-target]");
            const paneSel = btn && btn.getAttribute("data-bs-target");
            if (paneSel) {
                const pane = document.querySelector(paneSel);
                if (pane && !visible) pane.classList.remove("show", "active");
            }
        });

        const tabs = document.getElementById("mainTabs");
        if (tabs) {
          if (!applyRoleVisibility._init) {
            Array.from(tabs.children).forEach((li, idx) => { li.dataset.order = String(idx); });
            applyRoleVisibility._init = true;
          }
          // Keep tabs in their original declaration order so we never end up
          // with duplicates / shuffled siblings.
          const items = Array.from(tabs.children)
              .sort((a,b) => Number(a.dataset.order||0) - Number(b.dataset.order||0));
          items.forEach((li) => tabs.appendChild(li));
        }

        if (!applyRoleVisibility._activated) {
          applyRoleVisibility._activated = true;
          if (policy.defaultTab) showMainTab(policy.defaultTab);
        }
    }

    // ============================
    // Drawer state
    // ============================
    let UI_STATE = {
        meClientID: null,
        myAssetsById: {},
        pendingByAsset: {},
      myReqStatusByAsset: {},
      dashboardCounts: {}
    };

    let DRAWER_CTX = { assetId: null, asset: null, isOwner: false };

    function clearDrawerAlert() { setHtml("drawerAlerts", ""); }

    async function openAssetDrawer(assetId, options = {}) {
        clearDrawerAlert();
        DRAWER_CTX = { assetId, asset: null, isOwner: false };
        const overviewOnly = !!(options && options.overviewOnly);
        DRAWER_CTX.overviewOnly = overviewOnly;
        try {
          const tabs = document.getElementById("drawerTabs");
          if (tabs) tabs.classList.toggle("d-none", overviewOnly);
          ["pane-audit","pane-downloads"].forEach(pid => {
            const el = document.getElementById(pid);
            if (el) el.classList.toggle("d-none", overviewOnly);
          });
        } catch {}


        setEl("assetDrawerLabel", `Asset ${assetId}`);
        setEl("assetDrawerSub", `Loading from ${agentBase()}…`);

        setHtml("drawerOverview", `<div class="text-muted small">Loading…</div>`);
        setHtml("drawerAudit", `<div class="text-muted small">Loading…</div>`);
        setHtml("drawerDownloads", `<div class="text-muted small">Loading…</div>`);

        if (!(window.bootstrap && bootstrap.Offcanvas)) {
            // Fallback when Bootstrap JS is unavailable (e.g. CDN blocked)
            await showMetadata(assetId);
            return;
        }
        const ocEl = document.getElementById("assetDrawer");
        bootstrap.Offcanvas.getOrCreateInstance(ocEl).show();

        try {
            const full = await agentEval("ReadAsset", [assetId]);
            const asset = normalizeAsset(full);
            DRAWER_CTX.asset = asset;

            const me = UI_STATE.meClientID;
            const isOwner = isAssetOwner(asset, me);
            DRAWER_CTX.isOwner = isOwner;

            setEl("assetDrawerSub", `${escapeHtml(asset.Title || asset.title || "—")}`);

            const access = assetAccessState(asset, isOwner);

            const btnReq = document.getElementById("drawerBtnRequest");
            const btnDl = document.getElementById("drawerBtnDownload");
            const btnAppr = document.getElementById("drawerBtnApprove");
            const btnRot = document.getElementById("drawerBtnRotate");

            if (btnReq) { btnReq.disabled = !access.canRequest; btnReq.classList.toggle("d-none", isOwner); }
            if (btnDl) { btnDl.disabled = !access.canDownload; }
            if (btnAppr) btnAppr.classList.toggle("d-none", !(isOwner && assetNeedsReview(asset)));
            if (btnRot) { btnRot.classList.toggle("d-none", !isOwner); }

            renderDrawerOwnerPanel(asset);
            renderDrawerOverview(asset);

            drawerReloadAudit();
            drawerReloadDownloads();
        } catch (e) {
            setHtml("drawerOverview", `<div class="alert alert-danger py-2 small">${escapeHtml(e.message || e)}</div>`);
        }
    }

    function renderDrawerOverview(asset) {
        const meta = asset.metadata || asset.Metadata || {};
        const suggestion = bestAvailableAssetSuggestion(
            assetIdOf(asset),
            asset,
            UI_STATE.myAssetsById[assetIdOf(asset)] || null,
            ASSET_CACHE[assetIdOf(asset)] || null
        );
        const sug = suggestion.suggested || "";
        const conf = suggestion.confidence;
        const review = assetNeedsReview(asset);
        const official = asset.Category || asset.category || "";

        const catBadge = review
            ? '<span class="badge bg-warning text-dark ms-1">Needs review</span>'
            : (official === "Unverified"
                ? '<span class="badge bg-warning text-dark ms-1">Unverified</span>'
                : (official ? '<span class="badge bg-success ms-1">Approved</span>' : ''));

        const suggestedHtml = `${escapeHtml(sug || "—")}` +
            ((conf !== undefined && conf !== null && conf !== "")
                ? ` <span class="text-muted small">(${escapeHtml(conf)}%)</span>`
                : "");

        const isOwner = DRAWER_CTX.isOwner;
        const access = assetAccessState(asset, isOwner);
        const hasAccess = access.canDownload || !!(asset.CIDHash || asset.cidHash);
        const isSecurityService = (IDENTITY && IDENTITY.role === "SecurityService");
        const canSeeDetails = hasAccess || isSecurityService;

        const cid = escapeHtml(asset.CIDHash || asset.cidHash || "");
        const fileHash = escapeHtml(asset.FileHash || asset.fileHash || "");

        if (!canSeeDetails) {
            // Restricted view — only public summary
            setHtml("drawerOverview", `
              <div class="mb-2">
                <div><b>Official category:</b> ${escapeHtml(official)} ${catBadge}</div>
                <div><b>AI suggestion:</b> ${suggestedHtml}</div>
              </div>

              <div class="mb-2">
                <div class="text-muted small mb-1">Repository metadata</div>
                <div><b>Title:</b> ${escapeHtml(meta.title || asset.Title || "")}</div>
              </div>

              <div class="alert alert-secondary py-2 small mt-3">
                <i class="bi bi-lock"></i>
                Full provenance and metadata (CID, file hash, authors, DOI, etc.) are available only after access is granted.
                Use <b>Request access</b> above.
              </div>
            `);
            return;
        }

        setHtml("drawerOverview", `
          <div class="mb-2">
            <div><b>Official category:</b> ${escapeHtml(official)} ${catBadge}</div>
            <div><b>AI suggestion:</b> ${suggestedHtml}</div>
          </div>

          <div class="mb-2">
            <div class="text-muted small">Provenance</div>
            <div><b>CID:</b> <code style="word-break:break-all;">${cid}</code></div>
            <div><b>File hash:</b> <code style="word-break:break-all;">${fileHash}</code></div>
            <div><b>OwnerID:</b> <code style="word-break:break-all;">${escapeHtml(asset.OwnerID || "")}</code></div>
          </div>

          <hr class="my-2">

          <div class="text-muted small mb-1">Repository metadata</div>
          <div><b>Title:</b> ${escapeHtml(meta.title || asset.Title || "")}</div>
          <div><b>Authors:</b> ${escapeHtml(meta.authors || asset.Authors || "")}</div>
          <div><b>Discipline:</b> ${escapeHtml(meta.discipline || asset.Discipline || "")}</div>
          <div><b>License:</b> ${escapeHtml(meta.license || asset.License || "")}</div>
          <div><b>DOI:</b> ${escapeHtml(meta.doi || asset.DOI || "")}</div>
          <div><b>Keywords:</b> ${escapeHtml(meta.keywords || asset.Keywords || "")}</div>
        `);
    }

    function renderDrawerOwnerPanel(asset) {
        const panel = document.getElementById("drawerOwnerPanel");
        if (!panel) return;
        if (!DRAWER_CTX.isOwner) {
            clearElement(panel);
            return;
        }

        const pend = UI_STATE.pendingByAsset[asset.ID] || [];
        if (!pend.length) {
            setSanitizedHtml(panel, `<div class="alert alert-light py-2 mb-0 small">No pending requests for this asset.</div>`);
            return;
        }

        let html = `<div class="card bg-soft">
          <div class="card-body py-2">
            <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
              <div class="fw-semibold">Pending requests</div>
              <span class="badge bg-warning text-dark">${pend.length}</span>
            </div>
            <div class="list-group mt-2 list-tight">`;
        for (const r of pend) {
            const requesterID = r.requesterID || r.RequesterID || "";
            const requesterName = r.requester || r.Requester || (requesterID ? requesterID.substring(0, 12) + "…" : "unknown");
            const reason = (r.Reason || r.reason || "").toString();
            html += `
              <div class="list-group-item">
                <div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-2">
                  <div>
                    <div><b>${escapeHtml(requesterName)}</b></div>
                    <div class="text-muted small break-anywhere"><code>${escapeHtml(requesterID)}</code></div>
                    ${reason ? `<div class="text-muted small">reason: ${escapeHtml(reason)}</div>` : ``}
                  </div>
                  <div class="d-flex flex-wrap gap-1 justify-content-start justify-content-md-end">
	                    <button class="btn btn-sm btn-success" data-drawer-grant="${escapeHtml(requesterID)}">Grant</button>
	                    <button class="btn btn-sm btn-outline-danger" data-drawer-deny="${escapeHtml(requesterID)}">Deny</button>
                  </div>
                </div>
              </div>`;
        }
	        html += `</div></div></div>`;
	        setSanitizedHtml(panel, html);
            panel.querySelectorAll("[data-drawer-grant]").forEach((btn) => {
                btn.addEventListener("click", () => grantAccess(asset.ID, btn.getAttribute("data-drawer-grant") || ""));
            });
            panel.querySelectorAll("[data-drawer-deny]").forEach((btn) => {
                btn.addEventListener("click", () => denyAccessUI(asset.ID, btn.getAttribute("data-drawer-deny") || ""));
            });
	    }

    async function drawerReloadAudit() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        setHtml("drawerAudit", `<div class="text-muted small">Loading…</div>`);
        try {
            const res = await agentEval("QueryAuditEventsByAsset", [aid]);
            const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
            renderAuditItems(items);
        } catch (e) {
            setHtml("drawerAudit", `<div class="alert alert-warning py-2 small">${escapeHtml(e.message || e)}</div>`);
        }
    }

    function renderAuditItems(items) {
        if (!Array.isArray(items) || items.length === 0) {
            setHtml("drawerAudit", `<div class="text-muted small">No audit events.</div>`);
            return;
        }
        items = items.slice().sort((a,b) => String(b.timestamp || b.Timestamp || "").localeCompare(String(a.timestamp || a.Timestamp || "")));

        let out = `<div class="list-group">`;
        for (const it of items) {
            const ts = it.timestamp || it.Timestamp || "";
            const typ = it.eventType || it.EventType || "";
            const actor = it.actorID || it.ActorID || "";
            const tgt = it.targetUserID || it.TargetUserID || "";
            const detail = it.detail || it.Detail || "";
            const tx = it.txID || it.TxID || "";
            out += `
              <div class="list-group-item">
                <div class="d-flex justify-content-between">
                  <div><b>${escapeHtml(typ || "EVENT")}</b></div>
                  <div class="text-muted small">${escapeHtml(ts)}</div>
                </div>
                <div class="text-muted small">actor: <code>${escapeHtml(actor)}</code></div>
                ${tgt ? `<div class="text-muted small">target: <code>${escapeHtml(tgt)}</code></div>` : ``}
                ${detail ? `<div class="small mt-1">${escapeHtml(detail)}</div>` : ``}
                ${tx ? `<div class="text-muted small mt-1">tx: <code>${escapeHtml(tx)}</code></div>` : ``}
              </div>
            `;
        }
        out += `</div>`;
        setHtml("drawerAudit", out);
    }

    async function drawerReloadDownloads() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        setHtml("drawerDownloads", `<div class="text-muted small">Loading…</div>`);
        try {
            const res = await agentEval("QueryDownloadAuditsByAsset", [aid]);
            const items = (res && (res.items || res.Items)) ? (res.items || res.Items) : [];
            renderDownloadItems(items);
        } catch (e) {
            setHtml("drawerDownloads", `<div class="alert alert-warning py-2 small">${escapeHtml(e.message || e)}</div>`);
        }
    }

    function renderDownloadItems(items) {
        if (!Array.isArray(items) || items.length === 0) {
            setHtml("drawerDownloads", `<div class="text-muted small">No downloads logged.</div>`);
            return;
        }
        items = items.slice().sort((a,b) => String(b.timestamp || b.Timestamp || "").localeCompare(String(a.timestamp || a.Timestamp || "")));

        let out = `<div class="list-group">`;
        for (const it of items) {
            const ts = it.timestamp || it.Timestamp || "";
            const actor = it.actorID || it.ActorID || "";
            const tx = it.txID || it.TxID || "";
            out += `
              <div class="list-group-item">
                <div class="d-flex justify-content-between">
                  <div><b>DOWNLOAD</b></div>
                  <div class="text-muted small">${escapeHtml(ts)}</div>
                </div>
                <div class="text-muted small">actor: <code>${escapeHtml(actor)}</code></div>
                ${tx ? `<div class="text-muted small mt-1">tx: <code>${escapeHtml(tx)}</code></div>` : ``}
              </div>
            `;
        }
        out += `</div>`;
        setHtml("drawerDownloads", out);
    }

    // Drawer button handlers (re-use existing actions)
    async function drawerRequestAccess() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        await requestAccess(aid);
        await refreshAssetViews();
        try { await openAssetDrawer(aid); } catch {}
    }

    async function drawerDownload() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        await downloadAsset(aid);
        setTimeout(() => { drawerReloadDownloads(); }, 600);
    }

    async function drawerApproveCategory() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        await approveCategoryUI(aid);
        await refreshAssetViews();
        try { await openAssetDrawer(aid); } catch {}
    }

    async function drawerRotate() {
        const aid = DRAWER_CTX.assetId;
        if (!aid) return;
        await rotateAssetContentUI(aid);
        await refreshAssetViews();
        try { await openAssetDrawer(aid); } catch {}
    }

		    function localKeyErrorText(err) {
		        const code = String((err && err.message) ? err.message : err || "");
                if (code === "ARGON2_BLOCKED_BY_CSP") return "Argon2 blocked by CSP. Разрешите unsafe-eval/wasm-unsafe-eval для localhost или отключите строгий CSP-extension для этой страницы.";
                if (code === "ARGON2_TIMEOUT") return "Argon2 timeout. Проверьте CSP/расширения браузера, которые блокируют wasm/eval.";
		        if (code === "LOCAL_KEY_LOCKED" || code === "LOCAL_KEY_UNLOCK_CANCELLED") return "Local browser key is unavailable on this device.";
		        if (code === "LOCAL_KEY_STORE_UNAVAILABLE") return "This browser does not provide the secure local key storage required for protected data keys.";
		        if (code === "LOCAL_KEY_ALGORITHM_MISMATCH") return "The local private key cannot decrypt this encrypted key format. Re-sync the correct browser key for this account.";
			        if (code === "LOCAL_PRIVATE_KEY_MISSING") return "This browser does not have the private data encryption key for the public key already registered on-chain. Restore the local identities from a recovery bundle before accessing protected data.";
		        if (code === "LOCAL_FABRIC_KEY_MISSING") return "This device does not have the local Fabric signing key needed for chain transactions.";
		        if (code === "LOCAL_KEY_MISMATCH") return "The local private key does not match the public key already registered on-chain. Automatic key rotation is disabled to avoid losing access to existing encrypted data.";
			        if (code === "LOCAL_KEY_SETUP_CANCELLED") return "Local encryption key setup was cancelled.";
		        if (code === "RECOVERY_BUNDLE_REQUIRED") return "A recovery bundle is required for this account before you can safely continue.";
		        if (code === "RECOVERY_BUNDLE_CANCELLED") return "Recovery bundle creation was cancelled.";
		        if (code === "RECOVERY_BUNDLE_INVALID") return "The selected recovery bundle is invalid or was encrypted with a different passphrase.";
		        if (code === "RECOVERY_EXPORT_UNAVAILABLE") return "Recovery export material is not available on this device anymore. The app will try an automatic local-identity repair when that is safe; otherwise restore from an existing recovery bundle.";
		        if (code === "RECOVERY_REISSUE_NOT_ALLOWED") return "This account already has a recorded recovery bundle. Restore that bundle on this device instead of reissuing local identities.";
		        if (code === "RECOVERY_REISSUE_BLOCKED_DATA_EXISTS") return "Automatic recovery repair is blocked because this account already owns files or has encrypted asset access bound to the old device key. Use an existing recovery bundle instead.";
		        if (code === "RECOVERY_REISSUE_FAILED") return "Automatic recovery repair failed on this device. Restore from an existing recovery bundle or re-activate only if this account has no protected data yet.";
			        return humanizeErrorText(code || "Local data encryption key error");
		    }

		    async function confirmCreateLocalKey() {
		        return uiConfirm({
		            title: "Create local encryption key",
		            body: "A new device-local ECDH key will be generated for modern envelope encryption. The private key stays in protected browser storage; only the public encryption identity is published on-ledger.",
		            okText: "Create key",
		            cancelText: "Cancel",
		            okClass: "btn-primary"
	        });
	    }

        async function unlockStoredBrowserRsa() {
              if (!LOCAL_KEY_UNLOCKED) {
                  throw new Error("LOCAL_KEY_LOCKED");
              }
		        const protectedRecord = await loadBrowserRsaPair();
		        if (myPublicKey && myPrivateKey) {
		            if (!myKeyFingerprint && myPublicKey) {
		                myKeyFingerprint = await computePublicKeyFingerprint(myPublicKey);
		            }
		            return true;
		        }

		        if (protectedRecord && protectedRecord.kind === "legacy-protected") {
                  throw new Error("LOCAL_KEY_ALGORITHM_MISMATCH");
		        }

		        return false;
		    }

			    async function createBrowserRsaKeyPair() {
			        const keyPair = await crypto.subtle.generateKey(
			            { name: "ECDH", namedCurve: "P-256" },
			            true,
			            ["deriveBits"]
			        );
            const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
            const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
            const workingPrivateKey = await crypto.subtle.importKey(
              "jwk",
              privateJwk,
              { name: "ECDH", namedCurve: "P-256" },
              false,
              ["deriveBits"]
            );
			        const storedPublicKey = formatStoredEcdhPublicKey(publicJwk);
            const fingerprint = await computePublicKeyFingerprint(storedPublicKey);
            RECOVERY_EXPORT_CACHE.dataEncryption = {
              algorithm: KEY_ENVELOPE_V2_ALG,
              privateJwkB64: jsonToB64(privateJwk),
              privatePkcs8B64: "",
              publicKey: storedPublicKey,
              fingerprint,
            };
            RECOVERY_EXPORT_CACHE.createdAt = new Date().toISOString();
			        await saveBrowserDataEncryptionKeyPair(storedPublicKey, workingPrivateKey, fingerprint, jsonToB64(privateJwk));
			        await _refreshDeviceRecoveryEscrowFromState().catch(() => false);
			        clearBrowserRsaEnvelope();
			        clearLegacyBrowserRsaPair();
		        return true;
		    }

        async function ensureLocalKeyReady({ interactive = false, allowCreate = true } = {}) {
          await ensureLocalKeyAccessGate();
          if (await unlockStoredBrowserRsa()) return true;

	        const onChainKey = String((IDENTITY && IDENTITY.publicKey) || "").trim();
	        if (onChainKey) {
	            throw new Error("LOCAL_PRIVATE_KEY_MISSING");
	        }
	        if (!allowCreate) {
	            throw new Error("LOCAL_PRIVATE_KEY_MISSING");
	        }
	        if (interactive) {
	            const confirmed = await confirmCreateLocalKey();
	            if (!confirmed) {
	                throw new Error("LOCAL_KEY_SETUP_CANCELLED");
	            }
	        }
	        return createBrowserRsaKeyPair();
	    }

      async function connectProfile() {
	        if (!(AUTH_SESSION && AUTH_SESSION.username)) {
	            showLoginScreen();
	            return;
	        }
	        try { if (typeof hideMainApp === "function") hideMainApp(); } catch {}
	        setActiveProfile(AUTH_SESSION.username);
	        log(`Active session -> ${CURRENT_USER} (${agentBase()})`);

	        await checkHealthAll();
	        await refreshIdentity();

	        let localKeyReady = false;
	        try {
              localKeyReady = await ensureLocalKeyReady({ interactive: false, allowCreate: !(IDENTITY && IDENTITY.registered) });
	        } catch (e) {
	            const msg = localKeyErrorText(e);
	            showToast(msg, "warning");
		            log("⚠️ Local data encryption key: " + msg);
	        }

          try {
            await ensureFabricIdentityReady({ allowCreate: false });
          } catch (e) {
            const msg = localKeyErrorText(e);
            showToast(msg, "warning");
            log("⚠️ Local Fabric key: " + msg);
          }

          try {
            await _refreshDeviceRecoveryEscrowFromState();
          } catch {}

          try {
            const gatePassed = await ensureRecoveryBundleForSession({ mandatory: true });
            if (!gatePassed) {
                return;
            }
          } catch (e) {
            const msg = localKeyErrorText(e);
            showToast(msg, "warning");
            log("⚠️ Recovery bundle gate: " + msg);
            return;
          }

	        try { if (typeof showMainApp === "function") showMainApp(); } catch {}
	        if (localKeyReady) {
	            try {
	                const synced = await syncBrowserPublicKeyOnLedger();
	                if (synced) await refreshIdentity();
	            } catch (e) {
	                console.error(e);
	                const msg = localKeyErrorText(e);
	                showToast(msg, "warning");
		                log("⚠️ Browser encryption key sync error: " + msg);
	            }
	        }
          try { await loadPasskeys({ silent: true }); } catch {}
	        loadFiles();
	        loadDashboard();
          showProfileTab();
	    }

		    async function agentRsaDecrypt(ciphertextB64) {
		        await ensureLocalKeyReady({ interactive: true, allowCreate: false });
		        return rsaDecryptCiphertext(ciphertextB64);
		    }

	    async function syncBrowserPublicKeyOnLedger() {
	        if (!(AUTH_SESSION && CURRENT_USER)) return false;
	        if (!myPublicKey) {
	            await ensureLocalKeyReady({ interactive: false, allowCreate: !(IDENTITY && IDENTITY.registered) });
	        }
	        myKeyFingerprint = myKeyFingerprint || await computePublicKeyFingerprint(myPublicKey);

	        const clientId = (IDENTITY && IDENTITY.clientID) ? IDENTITY.clientID : (AUTH_SESSION.client_id || "");
	        const onChainKey = String((IDENTITY && IDENTITY.publicKey) || "").trim();

	        if (!(IDENTITY && IDENTITY.registered) || !clientId) throw new Error("LOCAL_PRIVATE_KEY_MISSING");

	        if (!onChainKey) {
	            await agentSubmit("SyncMyPublicKey", [myPublicKey, myKeyFingerprint || ""]);
		            log("✅ Browser encryption public key synced on-ledger.");
	            return true;
	        }

	        if (onChainKey === myPublicKey) {
	            return false;
	        }

	        throw new Error("LOCAL_KEY_MISMATCH");
	    }

	    async function registerIdentity() {
	        try {
	            await ensureLocalKeyReady({ interactive: false, allowCreate: !(IDENTITY && IDENTITY.registered) });
	        } catch (e) {
	            await uiAlert({ title: "Register failed", body: localKeyErrorText(e), tone: "danger" });
	            return false;
	        }

	        try {
	            await syncBrowserPublicKeyOnLedger();
	            showToast("Registered on-ledger", "success");
	            log("✅ Registered on blockchain (via backend session).");
	            await refreshIdentity(true);
	            return true;
	        } catch (e) {
	            console.error(e);
	            await uiAlert({ title: "Register failed", body: localKeyErrorText(e), tone: "danger" });
	            return false;
	        }
	}
