/**
 * 05-files-actions.js
 * Asset lifecycle + access-control UI actions:
 *   - showUploadResult + uploadFile (encrypt, store, register on ledger)
 *   - loadFiles / applyAssetSearchFilter - "My uploads" table
 *   - requestAccess / cancelMyRequest / reopenMyRequest
 *   - grantAccess / revokeAccess - owner actions
 *   - rotateAssetContentUI - owner key-rotation
     *   - downloadAsset / downloadFile - ECDH key envelope + AES-GCM payload fetch
 *   - showMetadata, approveCategoryUI, denyAccessUI
 *   - Security panel (secLoadUsers / secBlock / secUnblock / secCheck)
 */

function showUploadResult({ cid, assetId, suggested, confidence, needsReview, actionableSuggestion = false, storedOnChain = false }) {
    const el = document.getElementById("uploadResult");
    if (!el) return;
    el.dataset.assetId = assetId || "";
    el.dataset.cid = cid || "";
    el.dataset.suggested = suggested || "";
    el.dataset.confidence = (confidence !== undefined && confidence !== null) ? String(confidence) : "";
    renderUploadResultCard({
        assetId,
        cid,
        suggested,
        confidence,
        needsReview,
        storedOnChain: !!storedOnChain
    });
}

    async function uploadFile() {
        if (IDENTITY && IDENTITY.registered === false) {
            await uiAlert({ title: "Not registered", body: "Profile is not registered on-ledger. Please register in Settings.", tone: "warning" });
            try { showSettingsTab(); } catch {}
            return;
        }

		        // Ensure the local browser key is unlocked before encrypting a new upload.
	        try {
	            await ensureLocalKeyReady({ interactive: true, allowCreate: true });
	        } catch (e) {
	            await uiAlert({ title: "Upload", body: localKeyErrorText(e), tone: "danger" });
	            return;
	        }

        const btn = document.getElementById('btnUpload');
        const fileInput = document.getElementById('fileInput');
        const desc = document.getElementById('fileDesc').value;
        const resultEl = document.getElementById('uploadResult');
        if (resultEl) { resultEl.classList.add('d-none'); resultEl.innerHTML = ''; }

        const title = document.getElementById('metaTitle').value;
        const authors = document.getElementById('metaAuthors').value;
        const discipline = document.getElementById('metaDiscipline').value;
        const licenseStr = document.getElementById('metaLicense').value;
        const doi = document.getElementById('metaDOI').value;
        const keywords = document.getElementById('metaKeywords').value;

        if (!fileInput.files[0]) { await uiAlert({title:"Upload", body:"Select a file first.", tone:"warning"}); return; }

        const originalText = btn.innerText;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';
        btn.disabled = true;

        const file = fileInput.files[0];
        log("Processing upload...");

        const aesKeyB64 = await generateContentKeyB64();
        log(`🔹 AES-GCM content key generated.`);

        const reader = new FileReader();
        reader.onload = async function (e) {
            try {
                const buffer = e && e.target ? e.target.result : null;
                const fileBytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array();
                if (!fileBytes.length) throw new Error("Failed to read file bytes");

	                const fileHash = sha256HexFromBytes(fileBytes);
                    const predictedAssetId = `asset_${fileHash.slice(0, 8)}`;
                    const rawMetadataForAad = {
                        title,
                        authors,
                        discipline,
                        license: licenseStr,
                        doi,
                        keywords,
                        description: desc,
                        owner: CURRENT_USER
                    };

	                const filePayload = await encryptContentEnvelopeV2(
                        fileBytes,
                        aesKeyB64,
                        contentEnvelopeAadFor({
                            assetId: predictedAssetId,
                            fileHash,
                            filename: file.name,
                            metadata: rawMetadataForAad
                        })
                    );

		                const encryptedAesKey = await rsaEncryptForStoredPublicKey(myPublicKey, aesKeyB64);

                const blob = new Blob([filePayload], { type: "application/octet-stream" });

                const fd = new FormData();
                fd.append('file', blob, file.name + ".enc");
                fd.append('description', desc);
                fd.append('fileHash', fileHash);
                fd.append('owner', CURRENT_USER);
                fd.append('encryptedAesKey', encryptedAesKey);

                fd.append('title', title);
                fd.append('authors', authors);
                fd.append('discipline', discipline);
                fd.append('license', licenseStr);
                fd.append('doi', doi);
                fd.append('keywords', keywords);

                log("Uploading to IPFS (server)...");
                const res = await authFetch(`${API_URL}/upload`, { method: 'POST', body: fd });
                const json = await res.json();

                if (json.status !== 'success') {
                    log("❌ Upload Error: " + (json.message || "unknown"));
                    return;
                }

                                const cid = json.cid;
                                const assetId = json.asset_id;
                                const storage = json.storage || {};

                                // DISP decision from backend (source of truth)
                                const dispDecision = json.disp_decision || "allow";
                                const dispFlags = Array.isArray(json.disp_flags) ? json.disp_flags : [];
                                const dispScore = (json.disp_score !== undefined && json.disp_score !== null) ? json.disp_score : null;

                                // Always use sanitized fields returned by backend (never trust raw form fields for ledger writes)
                                const fileHashS = json.fileHash || fileHash;
                                const encryptedAesKeyS = json.encryptedAesKey || encryptedAesKey;
                                const descS = json.description ?? "";
                                const titleS = json.title ?? "";
                                const authorsS = json.authors ?? "";
                                const disciplineS = json.discipline ?? "";
                                const licenseS = json.license ?? "";
                                const doiS = json.doi ?? "";
                                const keywordsS = json.keywords ?? "";

                                const suggestedCategory = (json.ai_suggested_category || json.ai_category || "Unclassified");
                                const ledgerCategory = (json.initial_category || "Unverified");

                                const confStr = (json.ai_confidence !== undefined && json.ai_confidence !== null)
                                    ? ` (${json.ai_confidence}%)`
                                    : '';

                                const healthyReplicas = Number(storage.healthy_replicas || 0);
                                const requiredReplicas = Number(storage.required_replicas || 0);
                                if (storage.degraded || !storage.available) {
                                    const detail = storage.last_error ? ` ${storage.last_error}` : "";
                                    log(`⚠️ IPFS stored in degraded mode. CID: ${cid}. Replicas: ${healthyReplicas}/${requiredReplicas || "?"}.${detail} AI suggested: ${suggestedCategory}${confStr}`);
                                } else {
                                    log(`✅ IPFS quorum OK. CID: ${cid}. Replicas: ${healthyReplicas}/${requiredReplicas || "?"}. AI suggested: ${suggestedCategory}${confStr}`);
                                }

                                if (ledgerCategory && String(ledgerCategory).toLowerCase() !== String(suggestedCategory).toLowerCase()) {
                                    log(`ℹ️ Initial on-chain category will be set to: ${ledgerCategory} (needs approval)`);
                                }

                                if (dispDecision !== "allow") {
                                    log(`🛡️ DISP: ${dispDecision}` + (dispScore !== null ? ` score=${dispScore}` : "") + (dispFlags.length ? ` flags=${dispFlags.join(",")}` : ""));
                                    log("⚠️ Content requires manual review. AI suggestion will be computed on sanitized text and requires approval.");
                                }

                                log("Writing asset to blockchain via backend session...");

                                await agentSubmit("CreateAsset", [
                                    assetId,
                                    cid,
                                    String(ledgerCategory),
                                    fileHashS,
                                    descS,
                                    encryptedAesKeyS,
                                    titleS,
                                    authorsS,
                                    disciplineS,
                                    licenseS,
                                    doiS,
                                    keywordsS
                                ]);


                                // Ask backend to compute + persist AI suggestion on-chain via MLService agent (unverified).
                                // IMPORTANT: we send ONLY sanitized metadata returned by /upload.
                                let aiSuggest = isActionableCategory(suggestedCategory) ? suggestedCategory : "";
                                let aiConf = json.ai_confidence;
                                let aiActionable = false;
                                let aiStoredOnChain = false;

                                try {
                                    const r2 = await authFetch(`${API_URL}/ai_suggest_auto`, {
                                        method: "POST",
                                        headers: { "Content-Type": "application/json" },
                                        body: JSON.stringify({
                                            asset_id: assetId,
                                            suggested_category: suggestedCategory,
                                            confidence: aiConf,
                                            metadata: {
                                                title: titleS,
                                                author: authorsS,
                                                department: disciplineS,
                                                description: descS,
                                                keywords: keywordsS
                                            }
                                        })
                                    });
                                    const j2 = await r2.json();
                                    if (j2 && j2.status === "ok") {
                                        aiSuggest = isActionableCategory(j2.suggested_category) ? (j2.suggested_category || aiSuggest) : aiSuggest;
                                        aiConf = (j2.confidence !== undefined && j2.confidence !== null) ? j2.confidence : aiConf;
                                        aiActionable = !!j2.actionable && isActionableCategory(aiSuggest) && Number(aiConf || 0) > 0;
                                        aiStoredOnChain = !!j2.stored_on_chain;
                                        const conf2 = (aiConf !== undefined && aiConf !== null) ? ` (${aiConf}%)` : "";
                                        if (aiActionable && aiStoredOnChain) {
                                            log(` AI suggestion stored (unverified): ${aiSuggest}${conf2}`);
                                        } else if (aiActionable) {
                                            log(` AI suggestion ready, but not yet stored on-chain: ${aiSuggest}${conf2}`);
                                        } else {
                                            log("ℹ AI suggestion is not actionable yet. Category should be reviewed manually.");
                                        }
                                    } else {
                                        log("⚠️ AI suggestion failed: " + ((j2 && j2.message) ? j2.message : "unknown"));
                                    }
                                } catch (e) {
                                    console.warn("ai_suggest_auto failed:", e);
                                    log("⚠️ AI suggestion call failed: " + e.message);
                                }

                                                                // UI: no inline confirm/prompt. Category can be approved later by the owner.
                                if (ledgerCategory && String(ledgerCategory).toLowerCase() === 'unverified') {
                                    log('ℹ️ Category requires manual review. Use "Approve category" as owner.');
                                }

                                log(`✅ Blockchain OK. Asset ID: ${assetId}`);
                                showUploadResult({
                                  cid,
                                  assetId,
                                  suggested: aiSuggest,
                                  confidence: aiConf,
                                  needsReview: String(ledgerCategory || "").toLowerCase() === "unverified",
                                  actionableSuggestion: aiActionable,
                                  storedOnChain: aiStoredOnChain
                                });
                                clearUploadForm();
                                await refreshAssetViews();

            } catch (err) {
                console.error(err);
                log("❌ Upload Error: " + err.message);
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        };
        reader.readAsArrayBuffer(file);
    }

    async function loadFiles() {
        const tbody = document.getElementById('filesTable');
        if (!tbody) return;

        UI_STATE.dashboardCounts = { owned: 0, available: 0, requests: 0, needsReview: 0, pending: 0, needsReviewSec: 0 };
        syncDashboardCounters();

        let me = null;
        try {
            const who = await agentEval("WhoAmI", []);
            me = (who && (who.clientID || who.clientId || who.id)) ? (who.clientID || who.clientId || who.id) : null;
        } catch (e) {
            console.warn("WhoAmI failed:", e);
        }

        try {
            let assets = await agentEval("GetAllAssetsPublic", []);
            if (!Array.isArray(assets)) assets = [];
            assets = assets.map(normalizeAsset);
            for (const asset of assets) {
                const candidate = _extractActionableSuggestion(asset);
                if (candidate && asset && asset.ID) {
                    rememberAssetSuggestion(asset.ID, candidate.suggested, candidate.confidence);
                }
            }
            await fetchIpfsStatusesForAssets(assets);

            let myAssetsById = {};
            try {
                let myAssets = await agentEval("GetMyAssets", []);
                if (!Array.isArray(myAssets)) myAssets = [];
                myAssets = myAssets.map(normalizeAsset);
                for (const a of myAssets) {
                    if (a && a.ID) {
                        myAssetsById[a.ID] = a;
                        const candidate = _extractActionableSuggestion(a);
                        if (candidate) rememberAssetSuggestion(a.ID, candidate.suggested, candidate.confidence);
                    }
                }
            } catch (e) {
                console.warn("GetMyAssets failed:", e);
            }

            let myReqStatusByAsset = {};
            try {
                let myReqs = await agentEval("GetMyRequests", []);
                if (!Array.isArray(myReqs)) myReqs = [];
                for (const r of myReqs) {
                    const aid = r.AssetID || r.assetID || r.assetId || r.asset_id;
                    const st = (r.Status || r.status || "").toString().toUpperCase();
                    if (aid) myReqStatusByAsset[aid] = st;
                }
            } catch (e) {
                console.warn("GetMyRequests failed:", e);
            }

            let pendingByAsset = {};
            try {
                let reqs = await agentEval("GetPendingRequests", []);
                if (!Array.isArray(reqs)) reqs = [];
                for (const r of reqs) {
                    const aid = r.assetID || r.AssetID;
                    if (!aid) continue;
                    if (!pendingByAsset[aid]) pendingByAsset[aid] = [];
                    pendingByAsset[aid].push(r);
                }
            } catch (e) {
                console.warn("GetPendingRequests failed:", e);
            }

            UI_STATE.meClientID = me;
            UI_STATE.myAssetsById = myAssetsById;
            UI_STATE.pendingByAsset = pendingByAsset;
            UI_STATE.myReqStatusByAsset = myReqStatusByAsset;

            if (assets.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="text-muted text-center p-3">No assets found.</td></tr>`;
                try { applyAssetSearchFilter(); } catch {}
                return;
            }

            for (const a of assets) {
                if (a && a.ID) ASSET_CACHE[a.ID] = a;
            }

            let rowsHtml = "";
            let ownedCount = 0;
            let availableCount = 0;
            let needsReviewCount = 0;
            let pendingTotal = 0;
            const requestsCount = Object.keys(myReqStatusByAsset || {}).length;

            for (const v of Object.values(pendingByAsset || {})) {
                if (Array.isArray(v)) pendingTotal += v.length;
            }

            for (const rawAsset of assets.slice().reverse()) {
                const asset = normalizeAsset(rawAsset);
                const isOwner = isAssetOwner(asset, me);
                const review = assetNeedsReview(asset);
                const pend = pendingByAsset[asset.ID] || [];
                const access = assetAccessState(asset, isOwner);
                const ownedAsset = myAssetsById[asset.ID] || {};
                const grantedIds = grantedUserIdsFromAsset(ownedAsset, me);

                if (isOwner) {
                    ownedCount += 1;
                    if (review) needsReviewCount += 1;
                } else if (access.canDownload) {
                    availableCount += 1;
                }

                if (!isOwner) {
                    continue;
                }

                const officialCat = (asset.Category || asset.category || "").toString();
                const aiSuggestion = bestAvailableAssetSuggestion(asset.ID, asset, ownedAsset);
                const aiSug = aiSuggestion.suggested || "";
                const aiConf = aiSuggestion.confidence;
                const aiConfTxt = (aiConf !== undefined && aiConf !== null && aiConf !== "")
                    ? ` <span class="text-muted small">(${escapeHtml(aiConf)}%)</span>`
                    : "";
                const aiCell = isActionableCategory(aiSug)
                    ? `${escapeHtml(aiSug)}${aiConfTxt}`
                    : '<span class="text-muted">—</span>';
                const displayAuthors = asset.Authors || asset.authors || ownedAsset.Authors || ownedAsset.authors || "—";
                const catBadge = review
                    ? '<span class="badge bg-warning text-dark ms-1">Needs review</span>'
                    : (isPlaceholderCategory(officialCat)
                        ? '<span class="badge bg-warning text-dark ms-1">Unverified</span>'
                        : '<span class="badge bg-success ms-1">Approved</span>');
                const catCell = `${escapeHtml(officialCat || "Unverified")} ${catBadge}`;
                const cidText = assetCid(asset) || "—";
                const storageHtml = ipfsStatusHtml(asset);

                const statusParts = [];
                statusParts.push(accessBadgeHtml(access.status));
                if (review) {
                    statusParts.push('<span class="badge bg-warning text-dark">Manual review</span>');
                }
                if (pend.length > 0) {
                    statusParts.push(`<span class="badge bg-warning text-dark">📥 ${pend.length} pending</span>`);
                }
                if (grantedIds.length > 0) {
                    statusParts.push(`<span class="badge bg-success">${grantedIds.length} shared</span>`);
                }
                const statusHtml = statusParts.join(" ");

                let actions = `<div class="d-flex flex-wrap gap-1">`;
                actions += `<button class="btn btn-sm btn-outline-secondary" onclick="openAssetDrawer('${asset.ID}')">Details</button>`;
                actions += `<button class="btn btn-sm btn-outline-success" onclick="downloadAsset('${asset.ID}')">Download</button>`;
                actions += `<button class="btn btn-sm btn-outline-warning" onclick="rotateAssetContentUI('${asset.ID}')">Rotate</button>`;
                if (review) {
                    actions += `<button class="btn btn-sm btn-warning" onclick="approveCategoryUI('${asset.ID}')">Approve category</button>`;
                }
                actions += `</div>`;

                if (pend.length > 0) {
                    actions += `<div class="mt-1 p-1 border rounded small"><div><b>Pending requests:</b></div>`;
                    for (const r of pend) {
                        const requesterID = r.requesterID || r.RequesterID;
                        const requesterName = r.requester || r.Requester || (requesterID ? requesterID.substring(0, 10) + "..." : "unknown");
                        actions += `
                          <div class="d-flex flex-column flex-sm-row align-items-start align-items-sm-center justify-content-between gap-1 mt-1">
                            <div>
                              <div class="break-anywhere" title="${escapeHtml(requesterID)}">${escapeHtml(requesterName)}</div>
                              <div class="text-muted small break-anywhere"><code>${escapeHtml(requesterID)}</code></div>
                            </div>
                            <div class="d-flex flex-wrap gap-1">
                              <button class="btn btn-sm btn-success" onclick="grantAccess('${asset.ID}','${requesterID}')">Grant</button>
                              <button class="btn btn-sm btn-danger" onclick="denyAccessUI('${asset.ID}','${requesterID}')">Deny</button>
                            </div>
                          </div>
                        `;
                    }
                    actions += `</div>`;
                }

                if (grantedIds.length > 0) {
                    actions += `<div class="mt-1 p-1 border rounded small"><div><b>Granted users:</b></div>`;
                    for (const gid of grantedIds) {
                        const short = gid.length > 14 ? `${gid.substring(0, 14)}...` : gid;
                        actions += `
                          <div class="d-flex flex-column flex-sm-row align-items-start align-items-sm-center justify-content-between gap-1 mt-1">
                            <div class="break-anywhere" title="${escapeHtml(gid)}"><code class="small">${escapeHtml(short)}</code></div>
                            <div><button class="btn btn-sm btn-outline-danger" onclick="revokeAccess('${asset.ID}','${gid}')">Revoke</button></div>
                          </div>
                        `;
                    }
                    actions += `</div>`;
                }

                const searchBlob = `${asset.ID || ""} ${asset.Title || asset.title || ""} ${displayAuthors || ""} ${officialCat || ""} ${aiSug || ""} ${asset.Owner || ""} ${asset.OwnerID || ""}`.replace(/\s+/g, " ").trim();
                rowsHtml += `
                    <tr data-search="${escapeHtml(searchBlob)}" data-owned="1" data-review="${review ? 1 : 0}" data-pending="${pend.length > 0 ? 1 : 0}" data-shared="${grantedIds.length > 0 ? 1 : 0}" data-access="${escapeHtml(access.status)}">
                        <td>${escapeHtml(asset.ID || "")}</td>
                        <td>${escapeHtml(asset.Title || asset.title || "")}</td>
                        <td>${escapeHtml(displayAuthors)}</td>
                        <td>${catCell}</td>
                        <td>${aiCell}</td>
                        <td class="role-security-cell"><code class="small">${escapeHtml(cidText)}</code><div class="mt-1">${storageHtml}</div></td>
                        <td>${statusHtml}</td>
                        <td>${actions}</td>
                    </tr>
                `;
            }

            tbody.innerHTML = rowsHtml || `<tr><td colspan="8" class="text-muted text-center p-3">You have not uploaded any files yet.</td></tr>`;
            try { applyAssetSearchFilter(); } catch {}
            syncUploadResultCard();

            UI_STATE.dashboardCounts = {
                owned: ownedCount,
                available: availableCount,
                requests: requestsCount,
                needsReview: needsReviewCount,
                pending: pendingTotal,
                needsReviewSec: needsReviewCount
            };
            syncDashboardCounters();
        } catch (err) {
            console.error(err);
            const msg = humanizeErrorText(err && err.message ? err.message : String(err));
            tbody.innerHTML = `<tr><td colspan="8" class="text-danger text-center p-3">${escapeHtml(msg)}</td></tr>`;
            log("❌ Load Error: " + (err && err.message ? err.message : err));
        }
    }


    
    function applyAssetSearchFilter() {
    const inp = document.getElementById("assetSearchInput");
    const q = (inp ? inp.value : "").trim().toLowerCase();
    const sel = document.getElementById("assetFilterSelect");
    const mode = (sel ? sel.value : "all");
    const tbody = document.getElementById("filesTable");
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll("tr"));
    let visible = 0;

    for (const r of rows) {
        const hay = ((r.dataset && r.dataset.search) ? r.dataset.search : r.textContent).toLowerCase();
        const matchQuery = (!q) ? true : hay.includes(q);

        const review = (r.dataset.review === "1");
        const pending = (r.dataset.pending === "1");
        const shared = (r.dataset.shared === "1");

        let matchMode = true;
        if (mode === "needs_review") matchMode = review;
        else if (mode === "pending") matchMode = pending;
        else if (mode === "shared") matchMode = shared;

        const show = matchQuery && matchMode;
        r.style.display = show ? "" : "none";
        if (show) visible++;
    }

    const cnt = document.getElementById("assetFilterCount");
    if (cnt) cnt.textContent = (rows.length ? `${visible}/${rows.length}` : "");
}
async function requestAccess(assetId) {
        const now = Date.now();
        const key = reqKey(assetId);
        const last = lastRequestTs[key] || 0;
        const lastStatus = lastRequestStatus[key] || "";

        // Cooldown ONLY for truly pending requests (avoid "DENIED but pending cooldown" confusion)
        if (lastStatus === "PENDING" && (now - last) < REQUEST_TTL_MS) {
            log(`⏳ Request already pending for ${assetId} (cooldown)`);
            return;
        }

        log(`Requesting access for ${assetId} via backend session ${agentBase()}...`);

        try {
          const reason = await openAccessRequestModal();
          if (reason === null) return;
          const resp = await agentSubmit("RequestAccessWithReason", [assetId, reason || ""]);
            try { log("ℹ️ Response: " + (typeof resp === "string" ? resp : JSON.stringify(resp))); } catch {}

            // Track request status locally to avoid misleading cooldown after DENIED/APPROVED
            let status = "";
            if (resp && typeof resp === "object" && resp.status) status = String(resp.status);
            if (status) lastRequestStatus[key] = status;
            if (status === "PENDING") {
                pendingRequests.add(assetId);
                lastRequestTs[key] = now;
            } else {
                pendingRequests.delete(assetId);
                delete lastRequestTs[key];
            }

            if (status === "DENIED") {
                const msg = (resp && resp.message) ? String(resp.message) : "DENIED";
                log(`⚠️ Access request DENIED: ${msg}`);
            } else if (status === "PENDING") {
                log("✅ Access request created (PENDING).");
            } else if (status) {
                log(`✅ Access request status: ${status}`);
            } else {
                log("✅ Access request submitted (blockchain).");
            }
            await refreshAssetViews();
        } catch (e) {
            console.error(e);
            pendingRequests.delete(assetId);
            delete lastRequestTs[key];
            lastRequestStatus[key] = "ERROR";
            log("❌ " + e.message);
        }
    }


async function cancelMyRequest(assetId) {
    const ok = await uiConfirm({
        title: "Cancel request",
        body: `Cancel your pending request for <code>${escapeHtml(assetId)}</code>?`,
        okText: "Cancel request",
        okClass: "btn-danger"
    });
    if (!ok) return;

    try {
        await agentSubmit("CancelMyRequest", [assetId]);
        showToast("Request cancelled", "success");
        log("✅ Request cancelled: " + assetId);
        await refreshAssetViews();
    } catch (e) {
        console.error(e);
        await uiAlert({title:"Cancel failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
    }
}

async function reopenMyRequest(assetId) {
    const reason = await uiPrompt({
        title: "Reopen access request",
        label: "Reason (optional)",
        placeholder: "Why do you need access now?",
        value: "",
        multiline: true,
        okText: "Reopen"
    });
    if (reason === null) return;

    try {
        await agentSubmit("RequestAccessWithReason", [assetId, reason || ""]);
        showToast("Request reopened", "success");
        log("✅ Request reopened: " + assetId);
        await refreshAssetViews();
    } catch (e) {
        console.error(e);
        await uiAlert({title:"Reopen failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
    }
}

    async function grantAccess(assetId, requesterID) {
        try {
            if (!requesterID) {
                await uiAlert({title:"Grant access", body:"RequesterID is missing", tone:"warning"});
                return;
            }

            // 1) Fetch my encrypted AES key from chaincode (transaction-safe)
            const ownerKeyResp = await agentSubmit("RequestMyEncryptedKey", [assetId]);
            const ownerStatus = (ownerKeyResp && (ownerKeyResp.status || ownerKeyResp.Status)) || "";
            if (ownerStatus !== "OK") {
                await uiAlert({title:"Grant access", body:`Cannot get your AES key (owner). Status=${ownerStatus}`, tone:"warning"});
                return;
            }
            const ownerEncKey = ownerKeyResp.key || (ownerKeyResp.result && ownerKeyResp.result.key) || "";
            if (!ownerEncKey) {
                await uiAlert({title:"Grant access", body:"No encrypted key returned for owner", tone:"warning"});
                return;
            }

            // 2) Decrypt AES key locally in the browser (private key stays on this device)
            const aesKey = await agentRsaDecrypt(ownerEncKey);
            if (!aesKey) {
                await uiAlert({title:"Grant access", body:"Failed to decrypt owner AES key", tone:"danger"});
                return;
            }
            log(`🔹 AES key obtained for granting.`);

            // 3) Get requester's public key from blockchain
            const requesterPub = await agentEval("GetUserPublicKey", [requesterID]);
            if (!requesterPub) {
                await uiAlert({title:"Grant access", body:"Requester public key not found on-chain", tone:"warning"});
                return;
            }

            // 4) Encrypt AES key for requester
	            let encryptedForRequester = "";
	            try {
	                encryptedForRequester = await rsaEncryptForStoredPublicKey(requesterPub, aesKey.trim());
	            } catch {
	                await uiAlert({title:"Grant access", body:"Failed to encrypt AES key for requester", tone:"danger"});
	                return;
	            }

            // 5) Submit GrantAccess
            await agentSubmit("GrantAccess", [assetId, requesterID, encryptedForRequester]);
            const settled = await waitForAssetProjection(assetId, ({ myAsset, fullAsset, pending }) => {
                const ownerView = myAsset || fullAsset;
                const grantedIds = grantedUserIdsFromAsset(ownerView, UI_STATE.meClientID);
                return grantedIds.includes(requesterID);
            });
            if (settled.projection && Array.isArray(settled.projection.pending)) {
                settled.projection.pending = settled.projection.pending.filter((req) => requestRequesterId(req) !== requesterID);
            }
            applyAssetProjection(assetId, settled.projection);
            log("✅ Access granted on blockchain.");
            showToast("Access granted", "success");
            await refreshAssetViews();
            if (DRAWER_CTX.assetId === assetId) {
                try { await openAssetDrawer(assetId); } catch {}
            }
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Grant failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }


    async function revokeAccess(assetId, targetUserId) {
        const ok = await uiConfirm({title:"Revoke access", body:"This will revoke the user’s ability to download this asset. An audit event will be written.", okText:"Revoke", okClass:"btn-danger"});
        if (!ok) return;
        const reason = (await uiPrompt({title:"Revoke access", label:"Reason (written to audit log)", value:"manual revoke", placeholder:"e.g. policy change / user left project", multiline:false, okText:"Continue"})) || "manual revoke";
        log(`Revoking access for ${targetUserId} via backend session...`);

        try {
            await agentSubmit("RevokeAccess", [assetId, targetUserId, reason]);
            log("✅ Revoked (blockchain).");
            await refreshAssetViews();
        } catch (e) {
            console.error(e);
            log("❌ Revoke Error: " + (e.message || e));
        }
    }

    async function rotateAssetContentUI(assetId) {
        const ok = await uiConfirm({title:"Rotate asset content", body:"This uploads a NEW encrypted payload to IPFS, updates CID on-chain, and resets per-user keys. Everyone except you will lose access until you re-grant it.", okText:"Rotate", okClass:"btn-warning"});
	        if (!ok) return;

	        try {
	            if (!myPublicKey || !myPrivateKey) await ensureLocalKeyReady({ interactive: true, allowCreate: false });
	            // Always fetch full asset (public listing hides CIDHash)
	            const assetAny = await agentEval("ReadAsset", [assetId]);
            const asset = normalizeAsset(assetAny);

            const who = await agentEval("WhoAmI", []);
            const me = (who && (who.clientID || who.clientId || who.id)) ? (who.clientID || who.clientId || who.id) : null;
            if (!me || !asset.OwnerID || me !== asset.OwnerID) {
                await uiAlert({title:"Rotate", body:"Only the asset OWNER can rotate content.", tone:"warning"});
                return;
            }
const cid = ((asset.CIDHash || asset.CID || "").trim() || asset.cidHash || asset.CIDHash || (asset.metadata && (asset.metadata.cidHash || asset.metadata.cid)) || "").toString().trim();
            if (!cid) {
                await uiAlert({title:"Rotate", body:"CID is missing in asset metadata (expected asset.cidHash from chaincode).", tone:"warning"});
                return;
            }

            log(`🔄 Rotating content for ${assetId}...`);
            log(`1) Fetching your AES key (owner) from chaincode...`);

            const ownerKeyResp = await agentSubmit("RequestMyEncryptedKey", [assetId]);
            const ownerStatus = String((ownerKeyResp && (ownerKeyResp.status || ownerKeyResp.Status)) || "");
            if (ownerStatus !== "OK") {
                await uiAlert({title:"Grant access", body:`Cannot get your AES key (owner). Status=${ownerStatus}`, tone:"warning"});
                return;
            }
            const ownerEncKey = ownerKeyResp.key || (ownerKeyResp.result && ownerKeyResp.result.key) || "";
            if (!ownerEncKey) {
                await uiAlert({title:"Grant access", body:"No encrypted key returned for owner", tone:"warning"});
                return;
            }

            const aesKeyB64 = await agentRsaDecrypt(ownerEncKey);
            if (!aesKeyB64) {
                await uiAlert({title:"Grant access", body:"Failed to decrypt owner AES key", tone:"danger"});
                return;
            }

            log(`2) Downloading current encrypted payload through asset authorization...`);
            const res = await authFetch(`${API_URL}/download/asset/${encodeURIComponent(assetId)}`, { method: "POST" });
            if (!res.ok) {
                log(`❌ Failed to download. HTTP ${res.status}`);
                return;
            }

            const encryptedStr = await res.text();
            const decrypted = await decryptContentPayload(encryptedStr, aesKeyB64);
            const decryptedBytes = decrypted.bytes;
            const decryptedBase64 = _bytesToBase64(decryptedBytes);
            const fileHash = sha256HexFromBytes(decryptedBytes);

            const expectedHash = String(asset.FileHash || asset.fileHash || "");
            if (expectedHash && fileHash !== expectedHash) {
                const legacyHash = CryptoJS.SHA256(decryptedBase64).toString();
                if (legacyHash !== expectedHash) {
                    const cont = await uiConfirm({title:"Hash mismatch", bodyHtml:`Expected: <code>${escapeHtml(expectedHash)}</code><br>Actual: <code>${escapeHtml(fileHash)}</code><br><br>Continue rotation anyway?`, okText:"Continue", okClass:"btn-warning"});
                    if (!cont) return;
                } else {
                    log("ℹ️ Legacy hash format detected for this asset. Rotation will normalize it to a byte-level SHA-256.");
                }
            }

            log(`3) Re-encrypting with NEW AES-GCM envelope...`);
            const newAesKeyB64 = await generateContentKeyB64();
            const rotationMetadata = {
                title: String(asset.Title || asset.title || ""),
                authors: String(asset.Authors || asset.authors || ""),
                discipline: String(asset.Discipline || asset.discipline || ""),
                license: String(asset.License || asset.license || ""),
                doi: String(asset.DOI || asset.doi || ""),
                keywords: String(asset.Keywords || asset.keywords || ""),
                description: String(asset.Description || asset.description || "rotated content"),
                owner: CURRENT_USER
            };
            const newPayload = await encryptContentEnvelopeV2(
                decryptedBytes,
                newAesKeyB64,
                contentEnvelopeAadFor({
                    assetId,
                    fileHash,
                    filename: `${assetId}.rotated`,
                    metadata: rotationMetadata
                })
            );

            // Wrap NEW AES key for OWNER
	            const newEncryptedAesKeyForOwner = await rsaEncryptForStoredPublicKey(myPublicKey, newAesKeyB64);

            log(`4) Uploading NEW encrypted payload to IPFS (server)...`);
            const blob = new Blob([newPayload], { type: "application/octet-stream" });

            // Filename policy (server.py):
            //   YYYYMMDD_Author_Topic.ext.enc
            // - Author: [a-zA-Z]+
            // - Topic:  [a-zA-Z0-9]+
            // - ext: one of ALLOWED_EXTENSIONS (pdf,csv,json,txt,xlsx,docx)
            const d = new Date();
            const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
            const author = (String(CURRENT_USER || "User").replace(/[^a-zA-Z]/g, "") || "User");
            const topic = "Rotate"; // alnum only
            const realExt = "txt";
            const filename = `${stamp}_${author}_${topic}.${realExt}.enc`;

            const fd = new FormData();
            fd.append('file', blob, filename);
            fd.append('description', String(asset.Description || asset.description || "rotated content"));
            fd.append('fileHash', fileHash);
            fd.append('owner', CURRENT_USER);
            fd.append('encryptedAesKey', newEncryptedAesKeyForOwner);

            fd.append('title', String(asset.Title || asset.title || ""));
            fd.append('authors', String(asset.Authors || asset.authors || ""));
            fd.append('discipline', String(asset.Discipline || asset.discipline || ""));
            fd.append('license', String(asset.License || asset.license || ""));
            fd.append('doi', String(asset.DOI || asset.doi || ""));
            fd.append('keywords', String(asset.Keywords || asset.keywords || ""));

            const up = await authFetch(`${API_URL}/upload`, { method: 'POST', body: fd });
            const upj = await up.json();
            // server.py returns: {status:"success", cid:"..."} on success
            if (!upj || upj.status !== 'success') {
                throw new Error((upj && (upj.message || upj.error)) ? (upj.message || upj.error) : "upload failed");
            }
            const newCID = String(upj.cid || "").trim();
            if (!newCID) throw new Error("upload did not return CID");
            log(`✅ IPFS OK. New CID: ${newCID}`);

            log(`5) Writing rotation to blockchain (RotateAssetContent)...`);
            await agentSubmit("RotateAssetContent", [assetId, newCID, fileHash, newEncryptedAesKeyForOwner, "{}"]);
            log("✅ Content rotated on-chain. NOTE: all previously granted users lost access; re-grant if needed.");
            await refreshAssetViews();
        } catch (e) {
            console.error(e);
            log("❌ Rotate failed: " + (e.message || e));
        }
    }

    async function downloadAsset(assetId) {
        try {
            // Always fetch full asset via ReadAsset (GetAllAssetsPublic hides CIDHash)
            const assetAny = await agentEval("ReadAsset", [assetId]);
            const asset = normalizeAsset(assetAny);
            const expectedHash = asset.FileHash || asset.fileHash;

            if (!(asset.CIDHash || asset.cidHash || asset.CID || asset.cid)) {
                await uiAlert({title:"Download", body:"CID missing in asset metadata", tone:"warning"});
                return;
            }

            // Fetch my encrypted AES key from chaincode (transaction-safe)
            const keyResp = await agentSubmit("RequestMyEncryptedKey", [assetId]);
            const status = (keyResp && (keyResp.status || keyResp.Status)) || "";
            if (status !== "OK") {
                const msg = (keyResp && (keyResp.message || keyResp.Message)) || "Access denied";
                await uiAlert({title:"Download denied", body: String(msg || "Access denied"), tone:"warning"});
                return;
            }
            const encKey = (keyResp.key || keyResp.Key || "").trim();
            if (!encKey) {
                await uiAlert({title:"Download", body:"No encrypted key returned", tone:"warning"});
                return;
            }
            // Decrypt AES key locally
            const aesKeyB64 = await agentRsaDecrypt(encKey);
            if (!aesKeyB64) {
                await uiAlert({title:"Download", body:"Failed to decrypt AES key (wrong private key?)", tone:"danger"});
                return;
            }

	            await downloadFile(assetId, aesKeyB64.trim(), expectedHash);
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Download failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }

async function downloadFile(assetId, aesKeyB64, expectedHash) {
	        try {
	            log(`Downloading encrypted file through asset authorization...`);
	            log(`🔹 AES key obtained for download.`);

	            // 1) Download encrypted payload from backend -> IPFS
	            const res = await authFetch(`${API_URL}/download/asset/${encodeURIComponent(assetId)}`, { method: "POST" });
	            if (!res.ok) {
	                log(`❌ Failed to download. HTTP ${res.status}`);
	                return;
	            }

	            const encryptedStr = await res.text();
	            const decrypted = await decryptContentPayload(encryptedStr, aesKeyB64);

	            // 3) Verify the recovered bytes. Fallback to the legacy base64 hash so
	            // older uploads remain downloadable after the verification fix.
	            const decryptedBytes = decrypted.bytes;
            const decryptedBase64 = _bytesToBase64(decryptedBytes);
            let actualHash = sha256HexFromBytes(decryptedBytes);
            if (expectedHash && actualHash !== expectedHash) {
                const legacyHash = CryptoJS.SHA256(decryptedBase64).toString();
                if (legacyHash === expectedHash) {
                    actualHash = legacyHash;
                    log("ℹ️ Legacy hash format detected for this asset. Verification passed using the historic hash scheme.");
                } else {
                    log("❌ HASH MISMATCH! Download aborted.");
                    log(`Expected: ${expectedHash}`);
                    log(`Actual:   ${actualHash}`);
                    await uiAlert({title:"Integrity check failed", body:"Hash mismatch. File may be corrupted or tampered.", tone:"danger"});
                    return;
                }
            }

            log("✅ Hash Verified! Logging download to blockchain...");

            // 4) Log download to blockchain (via agent)
            try {
                await agentSubmit("LogDownload", [assetId]);
                log("✅ Download logged (blockchain).");
            } catch (e) {
                console.error(e);
                log("⚠️ Could not log download: " + e.message);
            }

            // 5) Save the restored bytes
            const blob = new Blob([decryptedBytes], { type: "application/octet-stream" });

            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = `${assetId}.bin`;
            a.click();
            URL.revokeObjectURL(a.href);

            log("✅ File saved.");

        } catch (e) {
            console.error(e);
            log("❌ Download/Decrypt Error: " + e.message);
        }
    }



    async function showMetadata(assetId) {
        try {
            const full = await agentEval("ReadAsset", [assetId]);
            const asset = normalizeAsset(full);
            const meta = asset.metadata || asset.Metadata || {};
            const suggestion = bestAvailableAssetSuggestion(
                assetId,
                asset,
                UI_STATE.myAssetsById[assetId] || null,
                ASSET_CACHE[assetId] || null
            );
            const sug = suggestion.suggested || "";
            const conf = suggestion.confidence;
            const review = assetNeedsReview(asset);

            const cat = asset.Category || asset.category || "";
            const catBadge = review
                ? '<span class="badge bg-warning text-dark ms-1">Needs review</span>'
                : (cat === "Unverified"
                    ? '<span class="badge bg-warning text-dark ms-1">Unverified</span>'
                    : '<span class="badge bg-success ms-1">Approved</span>');

            const suggestedHtml = `${escapeHtml(sug || "—")}` +
                ((conf !== undefined && conf !== null && conf !== "")
                    ? ` <span class="text-muted small">(${escapeHtml(conf)}%)</span>`
                    : "");

            const bodyHtml = `
              <div class="row g-2">
                <div class="col-md-6"><b>Asset ID:</b> ${escapeHtml(asset.ID)}</div>
                <div class="col-md-6"><b>OwnerID:</b> <code>${escapeHtml(asset.OwnerID)}</code></div>
                <div class="col-md-12"><b>CID:</b> <code>${escapeHtml(asset.CIDHash)}</code></div>
                <div class="col-md-12"><b>Category:</b> ${escapeHtml(cat)} ${catBadge}</div>
                <hr class="my-2">
                <div class="col-md-6"><b>Title:</b> ${escapeHtml(meta.title || asset.Title || "")}</div>
                <div class="col-md-6"><b>Authors:</b> ${escapeHtml(meta.authors || asset.Authors || "")}</div>
                <div class="col-md-6"><b>Discipline:</b> ${escapeHtml(meta.discipline || asset.Discipline || "")}</div>
                <div class="col-md-6"><b>License:</b> ${escapeHtml(meta.license || asset.License || "")}</div>
                <div class="col-md-6"><b>DOI:</b> ${escapeHtml(meta.doi || asset.DOI || "")}</div>
                <div class="col-md-6"><b>Keywords:</b> ${escapeHtml(meta.keywords || asset.Keywords || "")}</div>
                <hr class="my-2">
                <div class="col-md-12"><b>Suggested:</b> ${suggestedHtml}</div>
              </div>
            `;
	            setSanitizedHtml(document.getElementById("metadataModalBody"), bodyHtml);

            // If Bootstrap JS isn't available (e.g., no internet/CDN blocked), fall back to a simple dialog.
            if (window.bootstrap && bootstrap.Modal) {
                const modal = new bootstrap.Modal(document.getElementById("metadataModal"));
                modal.show();
            } else {
                // Minimal fallback: show as an alert with plain text.
                const txt =
                    `Asset: ${asset.ID}\n` +
                    `Owner: ${asset.OwnerID}\n` +
                    `CID: ${asset.CIDHash}\n` +
                    `Category: ${cat}${review ? ' (Needs review)' : ''}\n` +
                    `Title: ${(meta.title || asset.Title || '')}\n` +
                    `Authors: ${(meta.authors || asset.Authors || '')}\n` +
                    `Discipline: ${(meta.discipline || asset.Discipline || '')}\n` +
                    `License: ${(meta.license || asset.License || '')}\n` +
                    `DOI: ${(meta.doi || asset.DOI || '')}\n` +
                    `Keywords: ${(meta.keywords || asset.Keywords || '')}\n` +
                    `Suggested: ${sug || '—'}${(conf !== undefined && conf !== null && conf !== '') ? ' (' + conf + '%)' : ''}`;
                await uiAlert({title:"Metadata", body: txt, tone:"info"});
            }
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Metadata load failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }

    async function approveCategoryUI(assetId) {
    if (APPROVALS_IN_FLIGHT.has(assetId)) {
        showToast("Category approval is already running", "info");
        return;
    }
    APPROVALS_IN_FLIGHT.add(assetId);
    try {
        let asset = normalizeAsset(await agentEval("ReadAsset", [assetId]));
        for (let attempt = 0; attempt < 4; attempt += 1) {
            const currentSuggested = bestAvailableAssetSuggestion(
                assetId,
                asset,
                UI_STATE.myAssetsById[assetId] || null,
                ASSET_CACHE[assetId] || null
            ).suggested;
            const needsReviewNow = assetNeedsReview(asset);
            if (!needsReviewNow || isActionableCategory(currentSuggested)) break;
            await sleep(350);
            asset = normalizeAsset(await agentEval("ReadAsset", [assetId]));
        }

        const suggestion = bestAvailableAssetSuggestion(
            assetId,
            asset,
            UI_STATE.myAssetsById[assetId] || null,
            ASSET_CACHE[assetId] || null
        );
        const sug = suggestion.suggested || "";
        const conf = suggestion.confidence;
        const current = (asset.Category || asset.category || "").toString();
        const needsReview = assetNeedsReview(asset);
        if (!needsReview) {
            showToast("Category is already approved", "info");
            const settled = await waitForAssetProjection(assetId, ({ publicAsset, myAsset, fullAsset }) => {
                const view = publicAsset || myAsset || fullAsset;
                return !!view && !assetNeedsReview(view);
            }, { timeoutMs: 1500, intervalMs: 250 });
            applyAssetProjection(assetId, settled.projection);
            await refreshAssetViews();
            return;
        }

        // Fill modal
        document.getElementById("approveAssetId").textContent = assetId;
        document.getElementById("approveCurrent").textContent = current || "—";
        document.getElementById("approveSuggested").textContent = isActionableCategory(sug) ? sug : "—";
        document.getElementById("approveConfidence").textContent = (conf !== undefined && conf !== null && conf !== "") ? String(conf) + "%" : "—";
        document.getElementById("approveNeedsReview").textContent = needsReview ? "Yes" : "No";
        const hintEl = document.getElementById("approveModalHint");
        if (hintEl) {
            hintEl.textContent = isActionableCategory(sug)
                ? "The AI suggestion can be accepted as-is or edited before approval."
                : "No actionable AI suggestion is available yet. Enter the final category manually.";
        }

        const input = document.getElementById("approveCategoryInput");
        input.value = (isActionableCategory(sug) ? sug : (isActionableCategory(current) ? current : "")).trim();

        const chk = document.getElementById("approveAck");
        chk.checked = false;

        const mEl = document.getElementById("approveModal");
        const modal = bootstrap.Modal.getOrCreateInstance(mEl, { backdrop: "static" });

        const okBtn = document.getElementById("approveModalOk");
        okBtn.disabled = true;

        const onChange = () => {
            const proposed = (input.value || "").trim();
            okBtn.disabled = !(chk.checked && proposed && !isPlaceholderCategory(proposed));
        };
        chk.onchange = onChange;
        input.oninput = onChange;
        onChange();

        const approved = await new Promise((resolve) => {
            const cleanup = () => {
                okBtn.onclick = null;
                mEl.removeEventListener("hidden.bs.modal", onHidden);
            };
            const onHidden = () => { cleanup(); resolve(null); };
            okBtn.onclick = () => {
                const v = (input.value || "").trim();
                if (isPlaceholderCategory(v)) {
                    if (hintEl) hintEl.textContent = "Choose a concrete category. Placeholder values such as Unverified/Unknown cannot be approved.";
                    return;
                }
                cleanup();
                modal.hide();
                resolve(v);
            };
            mEl.addEventListener("hidden.bs.modal", onHidden);
            modal.show();
            setTimeout(() => input.focus(), 100);
        });

        if (!approved) return;

        await agentSubmit("ApproveCategory", [assetId, approved]);
        const settled = await waitForAssetProjection(assetId, ({ publicAsset, myAsset, fullAsset }) => {
            const view = publicAsset || myAsset || fullAsset;
            const category = String((view && (view.Category || view.category)) || "").trim().toLowerCase();
            return !!view && !assetNeedsReview(view) && category === approved.trim().toLowerCase();
        });
        applyAssetProjection(assetId, settled.projection);
        log("✅ Category approved: " + approved);
        showToast("Category approved", "success");
        await refreshAssetViews();
    } catch (e) {
        console.error(e);
        await uiAlert({title:"Approve failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
    } finally {
        APPROVALS_IN_FLIGHT.delete(assetId);
    }
}

    async function denyAccessUI(assetId, requesterID) {
        try {
            const reason = await uiPrompt({title:"Deny access", label:"Reason (optional)", value:"Manual deny", placeholder:"e.g. not enough justification / policy", multiline:true, okText:"Deny", cancelText:"Cancel"}); if (reason === null) return;
            await agentSubmit("DenyAccess", [assetId, requesterID, reason || "Manual deny"]);
            log("✅ Access denied (manual).");
            await refreshAssetViews();
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Deny failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }


    function secPanelVisible() {
        const panel = document.getElementById("securityPanel");
        if (!panel) return;
        const show = !!(IDENTITY && IDENTITY.role === "SecurityService");
        panel.classList.toggle("d-none", !show);
        if (show) setTimeout(secLoadUsers, 100);
    }
    
    async function secLoadUsers() {
        if (!(IDENTITY && IDENTITY.role === "SecurityService")) return;
        const sel = document.getElementById("secTargetId");
        if (!sel) return;
        try {
            const list = await agentEval("GetAllUserProfiles", []);
            sel.innerHTML = '<option value="">(Select user)</option>';
            if (Array.isArray(list)) {
                for (const u of list) {
                    const opt = document.createElement("option");
                    opt.value = u.userID || u.UserID || "";
                    opt.textContent = `${u.username || u.Username} (${u.role || u.Role}) - ${u.userID ? u.userID.slice(0, 16) + '...' : ''}`;
                    sel.appendChild(opt);
                }
            }
        } catch (e) {
            console.error("Failed to load users for sec panel", e);
        }
    }

    function secOut(v) {
        const out = document.getElementById("secOut");
        const statusLine = document.getElementById("secStatusLine");
        const statusWrap = document.getElementById("secStatusWrap");
        
        if (statusWrap) statusWrap.style.display = v ? "block" : "none";
        
        if (!out) return;
        if (v === undefined) {
             out.textContent = ""; 
             if (statusLine) statusLine.textContent = "Select a user to check status.";
             out.classList.add("d-none");
        } else {
             if (typeof v === "object") {
                 let str = "";
                 if (v.action === "BLOCK") str = `Success: User blocked. Reason: ${v.reason}`;
                 else if (v.action === "UNBLOCK") str = "Success: User unblocked.";
                 else if (v.blocked !== undefined) str = `Status: ${v.blocked === "true" || v.blocked === true || v.isBlocked ? "BLOCKED ❌" : "ACTIVE ✅"}`;
                 if (statusLine) statusLine.textContent = str;
                 
                 // Show raw details in secOut if needed
                 out.textContent = JSON.stringify(v, null, 2);
                 out.classList.remove("d-none");
             } else {
                 if (statusLine) statusLine.textContent = String(v);
                 out.textContent = String(v);
                 out.classList.remove("d-none");
             }
        }
    }

    function secGetTarget() {
        const el = document.getElementById("secTargetId");
        const id = (el?.value || "").trim();
        if (!id) throw new Error("Please select a target user.");
        return id;
    }

    async function secCheck() {
        try {
            if (!(IDENTITY && IDENTITY.role === "SecurityService")) throw new Error("Only SecurityService can use this action");
            const id = document.getElementById("secTargetId")?.value;
            if (!id) {
                secOut(undefined);
                return;
            }
            const res = await agentEval("GetUserProfile", [id]);
            if (res) {
                 secOut(res);
                 log(`ℹ️ UserProfile loaded for ${id.slice(0, 10)}...`);
            } else {
                 secOut({ error: "Not found" });
            }
        } catch (e) {
            console.error(e);
            uiAlert({title:"Security check failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }

    async function secBlock() {
        try {
            if (!(IDENTITY && IDENTITY.role === "SecurityService")) throw new Error("Only SecurityService can use this action");
            const id = secGetTarget();
            const reason = (document.getElementById("secReason")?.value || "manual block").trim();
            await agentSubmit("BlockUser", [id, reason]);
            secOut({ clientID: id, action: "BLOCK", reason });
            log(`✅ BlockUser: ${id}`);
            setTimeout(secCheck, 500);
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Block failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }

    async function secUnblock() {
        try {
            if (!(IDENTITY && IDENTITY.role === "SecurityService")) throw new Error("Only SecurityService can use this action");
            const id = secGetTarget();
            await agentSubmit("UnblockUser", [id]);
            secOut({ clientID: id, action: "UNBLOCK" });
            log(`✅ UnblockUser: ${id}`);
            setTimeout(secCheck, 500);
        } catch (e) {
            console.error(e);
            await uiAlert({title:"Unblock failed", body: (e && e.message) ? e.message : String(e), tone:"danger"});
        }
    }
