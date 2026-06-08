/**
 * 02-assets-crypto.js
 * Asset-model helpers + low-level cryptography primitives:
 *   - normalizeAsset, assetCid, ipfsStatusForAsset, accessBadgeHtml
 *   - isAssetOwner / assetAccessState / CanDownload checks
 *   - IPFS status table refresher + per-user access projection cache
 *   - Upload result card (render / clear / snapshot)
 *   - Protected local data-encryption keystore (IndexedDB + WebCrypto)
 *   - Legacy browser RSA envelope loader + migrations
 *   - Fabric enrollment CSR builder (DER / PKCS10)
 *   - PEM / DER / BigInt / ECDSA signature utilities
 *   - argon2 result parser + SHA-256 helper
 */

    function normalizeAsset(a) {
        if (!a) return a;
        if (!a.ID && a.id) a.ID = a.id;
        if (!a.CID && a.cid) a.CID = a.cid;
        if (!a.CIDHash && a.cidHash) a.CIDHash = a.cidHash;
        if (!a.OwnerID && a.ownerID) a.OwnerID = a.ownerID;
        if (!a.Category && a.category) a.Category = a.category;
        if (!a.FileHash && a.fileHash) a.FileHash = a.fileHash;
        if (!a.Description && a.description) a.Description = a.description;

        if (!a.Keys && a.keys) a.Keys = a.keys;
        if (!a.AccessLog && a.accessLog) a.AccessLog = a.accessLog;
        if (!a.AccessStatus && a.accessStatus) a.AccessStatus = a.accessStatus;
        if (a.CanDownload === undefined && a.canDownload !== undefined) a.CanDownload = !!a.canDownload;
        if (a.CanRequest === undefined && a.canRequest !== undefined) a.CanRequest = !!a.canRequest;

        if (!a.title && a.Title) a.title = a.Title;
        if (!a.authors && a.Authors) a.authors = a.Authors;
        if (!a.discipline && a.Discipline) a.discipline = a.Discipline;
        if (!a.license && a.License) a.license = a.License;
        if (!a.doi && a.DOI) a.doi = a.DOI;
        if (!a.keywords && a.Keywords) a.keywords = a.Keywords;
        // Pull nested metadata (chaincode returns {metadata:{title,...}})
        if (a.metadata) {
            if (!a.Title && a.metadata.title) a.Title = a.metadata.title;
            if (!a.Authors && a.metadata.authors) a.Authors = a.metadata.authors;
            if (!a.Discipline && a.metadata.discipline) a.Discipline = a.metadata.discipline;
            if (!a.License && a.metadata.license) a.License = a.metadata.license;
            if (!a.DOI && a.metadata.doi) a.DOI = a.metadata.doi;
            if (!a.Keywords && a.metadata.keywords) a.Keywords = a.metadata.keywords;
        }


        return a;
    }

    function assetCid(asset) {
        return String((asset && (asset.CIDHash || asset.cidHash || asset.CID || asset.cid)) || "").trim();
    }

    function ipfsStatusForAsset(asset) {
        const cid = assetCid(asset);
        return cid ? (IPFS_STATUS_BY_CID[cid] || null) : null;
    }

    function ipfsStatusHtml(asset) {
        const status = ipfsStatusForAsset(asset);
        const cid = assetCid(asset);
        if (!cid) {
            return '<span class="badge bg-secondary">CID hidden</span>';
        }
        if (!status) {
            return '<span class="badge bg-secondary">Checking</span>';
        }
        const healthy = Number(status.healthy_replicas || 0);
        const required = Number(status.required_replicas || 0);
        const tone = healthy >= required ? "success" : (healthy > 0 ? "warning text-dark" : "danger");
        const label = healthy >= required ? "Replicated" : "Degraded";
        const extra = status.last_error ? `<div class="small text-muted">${escapeHtml(status.last_error)}</div>` : "";
        return `<span class="badge bg-${tone}">${label} ${healthy}/${required}</span>${extra}`;
    }

    async function fetchIpfsStatusesForAssets(assets) {
        const cids = Array.from(new Set((Array.isArray(assets) ? assets : []).map(assetCid).filter(Boolean)));
        if (!cids.length) {
            IPFS_STATUS_BY_CID = {};
            return IPFS_STATUS_BY_CID;
        }
        try {
            const res = await authFetch(`${API_URL}/ipfs/statuses`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ cids })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok || !data || !data.ok) throw new Error((data && data.error) ? data.error : "Unable to load storage status");
            IPFS_STATUS_BY_CID = data.statuses || {};
        } catch (err) {
            console.warn("ipfs statuses failed:", err);
        }
        return IPFS_STATUS_BY_CID;
    }

    function isAssetOwner(asset, me = UI_STATE.meClientID) {
        if (!asset) return false;
        const assetId = asset.ID || asset.id || "";
        if (assetId && UI_STATE.myAssetsById && UI_STATE.myAssetsById[assetId]) return true;
        if (me && asset.OwnerID && me === asset.OwnerID) return true;
        if (asset.Owner && asset.Owner === CURRENT_USER) return true;
        return false;
    }

    function assetAccessState(asset, isOwner = false) {
        const raw = (asset && (asset.AccessStatus || asset.accessStatus)) || "";
        const requestRaw = (asset && asset.ID && UI_STATE.myReqStatusByAsset)
            ? UI_STATE.myReqStatusByAsset[asset.ID]
            : "";
        const requestStatus = String(requestRaw || "").trim().toUpperCase();
        let status = String(raw || "").trim().toUpperCase();
        const assetSaysDownload = !!(asset?.CanDownload || asset?.canDownload);
        const hasVisibleProtectedPayload = !!String(asset?.CIDHash || asset?.cidHash || asset?.CID || asset?.cid || "").trim();
        const requestImpliesCurrentAccess = ["APPROVED", "GRANTED"].includes(requestStatus)
            && (assetSaysDownload || (!status && hasVisibleProtectedPayload));

        if ((!status || status === "NONE") && (
            ["PENDING", "DENIED", "REVOKED", "CANCELLED"].includes(requestStatus)
            || requestImpliesCurrentAccess
        )) {
            status = requestStatus;
        }
        if (!status) {
            status = isOwner ? "OWNER" : "NONE";
        }
        const canDownload = !!(isOwner || assetSaysDownload || status === "OWNER" || requestImpliesCurrentAccess);
        let canRequest = isOwner ? false : !!((asset?.CanRequest ?? asset?.canRequest) ?? !["PENDING", "APPROVED", "GRANTED", "OWNER"].includes(status));
        if (!isOwner && requestStatus === "PENDING") canRequest = false;
        return { status, canDownload, canRequest };
    }

    function accessBadgeHtml(status) {
        const normalized = String(status || "").trim().toUpperCase();
        if (normalized === "OWNER") return '<span class="badge bg-info">Owner</span>';
        if (normalized === "APPROVED" || normalized === "GRANTED") return '<span class="badge bg-success">Access: Approved</span>';
        if (normalized === "PENDING") return '<span class="badge bg-warning text-dark">Access: Pending</span>';
        if (normalized === "DENIED") return '<span class="badge bg-danger">Access: Denied</span>';
        if (normalized === "REVOKED" || normalized === "CANCELLED") return '<span class="badge bg-secondary">Access: Closed</span>';
        return '<span class="badge bg-secondary">Access: None</span>';
    }

		    let CURRENT_USER = "";
		    let myPublicKey = null;
		    let myPrivateKey = null;
		    let myKeyFingerprint = "";
        let FABRIC_IDENTITY = { privateKey: null, publicSpkiB64: "", certificatePem: "", userHandle: "" };
        let RECOVERY_EXPORT_CACHE = {
          dataEncryption: null,
          fabricSigning: null,
          createdAt: ""
        };
        let PASSKEY_CACHE = [];
        let IPFS_STATUS_BY_CID = {};
        const LOCAL_AI_SUGGESTIONS_BY_ASSET = {};
        const APPROVALS_IN_FLIGHT = new Set();

		    const REQUEST_TTL_MS = 30_000;
		    const pendingRequests = new Set();
		    const lastRequestTs = {};
		    const lastRequestStatus = {};
		    function reqKey(assetId) { return `${CURRENT_USER}::${assetId}`; }

		    function browserRsaKeyBase(prefix = BROWSER_RSA_PREFIX) {
		        const username = (AUTH_SESSION && AUTH_SESSION.username) ? AUTH_SESSION.username : (CURRENT_USER || "");
            const org = (AUTH_SESSION && AUTH_SESSION.org) ? AUTH_SESSION.org : "org1";
            return `${prefix}:${String(org || "org1").toLowerCase()}:${String(username || "unknown")}`;
		    }

		    function browserRsaRecordId() {
		        return browserRsaKeyBase();
		    }

        function localUnlockRecordKey() {
            return `${LOCAL_UNLOCK_PREFIX}:${browserRsaRecordId()}`;
        }

		    function browserRsaKeySlots(prefix = BROWSER_RSA_PREFIX) {
		        const base = browserRsaKeyBase(prefix);
		        return {
		            base,
		            publicKey: `${base}:public`,
		            privateEnvelope: `${base}:privateEnvelope`,
		            fingerprint: `${base}:fingerprint`
		        };
		    }

		    function _bytesToBase64(bytes) {
		        let binary = "";
		        const chunk = 0x8000;
		        for (let i = 0; i < bytes.length; i += chunk) {
		            const slice = bytes.subarray(i, i + chunk);
		            binary += String.fromCharCode(...slice);
		        }
		        return btoa(binary);
		    }

		    function _base64ToBytes(b64) {
		        const binary = atob(String(b64 || ""));
		        const bytes = new Uint8Array(binary.length);
		        for (let i = 0; i < binary.length; i += 1) {
		            bytes[i] = binary.charCodeAt(i);
		        }
		        return bytes;
		    }

        function _wordArrayToBytes(wordArray) {
            if (!wordArray || !wordArray.sigBytes) return new Uint8Array();
            const words = wordArray.words || [];
            const sigBytes = wordArray.sigBytes || 0;
            const out = new Uint8Array(sigBytes);
            for (let i = 0; i < sigBytes; i += 1) {
                out[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            }
            return out;
        }

        function _bytesToWordArray(bytes) {
            return CryptoJS.lib.WordArray.create(bytes || new Uint8Array());
        }

        function sha256HexFromBytes(bytes) {
            return CryptoJS.SHA256(_bytesToWordArray(bytes)).toString();
        }

        function sha256HexFromText(text) {
            return CryptoJS.SHA256(String(text || "")).toString();
        }

        function randomBytes(length) {
            const out = new Uint8Array(Math.max(1, Number(length) || 1));
            crypto.getRandomValues(out);
            return out;
        }

        function stableStringify(value) {
            if (value === null || typeof value !== "object") return JSON.stringify(value);
            if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;
            return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
        }

        function utf8Bytes(value) {
            return new TextEncoder().encode(String(value || ""));
        }

        function utf8FromBytes(bytes) {
            return new TextDecoder().decode(bytes);
        }

        function jsonToB64(obj) {
            return _bytesToBase64(utf8Bytes(stableStringify(obj || {})));
        }

        function b64ToJson(b64) {
            return JSON.parse(utf8FromBytes(_base64ToBytes(b64 || "")));
        }

        function contentEnvelopeAadFor({ assetId = "", fileHash = "", filename = "", metadata = {} } = {}) {
            const metadataHash = sha256HexFromText(stableStringify(metadata || {}));
            return {
                type: CONTENT_ENVELOPE_V2_TYPE,
                version: 2,
                alg: CONTENT_ENVELOPE_V2_ALG,
                assetId: String(assetId || ""),
                fileHash: String(fileHash || ""),
                filename: String(filename || ""),
                metadataHash
            };
        }

        function contentKeyBytesFromB64(keyB64) {
            const keyBytes = _base64ToBytes(String(keyB64 || "").trim());
            if (keyBytes.length !== 32) throw new Error("CONTENT_KEY_INVALID");
            return keyBytes;
        }

        async function generateContentKeyB64() {
            return _bytesToBase64(randomBytes(32));
        }

        async function encryptContentEnvelopeV2(fileBytes, keyB64, aad = {}) {
            const keyBytes = contentKeyBytesFromB64(keyB64);
            const iv = randomBytes(12);
            const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
            const normalizedAad = Object.assign({}, aad, {
                type: CONTENT_ENVELOPE_V2_TYPE,
                version: 2,
                alg: CONTENT_ENVELOPE_V2_ALG
            });
            const ciphertext = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv,
                    additionalData: utf8Bytes(stableStringify(normalizedAad))
                },
                cryptoKey,
                fileBytes
            );
            return JSON.stringify({
                type: CONTENT_ENVELOPE_V2_TYPE,
                version: 2,
                alg: CONTENT_ENVELOPE_V2_ALG,
                ivB64: _bytesToBase64(iv),
                aad: normalizedAad,
                ciphertextB64: _bytesToBase64(new Uint8Array(ciphertext))
            });
        }

        async function decryptContentPayload(payloadText, keyB64) {
            const raw = String(payloadText || "").trim();
            if (raw.startsWith("{")) {
                const envelope = JSON.parse(raw);
                if (!envelope || envelope.version !== 2 || envelope.type !== CONTENT_ENVELOPE_V2_TYPE || envelope.alg !== CONTENT_ENVELOPE_V2_ALG) {
                    throw new Error("CONTENT_ENVELOPE_UNSUPPORTED");
                }
                const keyBytes = contentKeyBytesFromB64(keyB64);
                const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
                const plaintext = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: _base64ToBytes(envelope.ivB64 || ""),
                        additionalData: utf8Bytes(stableStringify(envelope.aad || {}))
                    },
                    cryptoKey,
                    _base64ToBytes(envelope.ciphertextB64 || "")
                );
                return { bytes: new Uint8Array(plaintext), version: 2, aad: envelope.aad || {} };
            }

            const parts = raw.split("::");
            if (parts.length !== 2) throw new Error("Invalid encrypted file format");
            const iv = CryptoJS.enc.Base64.parse(parts[0]);
            const ciphertext = CryptoJS.enc.Base64.parse(parts[1]);
            const aesKeyWA = CryptoJS.enc.Base64.parse(keyB64);
            const decryptedWA = CryptoJS.AES.decrypt(
                { ciphertext },
                aesKeyWA,
                { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
            );
            decryptedWA.clamp();
            return { bytes: _wordArrayToBytes(decryptedWA), version: 1, aad: {} };
        }

        function isPlaceholderCategory(value) {
            const v = String(value || "").trim().toLowerCase();
            return !v || ["unverified", "unknown", "unclassified", "error"].includes(v);
        }

        function isActionableCategory(value) {
            return !isPlaceholderCategory(value);
        }

        function assetIdOf(asset) {
            if (!asset) return "";
            return String(asset.ID || asset.id || "").trim();
        }

        function assetNeedsReview(asset) {
            return !!(asset && (asset.NeedsManualReview === true || asset.needsManualReview === true));
        }

        function _extractActionableSuggestion(source) {
            if (!source || typeof source !== "object") return null;
            const suggested = String(source.SuggestedCategory || source.suggestedCategory || "").trim();
            if (!isActionableCategory(suggested)) return null;
            const confidence = source.SuggestedConfidence ?? source.suggestedConfidence;
            return {
                suggested,
                confidence: (confidence !== undefined && confidence !== null && confidence !== "") ? confidence : ""
            };
        }

        function rememberAssetSuggestion(assetId, suggested, confidence = "") {
            const wanted = String(assetId || "").trim();
            const label = String(suggested || "").trim();
            if (!wanted || !isActionableCategory(label)) return false;
            LOCAL_AI_SUGGESTIONS_BY_ASSET[wanted] = {
                suggested: label,
                confidence: (confidence !== undefined && confidence !== null && confidence !== "") ? confidence : ""
            };
            return true;
        }

        function uploadResultSuggestionSnapshot(assetId = "") {
            const el = document.getElementById("uploadResult");
            if (!el) return null;
            const wanted = String(assetId || "").trim();
            const cardAssetId = String(el.dataset.assetId || "").trim();
            if (wanted && cardAssetId && wanted !== cardAssetId) return null;
            const suggested = String(el.dataset.suggested || "").trim();
            if (!isActionableCategory(suggested)) return null;
            return {
                suggested,
                confidence: (el.dataset.confidence !== undefined && el.dataset.confidence !== null && el.dataset.confidence !== "")
                    ? el.dataset.confidence
                    : ""
            };
        }

        function bestAvailableAssetSuggestion(assetId, ...sources) {
            for (const source of sources) {
                const candidate = _extractActionableSuggestion(source);
                if (candidate) return candidate;
            }
            const wanted = String(assetId || "").trim();
            if (wanted && LOCAL_AI_SUGGESTIONS_BY_ASSET[wanted]) {
                return Object.assign({}, LOCAL_AI_SUGGESTIONS_BY_ASSET[wanted]);
            }
            return uploadResultSuggestionSnapshot(wanted) || { suggested: "", confidence: "" };
        }

        function grantedUserIdsFromAsset(asset, me = UI_STATE.meClientID) {
            const keysObj = asset ? (asset.Keys || asset.keys) : null;
            if (!keysObj || typeof keysObj !== "object") return [];
            const ownerId = String((asset && (asset.OwnerID || asset.ownerID)) || "").trim();
            const viewerId = String(me || "").trim();
            return Object.keys(keysObj).filter((key) => key && key !== viewerId && key !== ownerId);
        }

        function requestAssetId(req) {
            return String((req && (req.assetID || req.AssetID || req.assetId || req.asset_id)) || "").trim();
        }

        function requestRequesterId(req) {
            return String((req && (req.requesterID || req.RequesterID || req.requester || req.Requester)) || "").trim();
        }

        function findAssetInList(list, assetId) {
            if (!Array.isArray(list)) return null;
            const wanted = String(assetId || "").trim();
            return list.map(normalizeAsset).find((asset) => assetIdOf(asset) === wanted) || null;
        }

        function clearUploadResultCard() {
            const el = document.getElementById("uploadResult");
            if (!el) return;
            delete el.dataset.assetId;
            delete el.dataset.cid;
            delete el.dataset.suggested;
            delete el.dataset.confidence;
            el.classList.add("d-none");
            el.innerHTML = "";
        }

        function clearUploadForm() {
            const textFieldIds = [
                "fileDesc",
                "metaTitle",
                "metaAuthors",
                "metaDiscipline",
                "metaLicense",
                "metaDOI",
                "metaKeywords",
            ];
            for (const id of textFieldIds) {
                const el = document.getElementById(id);
                if (el) el.value = "";
            }
            const fileEl = document.getElementById("fileInput");
            if (fileEl) fileEl.value = "";
        }

        function renderUploadResultCard({ assetId = "", cid = "", suggested = "", confidence = "", needsReview = false, storedOnChain = false } = {}) {
            const el = document.getElementById("uploadResult");
            if (!el) return;
            rememberAssetSuggestion(assetId, suggested, confidence);

            const confTxt = (confidence !== undefined && confidence !== null && confidence !== "") ? `${escapeHtml(confidence)}%` : "";
            const suggestionAvailable = isActionableCategory(suggested);
            const suggestionReady = suggestionAvailable && !!storedOnChain;
            const suggestTxt = suggestionAvailable
                ? `${escapeHtml(suggested)}${confTxt ? ` <span class="text-muted small">(${confTxt})</span>` : ""}`
                : '<span class="text-muted">Awaiting actionable AI suggestion</span>';
            const reviewBadge = needsReview ? `<span class="badge bg-warning text-dark ms-1">Needs review</span>` : `<span class="badge bg-success ms-1">Ready</span>`;
            const reviewBtn = needsReview
                ? `<button class="btn btn-sm btn-outline-warning" onclick="openAssetDrawer('${jsQuote(assetId)}')">Open review</button>`
                : `<button class="btn btn-sm btn-outline-secondary" onclick="openAssetDrawer('${jsQuote(assetId)}')">Open asset</button>`;
            const hint = needsReview
                ? (suggestionReady
                    ? `<div class="small text-muted mt-1">Review the asset once in the owner view and approve the stored AI suggestion there.</div>`
                    : (suggestionAvailable
                        ? `<div class="small text-muted mt-1">AI produced a local suggestion, but it is not on-chain yet. Open review and confirm the final category manually.</div>`
                        : `<div class="small text-muted mt-1">Manual review is required. If AI did not produce a usable suggestion yet, enter the category manually.</div>`))
                : `<div class="small text-muted mt-1">Category is already approved. You can open the asset for details or sharing.</div>`;

            el.classList.remove("d-none");
            el.innerHTML = `
              <div class="card bg-soft">
                <div class="card-body py-2">
                  <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <div>
                      <div class="small text-muted">Upload result</div>
                      <div><b>Asset:</b> <code>${escapeHtml(assetId || "—")}</code> ${reviewBadge}</div>
                      <div><b>CID:</b> <code>${escapeHtml(cid || "—")}</code></div>
                      <div><b>AI suggestion:</b> ${suggestTxt}</div>
                      ${hint}
                    </div>
                    <div class="d-flex gap-2">${reviewBtn}</div>
                  </div>
                </div>
              </div>
            `;
        }

        function syncUploadResultCard() {
            const el = document.getElementById("uploadResult");
            if (!el) return;
            const assetId = String(el.dataset.assetId || "").trim();
            if (!assetId) return;

            const asset = UI_STATE.myAssetsById[assetId] || ASSET_CACHE[assetId] || null;
            if (!asset) return;

            const suggestion = bestAvailableAssetSuggestion(assetId, asset);
            const suggested = suggestion.suggested || "";
            const confidence = suggestion.confidence;
            const needsReview = assetNeedsReview(asset);

            if (!needsReview && isActionableCategory(asset.Category || asset.category || "")) {
                clearUploadResultCard();
                return;
            }

            renderUploadResultCard({
                assetId,
                cid: el.dataset.cid || "",
                suggested,
                confidence,
                needsReview,
                storedOnChain: isActionableCategory(suggested)
            });
        }

        async function fetchAssetProjection(assetId) {
            const wanted = String(assetId || "").trim();
            const [publicRes, myAssetsRes, pendingRes, fullRes] = await Promise.allSettled([
                agentEval("GetAllAssetsPublic", []),
                agentEval("GetMyAssets", []),
                agentEval("GetPendingRequests", []),
                agentEval("ReadAsset", [wanted]),
            ]);

            const publicAsset = (publicRes.status === "fulfilled")
                ? findAssetInList(publicRes.value, wanted)
                : null;
            const myAsset = (myAssetsRes.status === "fulfilled")
                ? findAssetInList(myAssetsRes.value, wanted)
                : null;
            const pending = (pendingRes.status === "fulfilled" && Array.isArray(pendingRes.value))
                ? pendingRes.value.filter((req) => requestAssetId(req) === wanted)
                : [];
            const fullAsset = (fullRes.status === "fulfilled")
                ? normalizeAsset(fullRes.value)
                : null;

            return { publicAsset, myAsset, pending, fullAsset };
        }

        async function waitForAssetProjection(assetId, predicate, { timeoutMs = 9000, intervalMs = 350 } = {}) {
            const deadline = Date.now() + Math.max(500, Number(timeoutMs) || 9000);
            let lastProjection = null;
            while (Date.now() < deadline) {
                lastProjection = await fetchAssetProjection(assetId);
                try {
                    if (predicate(lastProjection)) {
                        return { matched: true, projection: lastProjection };
                    }
                } catch {}
                await sleep(intervalMs);
            }
            return { matched: false, projection: lastProjection };
        }

        function applyAssetProjection(assetId, projection) {
            if (!projection) return;

            const publicAsset = normalizeAsset(projection.publicAsset || projection.fullAsset);
            if (publicAsset && assetIdOf(publicAsset) === assetId) {
                ASSET_CACHE[assetId] = publicAsset;
                const candidate = _extractActionableSuggestion(publicAsset);
                if (candidate) rememberAssetSuggestion(assetId, candidate.suggested, candidate.confidence);
            }

            const myAsset = normalizeAsset(projection.myAsset || projection.fullAsset);
            if (myAsset && assetIdOf(myAsset) === assetId && isAssetOwner(myAsset, UI_STATE.meClientID)) {
                UI_STATE.myAssetsById[assetId] = myAsset;
                const candidate = _extractActionableSuggestion(myAsset);
                if (candidate) rememberAssetSuggestion(assetId, candidate.suggested, candidate.confidence);
            }

            if (Array.isArray(projection.pending)) {
                if (projection.pending.length) UI_STATE.pendingByAsset[assetId] = projection.pending;
                else delete UI_STATE.pendingByAsset[assetId];
            }

            syncUploadResultCard();
        }

        function _timingSafeEqBytes(left, right) {
            if (!left || !right || left.length !== right.length) return false;
            let diff = 0;
            for (let i = 0; i < left.length; i += 1) diff |= (left[i] ^ right[i]);
            return diff === 0;
        }

        function _readLocalUnlockRecord() {
            try {
                const raw = localStorage.getItem(localUnlockRecordKey()) || "";
                if (!raw) return null;
                const rec = JSON.parse(raw);
                if (!rec || !rec.salt || !rec.verifier) return null;
                return rec;
            } catch {
                return null;
            }
        }

        function _writeLocalUnlockRecord(rec) {
            localStorage.setItem(localUnlockRecordKey(), JSON.stringify(rec || {}));
        }

        async function ensureLocalKeyAccessGate() {
            if (AUTH_SESSION && AUTH_SESSION.username && typeof ensureRecentWebAuthnAuth === "function") {
                await ensureRecentWebAuthnAuth({ reason: "Using local data encryption keys requires a fresh passkey confirmation." });
            }
            LOCAL_KEY_UNLOCKED = true;
            return true;
        }

		    function _pemBody(pem) {
		        return String(pem || "")
		            .replace(/-----BEGIN [^-]+-----/g, "")
		            .replace(/-----END [^-]+-----/g, "")
		            .replace(/\s+/g, "");
		    }

		    function _formatPem(label, bytes) {
		        const body = (_bytesToBase64(bytes).match(/.{1,64}/g) || []).join("\n");
		        return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
		    }

		    async function computePublicKeyFingerprint(publicKey) {
		        if (!publicKey) return "";
		        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(publicKey)));
		        return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
		    }

			    function parseStoredPublicKey(publicKey) {
			        const stored = String(publicKey || "").trim();
			        if (!stored) return { kind: "empty", stored: "", pem: "" };
                    if (stored.startsWith(LOCAL_KEY_ECDH_MARKER)) {
                        const payload = stored.slice(LOCAL_KEY_ECDH_MARKER.length).trim();
                        let jwk = null;
                        try { jwk = JSON.parse(payload); } catch { jwk = null; }
                        return {
                            kind: "ecdh-p256",
                            stored,
                            jwk
                        };
                    }
			        if (stored.startsWith(LOCAL_KEY_WEBCRYPTO_MARKER)) {
			            return {
			                kind: "webcrypto",
			                stored,
		                pem: stored.slice(LOCAL_KEY_WEBCRYPTO_MARKER.length).trim()
		            };
		        }
		        return { kind: "legacy", stored, pem: stored };
		    }

			    function formatStoredWebCryptoPublicKey(publicPem) {
			        return `${LOCAL_KEY_WEBCRYPTO_MARKER}\n${String(publicPem || "").trim()}`;
			    }

                function formatStoredEcdhPublicKey(publicJwk) {
                    const jwk = Object.assign({}, publicJwk || {});
                    delete jwk.d;
                    jwk.key_ops = [];
                    jwk.ext = true;
                    return `${LOCAL_KEY_ECDH_MARKER}\n${stableStringify(jwk)}`;
                }

			    function parseEncryptedKeyCiphertext(ciphertext) {
			        const raw = String(ciphertext || "").trim();
			        if (!raw) return { kind: "empty", payload: "" };
                    if (raw.startsWith(LOCAL_KEY_ENVELOPE_V2_PREFIX)) {
                        const payloadB64 = raw.slice(LOCAL_KEY_ENVELOPE_V2_PREFIX.length);
                        return { kind: "key-envelope-v2", payload: payloadB64 };
                    }
			        if (raw.startsWith(LOCAL_KEY_OAEP_CIPHERTEXT_PREFIX)) {
			            return { kind: "webcrypto", payload: raw.slice(LOCAL_KEY_OAEP_CIPHERTEXT_PREFIX.length) };
			        }
			        return { kind: "legacy", payload: raw };
			    }

		    function clearBrowserRsaEnvelope() {
		        try {
		            const slots = browserRsaKeySlots();
		            localStorage.removeItem(slots.publicKey);
		            localStorage.removeItem(slots.privateEnvelope);
		            localStorage.removeItem(slots.fingerprint);
		        } catch {}
		    }

		    function openLocalKeyDb() {
		        return new Promise((resolve, reject) => {
		            if (!window.indexedDB) {
		                reject(new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		                return;
		            }
		            const req = window.indexedDB.open(LOCAL_KEY_DB_NAME, LOCAL_KEY_DB_VERSION);
		            req.onupgradeneeded = () => {
		                const db = req.result;
		                if (!db.objectStoreNames.contains(LOCAL_KEY_STORE)) {
		                    db.createObjectStore(LOCAL_KEY_STORE, { keyPath: "id" });
		                }
		            };
		            req.onsuccess = () => resolve(req.result);
		            req.onerror = () => reject(req.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		        });
		    }

		    async function readProtectedLocalKeyRecord() {
		        let db = null;
		        try {
		            db = await openLocalKeyDb();
		            return await new Promise((resolve, reject) => {
		                try {
		                    const tx = db.transaction(LOCAL_KEY_STORE, "readonly");
		                    const store = tx.objectStore(LOCAL_KEY_STORE);
		                    const req = store.get(browserRsaRecordId());
		                    req.onsuccess = () => resolve(req.result || null);
		                    req.onerror = () => reject(req.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		                    tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		                } catch (e) {
		                    reject(e);
		                }
		            });
		        } finally {
		            try { if (db) db.close(); } catch {}
		        }
		    }

		    async function writeProtectedLocalKeyRecord(record) {
		        let db = null;
		        try {
		            db = await openLocalKeyDb();
		            return await new Promise((resolve, reject) => {
		                try {
		                    const tx = db.transaction(LOCAL_KEY_STORE, "readwrite");
		                    const store = tx.objectStore(LOCAL_KEY_STORE);
		                    store.put(Object.assign({}, record, { id: browserRsaRecordId() }));
		                    tx.oncomplete = () => resolve(true);
		                    tx.onerror = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		                    tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
		                } catch (e) {
		                    reject(e);
		                }
		            });
		        } finally {
		            try { if (db) db.close(); } catch {}
		        }
		    }

        async function deleteProtectedLocalKeyRecord() {
            let db = null;
            try {
                db = await openLocalKeyDb();
                return await new Promise((resolve, reject) => {
                    try {
                        const tx = db.transaction(LOCAL_KEY_STORE, "readwrite");
                        const store = tx.objectStore(LOCAL_KEY_STORE);
                        store.delete(browserRsaRecordId());
                        tx.oncomplete = () => resolve(true);
                        tx.onerror = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                        tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                    } catch (e) {
                        reject(e);
                    }
                });
            } finally {
                try { if (db) db.close(); } catch {}
            }
        }

		    async function _generateLegacyProtectorKey() {
		        return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
		    }

		    async function _protectLegacyPrivateKey(privateKey) {
		        const protectorKey = await _generateLegacyProtectorKey();
		        const iv = crypto.getRandomValues(new Uint8Array(12));
		        const ciphertext = await crypto.subtle.encrypt(
		            { name: "AES-GCM", iv },
		            protectorKey,
		            new TextEncoder().encode(String(privateKey || ""))
		        );
		        return {
		            protectorKey,
		            envelope: {
		                iv: _bytesToBase64(iv),
		                ciphertext: _bytesToBase64(new Uint8Array(ciphertext))
		            }
		        };
		    }

		    async function _unprotectLegacyPrivateKey(record) {
		        if (!(record && record.protectorKey && record.privateEnvelope && record.privateEnvelope.iv && record.privateEnvelope.ciphertext)) {
		            throw new Error("LOCAL_KEY_RECORD_INVALID");
		        }
		        const plaintext = await crypto.subtle.decrypt(
		            { name: "AES-GCM", iv: _base64ToBytes(record.privateEnvelope.iv) },
		            record.protectorKey,
		            _base64ToBytes(record.privateEnvelope.ciphertext)
		        );
		        return new TextDecoder().decode(plaintext);
		    }

		    function loadBrowserRsaEnvelope() {
		        try {
		            const slots = browserRsaKeySlots();
		            const publicKey = localStorage.getItem(slots.publicKey) || null;
		            const fingerprint = localStorage.getItem(slots.fingerprint) || null;
		            const rawEnvelope = localStorage.getItem(slots.privateEnvelope) || "";
		            let envelope = null;
		            if (rawEnvelope) {
		                try {
		                    envelope = JSON.parse(rawEnvelope);
		                } catch {
		                    envelope = null;
		                }
		            }
		            return { publicKey, fingerprint, envelope };
		        } catch {
		            return { publicKey: null, fingerprint: null, envelope: null };
		        }
		    }

		    function loadLegacyBrowserRsaPair() {
		        try {
		            const base = browserRsaKeyBase(BROWSER_RSA_LEGACY_PREFIX);
		            const publicKey = localStorage.getItem(`${base}:public`) || null;
		            const privateKey = localStorage.getItem(`${base}:private`) || null;
		            return { publicKey, privateKey };
		        } catch {
		            return { publicKey: null, privateKey: null };
		        }
		    }

		    function clearLegacyBrowserRsaPair() {
		        try {
		            const base = browserRsaKeyBase(BROWSER_RSA_LEGACY_PREFIX);
		            localStorage.removeItem(`${base}:public`);
		            localStorage.removeItem(`${base}:private`);
		        } catch {}
		    }

		    async function exportWebCryptoPublicKeyPem(publicKey) {
		        const spki = await crypto.subtle.exportKey("spki", publicKey);
		        return _formatPem("PUBLIC KEY", new Uint8Array(spki));
		    }

			    async function importStoredWebCryptoPublicKey(publicKey) {
			        const parsed = parseStoredPublicKey(publicKey);
			        if (parsed.kind !== "webcrypto" || !parsed.pem) {
			            throw new Error("PUBLIC_KEY_ALGORITHM_UNSUPPORTED");
		        }
		        const der = _base64ToBytes(_pemBody(parsed.pem));
		        return crypto.subtle.importKey(
		            "spki",
		            der,
		            { name: "RSA-OAEP", hash: "SHA-256" },
		            false,
		            ["encrypt"]
			        );
			    }

                async function importStoredEcdhPublicKey(publicKey) {
                    const parsed = parseStoredPublicKey(publicKey);
                    if (parsed.kind !== "ecdh-p256" || !parsed.jwk) {
                        throw new Error("PUBLIC_KEY_ALGORITHM_UNSUPPORTED");
                    }
                    return crypto.subtle.importKey(
                        "jwk",
                        parsed.jwk,
                        { name: "ECDH", namedCurve: "P-256" },
                        true,
                        []
                    );
                }

                async function deriveKeyEnvelopeAesKey({ privateKey, publicKey, saltBytes, usage }) {
                    const sharedSecret = await crypto.subtle.deriveBits(
                        { name: "ECDH", public: publicKey },
                        privateKey,
                        256
                    );
                    const hkdfBase = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
                    return crypto.subtle.deriveKey(
                        {
                            name: "HKDF",
                            hash: "SHA-256",
                            salt: saltBytes,
                            info: utf8Bytes("SecureData Archive key envelope v2")
                        },
                        hkdfBase,
                        { name: "AES-GCM", length: 256 },
                        false,
                        [usage]
                    );
                }

			    async function rsaEncryptForStoredPublicKey(publicKey, plaintext) {
			        const parsed = parseStoredPublicKey(publicKey);
                    if (parsed.kind === "ecdh-p256") {
                        const recipientPublicKey = await importStoredEcdhPublicKey(publicKey);
                        const ephemeral = await crypto.subtle.generateKey(
                            { name: "ECDH", namedCurve: "P-256" },
                            true,
                            ["deriveBits"]
                        );
                        const epk = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
                        delete epk.d;
                        epk.key_ops = [];
                        epk.ext = true;
                        const salt = randomBytes(32);
                        const iv = randomBytes(12);
                        const aad = {
                            type: "securedata.key-envelope",
                            version: 2,
                            alg: KEY_ENVELOPE_V2_ALG,
                            recipientFingerprint: await computePublicKeyFingerprint(publicKey)
                        };
                        const wrapKey = await deriveKeyEnvelopeAesKey({
                            privateKey: ephemeral.privateKey,
                            publicKey: recipientPublicKey,
                            saltBytes: salt,
                            usage: "encrypt"
                        });
                        const ciphertext = await crypto.subtle.encrypt(
                            {
                                name: "AES-GCM",
                                iv,
                                additionalData: utf8Bytes(stableStringify(aad))
                            },
                            wrapKey,
                            utf8Bytes(String(plaintext || ""))
                        );
                        const envelope = {
                            type: "securedata.key-envelope",
                            version: 2,
                            alg: KEY_ENVELOPE_V2_ALG,
                            epk,
                            saltB64: _bytesToBase64(salt),
                            ivB64: _bytesToBase64(iv),
                            aad,
                            ciphertextB64: _bytesToBase64(new Uint8Array(ciphertext))
                        };
                        return LOCAL_KEY_ENVELOPE_V2_PREFIX + jsonToB64(envelope);
                    }
			        if (parsed.kind === "webcrypto") {
			            const cryptoKey = await importStoredWebCryptoPublicKey(publicKey);
			            const ciphertext = await crypto.subtle.encrypt(
		                { name: "RSA-OAEP" },
		                cryptoKey,
		                new TextEncoder().encode(String(plaintext || ""))
		            );
		            return LOCAL_KEY_OAEP_CIPHERTEXT_PREFIX + _bytesToBase64(new Uint8Array(ciphertext));
		        }
		        const encryptor = new JSEncrypt();
		        encryptor.setPublicKey(parsed.pem || publicKey);
		        const encrypted = encryptor.encrypt(String(plaintext || ""));
			        if (!encrypted) throw new Error("Legacy RSA encryption of content key failed.");
		        return encrypted;
		    }

			    async function rsaDecryptCiphertext(ciphertext) {
			        const parsed = parseEncryptedKeyCiphertext(ciphertext);
                    if (parsed.kind === "key-envelope-v2") {
                        if (!(myPrivateKey instanceof CryptoKey)) {
                            throw new Error("LOCAL_KEY_ALGORITHM_MISMATCH");
                        }
                        const envelope = b64ToJson(parsed.payload);
                        if (!envelope || envelope.version !== 2 || envelope.alg !== KEY_ENVELOPE_V2_ALG || !envelope.epk) {
                            throw new Error("KEY_ENVELOPE_UNSUPPORTED");
                        }
                        const ephemeralPublicKey = await crypto.subtle.importKey(
                            "jwk",
                            envelope.epk,
                            { name: "ECDH", namedCurve: "P-256" },
                            true,
                            []
                        );
                        const wrapKey = await deriveKeyEnvelopeAesKey({
                            privateKey: myPrivateKey,
                            publicKey: ephemeralPublicKey,
                            saltBytes: _base64ToBytes(envelope.saltB64 || ""),
                            usage: "decrypt"
                        });
                        const plaintext = await crypto.subtle.decrypt(
                            {
                                name: "AES-GCM",
                                iv: _base64ToBytes(envelope.ivB64 || ""),
                                additionalData: utf8Bytes(stableStringify(envelope.aad || {}))
                            },
                            wrapKey,
                            _base64ToBytes(envelope.ciphertextB64 || "")
                        );
                        return utf8FromBytes(new Uint8Array(plaintext));
                    }
			        if (parsed.kind === "webcrypto") {
			            if (!(myPrivateKey instanceof CryptoKey)) {
			                throw new Error("LOCAL_KEY_ALGORITHM_MISMATCH");
		            }
		            const plaintext = await crypto.subtle.decrypt(
		                { name: "RSA-OAEP" },
		                myPrivateKey,
		                _base64ToBytes(parsed.payload)
		            );
		            return new TextDecoder().decode(plaintext);
		        }
		        if (!myPrivateKey || (myPrivateKey instanceof CryptoKey)) {
		            throw new Error("LOCAL_KEY_ALGORITHM_MISMATCH");
		        }
		        const decryptor = new JSEncrypt();
		        decryptor.setPrivateKey(myPrivateKey);
		        const plain = decryptor.decrypt(parsed.payload);
			        if (!plain) throw new Error("Legacy RSA decrypt failed");
		        return plain;
		    }

		    async function saveProtectedLegacyBrowserRsaPair(publicKey, privateKey, fingerprint = "") {
		        const protectedKey = await _protectLegacyPrivateKey(privateKey);
		        const nextFingerprint = fingerprint || await computePublicKeyFingerprint(publicKey);
		        await writeProtectedLocalKeyRecord({
		            version: 3,
		            kind: "legacy-protected",
		            publicKey,
		            fingerprint: nextFingerprint,
		            privateEnvelope: protectedKey.envelope,
		            protectorKey: protectedKey.protectorKey
		        });
		        myPublicKey = publicKey;
		        myPrivateKey = privateKey;
		        myKeyFingerprint = nextFingerprint;
		    }

			    async function saveWebCryptoBrowserRsaPair(publicKey, privateKey, fingerprint = "") {
			        const nextFingerprint = fingerprint || await computePublicKeyFingerprint(publicKey);
			        await writeProtectedLocalKeyRecord({
			            version: 4,
			            kind: "webcrypto",
                        algorithm: "RSA-OAEP-2048/SHA-256",
			            publicKey,
			            fingerprint: nextFingerprint,
			            privateKey
			        });
			        myPublicKey = publicKey;
			        myPrivateKey = privateKey;
			        myKeyFingerprint = nextFingerprint;
			    }

                async function saveBrowserDataEncryptionKeyPair(publicKey, privateKey, fingerprint = "", privateJwkB64 = "") {
                    const nextFingerprint = fingerprint || await computePublicKeyFingerprint(publicKey);
                    await writeProtectedLocalKeyRecord({
                        version: 5,
                        kind: "ecdh-p256",
                        algorithm: KEY_ENVELOPE_V2_ALG,
                        publicKey,
                        fingerprint: nextFingerprint,
                        privateKey,
                        privateJwkB64
                    });
                    myPublicKey = publicKey;
                    myPrivateKey = privateKey;
                    myKeyFingerprint = nextFingerprint;
                }

        async function migrateLegacyBrowserRsaPair() {
            clearBrowserRsaEnvelope();
            clearLegacyBrowserRsaPair();
            return false;
        }

        async function resetLocalKeyStateForProfile() {
            await deleteProtectedLocalKeyRecord().catch(() => {});
            await deleteLocalStoreRecord(recoveryEscrowRecordId()).catch(() => {});
            await deleteLocalStoreRecord(recoveryDeviceEscrowRecordId()).catch(() => {});
            await deleteLocalStoreRecord(recoveryDeviceEscrowKeyRecordId()).catch(() => {});
            clearBrowserRsaEnvelope();
            clearLegacyBrowserRsaPair();
            try { localStorage.removeItem(localUnlockRecordKey()); } catch {}
            LOCAL_KEY_UNLOCKED = false;
            myPublicKey = null;
            myPrivateKey = null;
            myKeyFingerprint = "";
            RECOVERY_EXPORT_CACHE = { dataEncryption: null, fabricSigning: null, createdAt: "" };
            return true;
        }

		    async function loadBrowserRsaPair() {
		        const protectedRecord = await readProtectedLocalKeyRecord().catch(() => null);
		        if (protectedRecord && protectedRecord.publicKey) {
		            myPublicKey = protectedRecord.publicKey || null;
		            myKeyFingerprint = protectedRecord.fingerprint || "";
                        if (protectedRecord.kind === "ecdh-p256") {
                            let privateKey = protectedRecord.privateKey instanceof CryptoKey ? protectedRecord.privateKey : null;
                            const privateJwkB64 = protectedRecord.privateJwkB64 || "";
                            if (!privateKey && privateJwkB64) {
                                privateKey = await crypto.subtle.importKey(
                                    "jwk",
                                    b64ToJson(privateJwkB64),
                                    { name: "ECDH", namedCurve: "P-256" },
                                    false,
                                    ["deriveBits"]
                                ).catch(() => null);
                                if (privateKey) {
                                    await writeProtectedLocalKeyRecord({
                                        version: 5,
                                        kind: "ecdh-p256",
                                        algorithm: KEY_ENVELOPE_V2_ALG,
                                        publicKey: protectedRecord.publicKey,
                                        fingerprint: protectedRecord.fingerprint || "",
                                        privateKey,
                                        privateJwkB64
                                    });
                                }
                            }
                            myPrivateKey = privateKey;
	                    } else if (protectedRecord.kind === "webcrypto") {
	                        let privateKey = protectedRecord.privateKey instanceof CryptoKey ? protectedRecord.privateKey : null;
                        const privatePkcs8B64 = protectedRecord.privatePkcs8B64 || "";
                        if (!privateKey && privatePkcs8B64) {
                            privateKey = await crypto.subtle.importKey(
                                "pkcs8",
                                _base64ToBytes(privatePkcs8B64),
                                {
                                    name: "RSA-OAEP",
                                    hash: "SHA-256"
                                },
                                false,
                                ["decrypt"]
                            ).catch(() => null);
                            if (privateKey) {
                              await writeProtectedLocalKeyRecord({
                                version: 4,
                                kind: "webcrypto",
                                publicKey: protectedRecord.publicKey,
                                fingerprint: protectedRecord.fingerprint || "",
                                privateKey,
                                privatePkcs8B64
                              });
                            }
                        }
		                myPrivateKey = privateKey;
                    } else {
                        myPrivateKey = null;
                    }
		            return protectedRecord;
		        }
		        myPrivateKey = null;
            myPublicKey = null;
            myKeyFingerprint = "";
            return null;
		    }

        function fabricIdentityRecordId() {
            return `${browserRsaKeyBase("securedataFabricIdentityV1")}:fabric`;
        }

        function recoveryEscrowRecordId() {
            return `${browserRsaKeyBase("securedataRecoveryEscrowV1")}:escrow`;
        }

        function recoveryDeviceEscrowKeyRecordId() {
            return `${browserRsaKeyBase("securedataRecoveryDeviceEscrowKeyV1")}:key`;
        }

        function recoveryDeviceEscrowRecordId() {
            return `${browserRsaKeyBase("securedataRecoveryDeviceEscrowV1")}:escrow`;
        }

        async function readLocalStoreRecord(recordId) {
            let db = null;
            try {
                db = await openLocalKeyDb();
                return await new Promise((resolve, reject) => {
                    const tx = db.transaction(LOCAL_KEY_STORE, "readonly");
                    const store = tx.objectStore(LOCAL_KEY_STORE);
                    const req = store.get(recordId);
                    req.onsuccess = () => resolve(req.result || null);
                    req.onerror = () => reject(req.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                    tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                });
            } finally {
                try { if (db) db.close(); } catch {}
            }
        }

        async function writeLocalStoreRecord(recordId, value) {
            let db = null;
            try {
                db = await openLocalKeyDb();
                return await new Promise((resolve, reject) => {
                    const tx = db.transaction(LOCAL_KEY_STORE, "readwrite");
                    const store = tx.objectStore(LOCAL_KEY_STORE);
                    store.put(Object.assign({}, value, { id: recordId }));
                    tx.oncomplete = () => resolve(true);
                    tx.onerror = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                    tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                });
            } finally {
                try { if (db) db.close(); } catch {}
            }
        }

        async function deleteLocalStoreRecord(recordId) {
            let db = null;
            try {
                db = await openLocalKeyDb();
                return await new Promise((resolve, reject) => {
                    const tx = db.transaction(LOCAL_KEY_STORE, "readwrite");
                    const store = tx.objectStore(LOCAL_KEY_STORE);
                    store.delete(recordId);
                    tx.oncomplete = () => resolve(true);
                    tx.onerror = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                    tx.onabort = () => reject(tx.error || new Error("LOCAL_KEY_STORE_UNAVAILABLE"));
                });
            } finally {
                try { if (db) db.close(); } catch {}
            }
        }

        async function loadFabricIdentityRecord() {
            const rec = await readLocalStoreRecord(fabricIdentityRecordId()).catch(() => null);
            let privateKey = rec && rec.privateKey instanceof CryptoKey ? rec.privateKey : null;
            const legacyPkcs8 = rec && rec.privatePkcs8B64 ? rec.privatePkcs8B64 : "";
            if (!privateKey && legacyPkcs8) {
                privateKey = await crypto.subtle.importKey(
                  "pkcs8",
                  _base64ToBytes(legacyPkcs8),
                  { name: "ECDSA", namedCurve: "P-256" },
                  false,
                  ["sign"]
                ).catch(() => null);
                if (privateKey) {
                  await writeLocalStoreRecord(fabricIdentityRecordId(), {
                    privateKey,
                    publicSpkiB64: rec && rec.publicSpkiB64 ? rec.publicSpkiB64 : "",
                    certificatePem: rec && rec.certificatePem ? rec.certificatePem : "",
                    userHandle: rec && rec.userHandle ? rec.userHandle : "",
                    privatePkcs8B64: legacyPkcs8,
                  });
                }
            }
            FABRIC_IDENTITY = {
                privateKey,
                publicSpkiB64: rec && rec.publicSpkiB64 ? rec.publicSpkiB64 : "",
                certificatePem: rec && rec.certificatePem ? rec.certificatePem : "",
                userHandle: rec && rec.userHandle ? rec.userHandle : "",
            };
            return FABRIC_IDENTITY;
        }

        async function saveFabricIdentityRecord(partial = {}) {
            const next = Object.assign({}, FABRIC_IDENTITY || {}, partial || {});
            let privateKey = next.privateKey instanceof CryptoKey ? next.privateKey : null;
            const privatePkcs8B64 = next.privatePkcs8B64 || "";
            if (!privateKey && privatePkcs8B64) {
                privateKey = await crypto.subtle.importKey(
                  "pkcs8",
                  _base64ToBytes(privatePkcs8B64),
                  { name: "ECDSA", namedCurve: "P-256" },
                  false,
                  ["sign"]
                ).catch(() => null);
            }
            FABRIC_IDENTITY = {
                privateKey,
                publicSpkiB64: next.publicSpkiB64 || "",
                certificatePem: next.certificatePem || "",
                userHandle: next.userHandle || "",
            };
            await writeLocalStoreRecord(fabricIdentityRecordId(), {
                privateKey: FABRIC_IDENTITY.privateKey,
                publicSpkiB64: FABRIC_IDENTITY.publicSpkiB64,
                certificatePem: FABRIC_IDENTITY.certificatePem,
                userHandle: FABRIC_IDENTITY.userHandle,
            });
            return FABRIC_IDENTITY;
        }

        async function generateFabricSigningKeyPair() {
            const keyPair = await crypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["sign", "verify"]
            );
            const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
            const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
            const workingPrivateKey = await crypto.subtle.importKey(
              "pkcs8",
              pkcs8,
              { name: "ECDSA", namedCurve: "P-256" },
              false,
              ["sign"]
            );
            RECOVERY_EXPORT_CACHE.fabricSigning = {
              algorithm: "ECDSA-P256",
              privatePkcs8B64: _bytesToBase64(new Uint8Array(pkcs8)),
              publicSpkiB64: _bytesToBase64(new Uint8Array(spki)),
            };
            RECOVERY_EXPORT_CACHE.createdAt = new Date().toISOString();
            await saveFabricIdentityRecord({
                privateKey: workingPrivateKey,
                publicSpkiB64: _bytesToBase64(new Uint8Array(spki))
            });
            await _refreshDeviceRecoveryEscrowFromState().catch(() => false);
            return FABRIC_IDENTITY;
        }

        async function ensureFabricIdentityReady({ allowCreate = false } = {}) {
            const current = await loadFabricIdentityRecord();
            if (current.privateKey) return current;
            if (!allowCreate) throw new Error("LOCAL_FABRIC_KEY_MISSING");
            return generateFabricSigningKeyPair();
        }

        async function setFabricCertificatePem(certPem, userHandle = "") {
            await saveFabricIdentityRecord({
                certificatePem: String(certPem || "").trim(),
                userHandle: String(userHandle || FABRIC_IDENTITY.userHandle || "").trim()
            });
            await _refreshDeviceRecoveryEscrowFromState().catch(() => false);
            return FABRIC_IDENTITY;
        }

        async function signFabricPayloadB64(payloadB64) {
            const current = await ensureFabricIdentityReady({ allowCreate: false });
            if (!(current.privateKey instanceof CryptoKey)) {
                throw new Error("LOCAL_FABRIC_KEY_MISSING");
            }
            const payload = _base64ToBytes(payloadB64);
            const sig = await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                current.privateKey,
                payload
            );
            return _bytesToBase64(_derEcdsaSignature(new Uint8Array(sig)));
        }

        function _derLen(len) {
            if (len < 128) return [len];
            const bytes = [];
            let n = len;
            while (n > 0) {
                bytes.unshift(n & 0xff);
                n >>= 8;
            }
            return [0x80 | bytes.length, ...bytes];
        }

        function _derNode(tag, bytes) {
            const body = Array.from(bytes || []);
            return Uint8Array.from([tag, ..._derLen(body.length), ...body]);
        }

        function _derSeq(items) {
            const body = [];
            for (const item of items) body.push(...Array.from(item || []));
            return _derNode(0x30, body);
        }

        function _derSet(items) {
            const body = [];
            for (const item of items) body.push(...Array.from(item || []));
            return _derNode(0x31, body);
        }

        function _derInt(n) {
            const bytes = [];
            let value = n;
            do {
                bytes.unshift(value & 0xff);
                value >>= 8;
            } while (value > 0);
            if (bytes[0] & 0x80) bytes.unshift(0x00);
            return _derNode(0x02, bytes);
        }

        function _derIntBytes(bytes) {
            const raw = Array.from(bytes || []);
            while (raw.length > 1 && raw[0] === 0x00 && !(raw[1] & 0x80)) raw.shift();
            if (!raw.length) raw.push(0x00);
            if (raw[0] & 0x80) raw.unshift(0x00);
            return _derNode(0x02, raw);
        }

        function _derOid(parts) {
            const nums = String(parts || "").split(".").map((v) => Number(v));
            const out = [40 * nums[0] + nums[1]];
            for (let i = 2; i < nums.length; i += 1) {
                let n = nums[i];
                const tmp = [n & 0x7f];
                n >>= 7;
                while (n > 0) {
                    tmp.unshift(0x80 | (n & 0x7f));
                    n >>= 7;
                }
                out.push(...tmp);
            }
            return _derNode(0x06, out);
        }

        function _derUtf8(text) {
            return _derNode(0x0c, new TextEncoder().encode(String(text || "")));
        }

        function _derBitString(bytes) {
            return _derNode(0x03, [0x00, ...Array.from(bytes || [])]);
        }

        function _derContextZero(bytes) {
            return _derNode(0xa0, bytes);
        }

        function _bytesToBigInt(bytes) {
            let value = 0n;
            for (const b of Array.from(bytes || [])) {
                value = (value << 8n) | BigInt(b & 0xff);
            }
            return value;
        }

        function _bigIntToBytes(value, size) {
            let hex = BigInt(value || 0n).toString(16);
            if (hex.length % 2) hex = `0${hex}`;
            const out = [];
            for (let i = 0; i < hex.length; i += 2) {
                out.push(parseInt(hex.slice(i, i + 2), 16));
            }
            while (out.length < size) out.unshift(0);
            if (out.length > size) return out.slice(out.length - size);
            return out;
        }

        function _derEcdsaSignature(bytes) {
            const raw = Uint8Array.from(bytes || []);
            if (!raw.length || raw.length % 2 !== 0) {
                throw new Error("Invalid ECDSA signature length");
            }
            const half = raw.length / 2;
            const r = raw.slice(0, half);
            const curveOrder = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
            const halfOrder = curveOrder >> 1n;
            let sValue = _bytesToBigInt(raw.slice(half));
            if (sValue > halfOrder) {
                sValue = curveOrder - sValue;
            }
            const s = Uint8Array.from(_bigIntToBytes(sValue, half));
            return _derSeq([
                _derIntBytes(r),
                _derIntBytes(s),
            ]);
        }

        function _pemFromDer(label, derBytes) {
            return _formatPem(label, new Uint8Array(derBytes));
        }

        async function buildFabricEnrollmentCsrPem(username, org, identityOverride = null) {
            const current = identityOverride || await ensureFabricIdentityReady({ allowCreate: true });
            if (!(current && current.privateKey instanceof CryptoKey) || !current.publicSpkiB64) {
                throw new Error("LOCAL_FABRIC_KEY_MISSING");
            }
            const publicSpki = _base64ToBytes(current.publicSpkiB64);
            const subject = _derSeq([
                _derSet([_derSeq([_derOid("2.5.4.3"), _derUtf8(username)])]),
                _derSet([_derSeq([_derOid("2.5.4.10"), _derUtf8(String(org || "org1").toUpperCase())])]),
            ]);
            const cri = _derSeq([
                _derInt(0),
                subject,
                publicSpki,
                _derContextZero([]),
            ]);
            const signature = await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                current.privateKey,
                cri
            );
            const algorithm = _derSeq([
                _derOid("1.2.840.10045.4.3.2"),
            ]);
            const csr = _derSeq([
                cri,
                algorithm,
                _derBitString(_derEcdsaSignature(new Uint8Array(signature))),
            ]);
            return _pemFromDer("CERTIFICATE REQUEST", csr);
        }

        function _hexToBytes(hex) {
            const raw = String(hex || "").trim();
            if (!raw || raw.length % 2 !== 0) throw new Error("RECOVERY_BUNDLE_INVALID");
            const out = new Uint8Array(raw.length / 2);
            for (let i = 0; i < raw.length; i += 2) {
                out[i / 2] = parseInt(raw.slice(i, i + 2), 16);
            }
            return out;
        }
