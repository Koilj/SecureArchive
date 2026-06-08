        function _argon2HashBytesFromResult(result) {
            const raw = result && (result.hash || result.result || result.hashHex || result.encoded);
            if (raw instanceof Uint8Array) return raw;
            if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
            if (typeof raw === "string" && /^[0-9a-f]+$/i.test(raw)) return _hexToBytes(raw);
            if (Array.isArray(raw)) return Uint8Array.from(raw);
            throw new Error("RECOVERY_BUNDLE_INVALID");
        }

        async function _deriveRecoveryKeyBytes(passphrase, saltBytes) {
            await waitForArgon2Ready(ARGON2_TIMEOUT_MS);
            const result = await withTimeout(window.argon2.hash({
                pass: String(passphrase || ""),
                salt: Uint8Array.from(saltBytes || []),
                time: RECOVERY_ARGON2_TIME,
                mem: RECOVERY_ARGON2_MEM_KIB,
                hashLen: RECOVERY_ARGON2_HASH_LEN,
                parallelism: RECOVERY_ARGON2_PARALLELISM,
                type: window.argon2.ArgonType.Argon2id
            }), ARGON2_TIMEOUT_MS, "ARGON2_TIMEOUT");
            return _argon2HashBytesFromResult(result);
        }

        async function _refreshAuthSessionState() {
            try {
                const res = await authFetch(`${API_URL}/auth/session`);
                const data = await res.json().catch(() => null);
                if (res.ok && data && data.ok && data.session) {
                    const nextSession = data.session;
                    if (AUTH_SESSION && AUTH_SESSION.recovery_bundle_created && !nextSession.recovery_bundle_created) {
                        nextSession.recovery_bundle_required = true;
                        nextSession.recovery_bundle_created = true;
                        nextSession.recovery_bundle_created_at = AUTH_SESSION.recovery_bundle_created_at || nextSession.recovery_bundle_created_at || "";
                    }
                    setAuthSession(nextSession);
                    applyAuthSession();
                    return AUTH_SESSION;
                }
            } catch {}
            return AUTH_SESSION;
        }

        async function _promptRecoveryPassphrase({ confirm = true } = {}) {
            while (true) {
                const first = await uiPrompt({
                    title: "Recovery passphrase",
                    label: "Set a separate recovery passphrase",
                    placeholder: "At least 12 characters",
                    value: "",
                    inputType: "password",
                    okText: "Continue",
                    cancelText: "Cancel"
                });
                if (first === null) throw new Error("RECOVERY_BUNDLE_CANCELLED");
                if (String(first || "").length < 12) {
                    await uiAlert({ title: "Recovery bundle", body: "Use a recovery passphrase with at least 12 characters.", tone: "warning" });
                    continue;
                }
                if (!confirm) return String(first);
                const second = await uiPrompt({
                    title: "Confirm recovery passphrase",
                    label: "Enter the same passphrase again",
                    placeholder: "Repeat the passphrase",
                    value: "",
                    inputType: "password",
                    okText: "Create bundle",
                    cancelText: "Cancel"
                });
                if (second === null) throw new Error("RECOVERY_BUNDLE_CANCELLED");
                if (String(first) !== String(second)) {
                    await uiAlert({ title: "Recovery bundle", body: "The passphrases do not match. Try again.", tone: "warning" });
                    continue;
                }
                return String(first);
            }
        }

        async function _encryptRecoveryPayload(payload, passphrase, format = RECOVERY_BUNDLE_FORMAT) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const aad = {
                format,
                version: RECOVERY_BUNDLE_VERSION,
                username: payload.username || "",
                createdAt: payload.createdAt || new Date().toISOString()
            };
            const keyBytes = await _deriveRecoveryKeyBytes(passphrase, salt);
            const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
            const ciphertext = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv,
                    additionalData: new TextEncoder().encode(JSON.stringify(aad))
                },
                aesKey,
                new TextEncoder().encode(JSON.stringify(payload))
            );
            return {
                format,
                version: RECOVERY_BUNDLE_VERSION,
                createdAt: payload.createdAt,
                username: payload.username,
                org: payload.org,
                mspId: payload.mspId,
                kdf: {
                    name: "Argon2id",
                    timeCost: RECOVERY_ARGON2_TIME,
                    memoryKiB: RECOVERY_ARGON2_MEM_KIB,
                    parallelism: RECOVERY_ARGON2_PARALLELISM,
                    hashLen: RECOVERY_ARGON2_HASH_LEN,
                    saltB64: _bytesToBase64(salt)
                },
                cipher: {
                    name: "AES-256-GCM",
                    ivB64: _bytesToBase64(iv)
                },
                aad,
                ciphertextB64: _bytesToBase64(new Uint8Array(ciphertext))
            };
        }

        async function _decryptRecoveryPayload(bundle, passphrase, expectedFormat = RECOVERY_BUNDLE_FORMAT) {
            if (!bundle || bundle.format !== expectedFormat || !bundle.kdf || !bundle.cipher || !bundle.ciphertextB64) {
                throw new Error("RECOVERY_BUNDLE_INVALID");
            }
            const salt = _base64ToBytes(bundle.kdf.saltB64 || "");
            const iv = _base64ToBytes(bundle.cipher.ivB64 || "");
            const keyBytes = await _deriveRecoveryKeyBytes(passphrase, salt);
            const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
            let plaintext;
            try {
                plaintext = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv,
                        additionalData: new TextEncoder().encode(JSON.stringify(bundle.aad || {}))
                    },
                    aesKey,
                    _base64ToBytes(bundle.ciphertextB64 || "")
                );
            } catch {
                throw new Error("RECOVERY_BUNDLE_INVALID");
            }
            const payload = JSON.parse(new TextDecoder().decode(plaintext));
            if (!payload || payload.format !== RECOVERY_BUNDLE_FORMAT || !payload.identities) {
                throw new Error("RECOVERY_BUNDLE_INVALID");
            }
            return payload;
        }

        async function _storeLocalRecoveryEscrow(payload, passphrase) {
            const escrow = await _encryptRecoveryPayload(payload, passphrase, RECOVERY_ESCROW_FORMAT);
            await writeLocalStoreRecord(recoveryEscrowRecordId(), escrow);
            return escrow;
        }

        async function _loadLocalRecoveryEscrow(passphrase) {
            const escrow = await readLocalStoreRecord(recoveryEscrowRecordId()).catch(() => null);
            if (!escrow) return null;
            return _decryptRecoveryPayload(escrow, passphrase, RECOVERY_ESCROW_FORMAT);
        }

        async function _loadRecoveryDeviceEscrowKey({ create = false } = {}) {
            const rec = await readLocalStoreRecord(recoveryDeviceEscrowKeyRecordId()).catch(() => null);
            if (rec && rec.key instanceof CryptoKey) {
                return rec.key;
            }
            if (!create) return null;
            const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
            await writeLocalStoreRecord(recoveryDeviceEscrowKeyRecordId(), {
                key,
                createdAt: new Date().toISOString()
            });
            return key;
        }

        async function _storeDeviceRecoveryEscrow(payload) {
            const encIdentity = (payload && payload.identities && payload.identities.dataEncryption) || {};
            const fabricIdentity = (payload && payload.identities && payload.identities.fabricSigning) || {};
            if (!(encIdentity.privatePkcs8B64 || encIdentity.privateJwkB64) || !fabricIdentity.privatePkcs8B64) {
                return false;
            }
            const key = await _loadRecoveryDeviceEscrowKey({ create: true });
            const createdAt = (payload && payload.createdAt) ? payload.createdAt : new Date().toISOString();
            const aad = {
                format: RECOVERY_DEVICE_ESCROW_FORMAT,
                version: RECOVERY_BUNDLE_VERSION,
                username: (payload && payload.username) ? payload.username : "",
                createdAt
            };
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv,
                    additionalData: new TextEncoder().encode(JSON.stringify(aad))
                },
                key,
                new TextEncoder().encode(JSON.stringify(payload))
            );
            await writeLocalStoreRecord(recoveryDeviceEscrowRecordId(), {
                format: RECOVERY_DEVICE_ESCROW_FORMAT,
                version: RECOVERY_BUNDLE_VERSION,
                createdAt,
                aad,
                cipher: {
                    name: "AES-256-GCM",
                    ivB64: _bytesToBase64(iv)
                },
                ciphertextB64: _bytesToBase64(new Uint8Array(ciphertext))
            });
            return true;
        }

        async function _loadDeviceRecoveryEscrow() {
            const escrow = await readLocalStoreRecord(recoveryDeviceEscrowRecordId()).catch(() => null);
            if (!escrow || escrow.format !== RECOVERY_DEVICE_ESCROW_FORMAT || !escrow.cipher || !escrow.cipher.ivB64 || !escrow.ciphertextB64) {
                return null;
            }
            const key = await _loadRecoveryDeviceEscrowKey({ create: false });
            if (!(key instanceof CryptoKey)) return null;
            try {
                const plaintext = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: _base64ToBytes(escrow.cipher.ivB64 || ""),
                        additionalData: new TextEncoder().encode(JSON.stringify(escrow.aad || {}))
                    },
                    key,
                    _base64ToBytes(escrow.ciphertextB64 || "")
                );
                const payload = JSON.parse(new TextDecoder().decode(plaintext));
                if (!payload || payload.format !== RECOVERY_BUNDLE_FORMAT || !payload.identities) {
                    return null;
                }
                return payload;
            } catch {
                return null;
            }
        }

	        async function _exportPrivateKeyPkcs8B64(privateKey) {
	            if (!(privateKey instanceof CryptoKey)) return "";
	            try {
	                const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
	                return _bytesToBase64(new Uint8Array(pkcs8));
	            } catch {
	                return "";
	            }
        }

        function _hasDataEncryptionPrivateMaterial(identity = {}) {
            return !!String((identity && (identity.privateJwkB64 || identity.privatePkcs8B64)) || "").trim();
        }

        async function _buildRecoveryBundlePayloadFromMaterial(material = {}, fabric = null) {
            const nextFabric = fabric || await ensureFabricIdentityReady({ allowCreate: false });
            const encIdentity = material.dataEncryption || {};
            const fabricIdentity = material.fabricSigning || {};
            const publicKey = String(encIdentity.publicKey || myPublicKey || "").trim();
            const fingerprint = String(encIdentity.fingerprint || myKeyFingerprint || "").trim()
                || (publicKey ? await computePublicKeyFingerprint(publicKey) : "");
            return {
                format: RECOVERY_BUNDLE_FORMAT,
                version: RECOVERY_BUNDLE_VERSION,
                createdAt: new Date().toISOString(),
                username: (AUTH_SESSION && AUTH_SESSION.username) || CURRENT_USER || "",
                org: (AUTH_SESSION && AUTH_SESSION.org) || "",
                mspId: (AUTH_SESSION && AUTH_SESSION.msp_id) || (IDENTITY && IDENTITY.mspID) || "",
                identities: {
                    webauthn: {
                        note: "WebAuthn passkeys are intentionally not included in the recovery bundle."
                    },
                    fabricSigning: {
                        algorithm: String(fabricIdentity.algorithm || "ECDSA-P256"),
                        publicSpkiB64: String(fabricIdentity.publicSpkiB64 || nextFabric.publicSpkiB64 || "").trim(),
                        privatePkcs8B64: String(fabricIdentity.privatePkcs8B64 || "").trim(),
                        certificatePem: String(fabricIdentity.certificatePem || nextFabric.certificatePem || "").trim()
                    },
	                    dataEncryption: {
	                        algorithm: String(encIdentity.algorithm || KEY_ENVELOPE_V2_ALG),
	                        publicKey,
	                        fingerprint,
	                        privateJwkB64: String(encIdentity.privateJwkB64 || "").trim(),
	                        privatePkcs8B64: String(encIdentity.privatePkcs8B64 || "").trim()
	                    }
                }
            };
        }

        async function _loadStoredRecoveryMaterialFromLocalRecords() {
            const protectedRecord = await readProtectedLocalKeyRecord().catch(() => null);
            const fabricRecord = await readLocalStoreRecord(fabricIdentityRecordId()).catch(() => null);
	            const dataPrivatePkcs8B64 = String((protectedRecord && protectedRecord.privatePkcs8B64) || "").trim();
                const dataPrivateJwkB64 = String((protectedRecord && protectedRecord.privateJwkB64) || "").trim();
	            const fabricPrivatePkcs8B64 = String((fabricRecord && fabricRecord.privatePkcs8B64) || "").trim();
            if (!protectedRecord && !fabricRecord) {
                return null;
            }
            return {
	                dataEncryption: {
	                    algorithm: String((protectedRecord && protectedRecord.algorithm) || (protectedRecord && protectedRecord.kind === "ecdh-p256" ? KEY_ENVELOPE_V2_ALG : "RSA-OAEP-2048/SHA-256")),
	                    publicKey: String((protectedRecord && protectedRecord.publicKey) || myPublicKey || "").trim(),
	                    fingerprint: String((protectedRecord && protectedRecord.fingerprint) || myKeyFingerprint || "").trim(),
                        privateJwkB64: dataPrivateJwkB64,
	                    privatePkcs8B64: dataPrivatePkcs8B64
	                },
                fabricSigning: {
                    algorithm: "ECDSA-P256",
                    publicSpkiB64: String((fabricRecord && fabricRecord.publicSpkiB64) || (FABRIC_IDENTITY && FABRIC_IDENTITY.publicSpkiB64) || "").trim(),
                    privatePkcs8B64: fabricPrivatePkcs8B64,
                    certificatePem: String((fabricRecord && fabricRecord.certificatePem) || (FABRIC_IDENTITY && FABRIC_IDENTITY.certificatePem) || "").trim()
                }
            };
        }

        async function _captureRecoveryBundlePayloadFromState() {
            const fabric = await ensureFabricIdentityReady({ allowCreate: false });
            const storedMaterial = await _loadStoredRecoveryMaterialFromLocalRecords().catch(() => null);
                const dataPrivateJwkB64 =
                    String((RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.dataEncryption && RECOVERY_EXPORT_CACHE.dataEncryption.privateJwkB64) || "").trim()
                    || String((storedMaterial && storedMaterial.dataEncryption && storedMaterial.dataEncryption.privateJwkB64) || "").trim();
	            const dataPrivatePkcs8B64 =
	                String((RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.dataEncryption && RECOVERY_EXPORT_CACHE.dataEncryption.privatePkcs8B64) || "").trim()
	                || String((storedMaterial && storedMaterial.dataEncryption && storedMaterial.dataEncryption.privatePkcs8B64) || "").trim()
	                || (dataPrivateJwkB64 ? "" : await _exportPrivateKeyPkcs8B64(myPrivateKey));
            const fabricPrivatePkcs8B64 =
                String((RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.fabricSigning && RECOVERY_EXPORT_CACHE.fabricSigning.privatePkcs8B64) || "").trim()
                || String((storedMaterial && storedMaterial.fabricSigning && storedMaterial.fabricSigning.privatePkcs8B64) || "").trim()
                || await _exportPrivateKeyPkcs8B64(fabric.privateKey);
	            if (!(dataPrivateJwkB64 || dataPrivatePkcs8B64) || !fabricPrivatePkcs8B64) {
	                return null;
	            }
            return _buildRecoveryBundlePayloadFromMaterial(
                {
                    dataEncryption: {
	                        algorithm: (RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.dataEncryption && RECOVERY_EXPORT_CACHE.dataEncryption.algorithm) || (storedMaterial && storedMaterial.dataEncryption && storedMaterial.dataEncryption.algorithm) || KEY_ENVELOPE_V2_ALG,
	                        publicKey: (RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.dataEncryption && RECOVERY_EXPORT_CACHE.dataEncryption.publicKey) || (storedMaterial && storedMaterial.dataEncryption && storedMaterial.dataEncryption.publicKey) || myPublicKey || "",
	                        fingerprint: (RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.dataEncryption && RECOVERY_EXPORT_CACHE.dataEncryption.fingerprint) || (storedMaterial && storedMaterial.dataEncryption && storedMaterial.dataEncryption.fingerprint) || myKeyFingerprint || "",
                            privateJwkB64: dataPrivateJwkB64,
	                        privatePkcs8B64: dataPrivatePkcs8B64
	                    },
                    fabricSigning: {
                        algorithm: (RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.fabricSigning && RECOVERY_EXPORT_CACHE.fabricSigning.algorithm) || "ECDSA-P256",
                        publicSpkiB64: (RECOVERY_EXPORT_CACHE && RECOVERY_EXPORT_CACHE.fabricSigning && RECOVERY_EXPORT_CACHE.fabricSigning.publicSpkiB64) || (storedMaterial && storedMaterial.fabricSigning && storedMaterial.fabricSigning.publicSpkiB64) || fabric.publicSpkiB64 || "",
                        privatePkcs8B64: fabricPrivatePkcs8B64,
                        certificatePem: (storedMaterial && storedMaterial.fabricSigning && storedMaterial.fabricSigning.certificatePem) || fabric.certificatePem || ""
                    }
                },
                fabric
            );
        }

        async function _refreshDeviceRecoveryEscrowFromState() {
            const payload = await _captureRecoveryBundlePayloadFromState().catch(() => null);
            if (!payload) return false;
            _primeRecoveryExportCache(payload);
            await _storeDeviceRecoveryEscrow(payload).catch(() => false);
            return true;
        }

        function _primeRecoveryExportCache(payload) {
            const encIdentity = (payload && payload.identities && payload.identities.dataEncryption) || {};
            const fabricIdentity = (payload && payload.identities && payload.identities.fabricSigning) || {};
            RECOVERY_EXPORT_CACHE = {
                createdAt: payload && payload.createdAt ? payload.createdAt : new Date().toISOString(),
                dataEncryption: {
	                    algorithm: String(encIdentity.algorithm || KEY_ENVELOPE_V2_ALG),
	                    publicKey: String(encIdentity.publicKey || "").trim(),
	                    fingerprint: String(encIdentity.fingerprint || "").trim(),
                        privateJwkB64: String(encIdentity.privateJwkB64 || "").trim(),
	                    privatePkcs8B64: String(encIdentity.privatePkcs8B64 || "").trim()
	                },
                fabricSigning: {
                    algorithm: String(fabricIdentity.algorithm || "ECDSA-P256"),
                    publicSpkiB64: String(fabricIdentity.publicSpkiB64 || "").trim(),
                    privatePkcs8B64: String(fabricIdentity.privatePkcs8B64 || "").trim()
                }
            };
        }

        async function _exportRecoveryBundlePayload() {
            await ensureLocalKeyReady({ interactive: true, allowCreate: false });
            const fabric = await ensureFabricIdentityReady({ allowCreate: false });
            if (!(myPrivateKey instanceof CryptoKey) || !myPublicKey) {
                throw new Error("LOCAL_PRIVATE_KEY_MISSING");
            }
            if (!(fabric && fabric.privateKey && fabric.certificatePem)) {
                throw new Error("LOCAL_FABRIC_KEY_MISSING");
            }
	            if (
                    RECOVERY_EXPORT_CACHE
                    && RECOVERY_EXPORT_CACHE.dataEncryption
                    && RECOVERY_EXPORT_CACHE.fabricSigning
                    && _hasDataEncryptionPrivateMaterial(RECOVERY_EXPORT_CACHE.dataEncryption)
                    && RECOVERY_EXPORT_CACHE.fabricSigning.privatePkcs8B64
                ) {
                return _buildRecoveryBundlePayloadFromMaterial(
                    {
                        dataEncryption: RECOVERY_EXPORT_CACHE.dataEncryption || {},
                        fabricSigning: RECOVERY_EXPORT_CACHE.fabricSigning || {}
                    },
                    fabric
                );
            }
            const devicePayload = await _loadDeviceRecoveryEscrow();
            if (devicePayload && devicePayload.identities) {
                const nextPayload = await _buildRecoveryBundlePayloadFromMaterial(
                    {
                        dataEncryption: devicePayload.identities.dataEncryption || {},
                        fabricSigning: devicePayload.identities.fabricSigning || {}
                    },
                    fabric
                );
                _primeRecoveryExportCache(nextPayload);
                await _storeDeviceRecoveryEscrow(nextPayload).catch(() => false);
                return nextPayload;
            }
            const storedMaterial = await _loadStoredRecoveryMaterialFromLocalRecords().catch(() => null);
	            if (
	                storedMaterial
	                && storedMaterial.dataEncryption
	                && storedMaterial.fabricSigning
	                && _hasDataEncryptionPrivateMaterial(storedMaterial.dataEncryption)
	                && storedMaterial.fabricSigning.privatePkcs8B64
	            ) {
                const nextPayload = await _buildRecoveryBundlePayloadFromMaterial(storedMaterial, fabric);
                _primeRecoveryExportCache(nextPayload);
                await _storeDeviceRecoveryEscrow(nextPayload).catch(() => false);
                return nextPayload;
            }
            const livePayload = await _captureRecoveryBundlePayloadFromState().catch(() => null);
	            if (livePayload && livePayload.identities && livePayload.identities.fabricSigning.privatePkcs8B64 && _hasDataEncryptionPrivateMaterial(livePayload.identities.dataEncryption)) {
                _primeRecoveryExportCache(livePayload);
                await _storeDeviceRecoveryEscrow(livePayload).catch(() => false);
                return livePayload;
            }
            throw new Error("RECOVERY_EXPORT_UNAVAILABLE");
        }

        async function _generateRecoveryReissueMaterial() {
	            const dataKeyPair = await crypto.subtle.generateKey(
	                { name: "ECDH", namedCurve: "P-256" },
	                true,
	                ["deriveBits"]
	            );
	            const dataPrivateJwk = await crypto.subtle.exportKey("jwk", dataKeyPair.privateKey);
	            const dataPublicJwk = await crypto.subtle.exportKey("jwk", dataKeyPair.publicKey);
	            const dataWorkingPrivateKey = await crypto.subtle.importKey(
	                "jwk",
	                dataPrivateJwk,
	                { name: "ECDH", namedCurve: "P-256" },
	                false,
	                ["deriveBits"]
	            );
	            const dataPublicKey = formatStoredEcdhPublicKey(dataPublicJwk);
	            const dataFingerprint = await computePublicKeyFingerprint(dataPublicKey);

            const fabricKeyPair = await crypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["sign", "verify"]
            );
            const fabricSpki = await crypto.subtle.exportKey("spki", fabricKeyPair.publicKey);
            const fabricPkcs8 = await crypto.subtle.exportKey("pkcs8", fabricKeyPair.privateKey);
            const fabricWorkingPrivateKey = await crypto.subtle.importKey(
                "pkcs8",
                fabricPkcs8,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            );

            return {
	                dataEncryption: {
	                    algorithm: KEY_ENVELOPE_V2_ALG,
	                    publicKey: dataPublicKey,
	                    fingerprint: dataFingerprint,
	                    privateKey: dataWorkingPrivateKey,
	                    privateJwkB64: jsonToB64(dataPrivateJwk),
	                    privatePkcs8B64: ""
	                },
                fabricSigning: {
                    algorithm: "ECDSA-P256",
                    publicSpkiB64: _bytesToBase64(new Uint8Array(fabricSpki)),
                    privateKey: fabricWorkingPrivateKey,
                    privatePkcs8B64: _bytesToBase64(new Uint8Array(fabricPkcs8))
                }
            };
        }

        async function _tryLegacyRecoveryBundleSelfHeal() {
            if (!(AUTH_SESSION && AUTH_SESSION.username)) {
                throw new Error("RECOVERY_REISSUE_FAILED");
            }
            if (AUTH_SESSION.recovery_bundle_created) {
                throw new Error("RECOVERY_REISSUE_NOT_ALLOWED");
            }
            const username = String(AUTH_SESSION.username || "").trim();
            const org = String((AUTH_SESSION && AUTH_SESSION.org) || "org1").trim() || "org1";
            const currentFabric = await loadFabricIdentityRecord().catch(() => FABRIC_IDENTITY || {});
            const staged = await _generateRecoveryReissueMaterial();
            const csrPem = await buildFabricEnrollmentCsrPem(username, org, {
                privateKey: staged.fabricSigning.privateKey,
                publicSpkiB64: staged.fabricSigning.publicSpkiB64
            });
            const res = await authFetch(`${API_URL}/auth/recovery/reissue-local-identities`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    content_public_key: staged.dataEncryption.publicKey,
                    content_key_fingerprint: staged.dataEncryption.fingerprint,
                    fabric_csr_pem: csrPem
                })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok || !(data && data.ok)) {
                throw new Error((data && (data.error_code || data.error)) ? (data.error_code || data.error) : "RECOVERY_REISSUE_FAILED");
            }
            const certificatePem = String((data && data.fabric_certificate) || "").trim();
            if (!certificatePem) {
                throw new Error("RECOVERY_REISSUE_FAILED");
            }
	            await saveBrowserDataEncryptionKeyPair(
	                staged.dataEncryption.publicKey,
	                staged.dataEncryption.privateKey,
	                staged.dataEncryption.fingerprint,
                    staged.dataEncryption.privateJwkB64
	            );
            await saveFabricIdentityRecord({
                privateKey: staged.fabricSigning.privateKey,
                publicSpkiB64: staged.fabricSigning.publicSpkiB64,
                certificatePem,
                userHandle: String((currentFabric && currentFabric.userHandle) || (FABRIC_IDENTITY && FABRIC_IDENTITY.userHandle) || "").trim()
            });
            const payload = await _buildRecoveryBundlePayloadFromMaterial(
                {
                    dataEncryption: {
	                        algorithm: staged.dataEncryption.algorithm,
	                        publicKey: staged.dataEncryption.publicKey,
	                        fingerprint: staged.dataEncryption.fingerprint,
                            privateJwkB64: staged.dataEncryption.privateJwkB64,
	                        privatePkcs8B64: staged.dataEncryption.privatePkcs8B64
	                    },
                    fabricSigning: {
                        algorithm: staged.fabricSigning.algorithm,
                        publicSpkiB64: staged.fabricSigning.publicSpkiB64,
                        privatePkcs8B64: staged.fabricSigning.privatePkcs8B64,
                        certificatePem
                    }
                },
                {
                    privateKey: staged.fabricSigning.privateKey,
                    publicSpkiB64: staged.fabricSigning.publicSpkiB64,
                    certificatePem,
                    userHandle: String((currentFabric && currentFabric.userHandle) || (FABRIC_IDENTITY && FABRIC_IDENTITY.userHandle) || "").trim()
                }
            );
            _primeRecoveryExportCache(payload);
            await _storeDeviceRecoveryEscrow(payload).catch(() => false);
            if (data && data.session) {
                setAuthSession(data.session);
                try { applyAuthSession(); } catch {}
            }
            await _refreshAuthSessionState().catch(() => AUTH_SESSION);
            try { await refreshIdentity(); } catch {}
            try { loadProfileData(); } catch {}
            renderNotices();
            log("✅ Recovery bundle: local identities safely reissued for this device.");
            return payload;
        }

        function _downloadBlob(filename, blob) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }

        async function createRecoveryBundle(options = {}) {
            const mandatory = !!(options && options.mandatory);
            try {
                await ensureRecentWebAuthnAuth({ reason: "Creating or reissuing a recovery bundle requires a fresh passkey confirmation." });
                const passphrase = await _promptRecoveryPassphrase({ confirm: true });
                let payload;
                try {
                    payload = await _exportRecoveryBundlePayload();
                } catch (err) {
                    if (String((err && err.message) || err || "") !== "RECOVERY_EXPORT_UNAVAILABLE") {
                        throw err;
                    }
                    log("ℹ️ Recovery bundle: local export material missing, trying safe device reissue...");
                    payload = await _tryLegacyRecoveryBundleSelfHeal();
                }
                const bundleFile = await _encryptRecoveryPayload(payload, passphrase, RECOVERY_BUNDLE_FORMAT);
                const filenameBase = (payload.username || "securedata-user").replace(/[^A-Za-z0-9_.-]+/g, "_");
                _downloadBlob(
                    `${filenameBase}.securedata-recovery.json`,
                    new Blob([JSON.stringify(bundleFile, null, 2)], { type: "application/json" })
                );
                await _storeDeviceRecoveryEscrow(payload);
                await _storeLocalRecoveryEscrow(payload, passphrase);
                await agentSubmit("MarkRecoveryBundleCreated", [payload.createdAt, String(RECOVERY_BUNDLE_VERSION), RECOVERY_PROTECTION]);
                if (AUTH_SESSION) {
                    AUTH_SESSION.recovery_bundle_required = true;
                    AUTH_SESSION.recovery_bundle_created = true;
                    AUTH_SESSION.recovery_bundle_created_at = payload.createdAt;
                    try { applyAuthSession(); } catch {}
                }
                await _refreshAuthSessionState();
                try { await refreshIdentity(); } catch {}
                try { loadProfileData(); } catch {}
                renderNotices();
                showToast("Recovery bundle created and downloaded. Store it offline.", "success");
                log("✅ Recovery bundle created and recorded on-ledger.");
                return true;
            } catch (err) {
                if (String((err && err.message) || err || "") === "RECOVERY_BUNDLE_CANCELLED") {
                    if (!mandatory) showToast(localKeyErrorText(err), "warning");
                    return false;
                }
                const msg = localKeyErrorText(err);
                showToast(msg, mandatory ? "danger" : "warning");
                log("⚠️ Recovery bundle: " + msg);
                if (mandatory) throw err;
                return false;
            }
        }

        function triggerRecoveryBundleImport() {
            const input = document.getElementById("recoveryBundleFileInput");
            if (!input) return;
            input.value = "";
            input.click();
        }

        async function restoreFromRecoveryBundleFile(file) {
            try {
                if (!file) throw new Error("RECOVERY_BUNDLE_INVALID");
                const raw = await file.text();
                const bundle = JSON.parse(raw);
                if (!bundle || bundle.format !== RECOVERY_BUNDLE_FORMAT || !bundle.kdf || !bundle.cipher || !bundle.ciphertextB64) throw new Error("RECOVERY_BUNDLE_INVALID");
                const passphrase = await _promptRecoveryPassphrase({ confirm: false });
                const payload = await _decryptRecoveryPayload(bundle, passphrase, RECOVERY_BUNDLE_FORMAT);
                if (AUTH_SESSION && payload.username && payload.username !== AUTH_SESSION.username) {
                    throw new Error("RECOVERY_BUNDLE_INVALID");
                }
                const encIdentity = payload.identities.dataEncryption || {};
                const fabricIdentity = payload.identities.fabricSigning || {};
                const currentPublicKey = String(myPublicKey || "").trim();
                const currentFabricCert = String((FABRIC_IDENTITY && FABRIC_IDENTITY.certificatePem) || "").trim();
                const currentFabricSpki = String((FABRIC_IDENTITY && FABRIC_IDENTITY.publicSpkiB64) || "").trim();
                const restoringSameKeys =
                    currentPublicKey
                    && currentPublicKey === String(encIdentity.publicKey || "").trim()
                    && currentFabricCert === String(fabricIdentity.certificatePem || "").trim()
                    && currentFabricSpki === String(fabricIdentity.publicSpkiB64 || "").trim();
	                let dataPrivateKey = null;
                    if (String(encIdentity.privateJwkB64 || "").trim()) {
                        dataPrivateKey = await crypto.subtle.importKey(
                            "jwk",
                            b64ToJson(encIdentity.privateJwkB64 || ""),
                            { name: "ECDH", namedCurve: "P-256" },
                            false,
                            ["deriveBits"]
                        );
                    } else {
                        dataPrivateKey = await crypto.subtle.importKey(
                            "pkcs8",
                            _base64ToBytes(encIdentity.privatePkcs8B64 || ""),
                            { name: "RSA-OAEP", hash: "SHA-256" },
                            false,
                            ["decrypt"]
                        );
                    }
                const fabricPrivateKey = await crypto.subtle.importKey(
                    "pkcs8",
                    _base64ToBytes(fabricIdentity.privatePkcs8B64 || ""),
                    { name: "ECDSA", namedCurve: "P-256" },
                    false,
                    ["sign"]
                );
                    if (String(encIdentity.privateJwkB64 || "").trim()) {
                        await saveBrowserDataEncryptionKeyPair(
                            String(encIdentity.publicKey || "").trim(),
                            dataPrivateKey,
                            String(encIdentity.fingerprint || "").trim(),
                            String(encIdentity.privateJwkB64 || "").trim()
                        );
                    } else {
	                    await saveWebCryptoBrowserRsaPair(String(encIdentity.publicKey || "").trim(), dataPrivateKey, String(encIdentity.fingerprint || "").trim());
                    }
                await saveFabricIdentityRecord({
                    privateKey: fabricPrivateKey,
                    publicSpkiB64: String(fabricIdentity.publicSpkiB64 || "").trim(),
                    certificatePem: String(fabricIdentity.certificatePem || "").trim(),
                    userHandle: FABRIC_IDENTITY.userHandle || ""
                });
                _primeRecoveryExportCache(payload);
                await _storeDeviceRecoveryEscrow(payload);
                await _storeLocalRecoveryEscrow(payload, passphrase);
                LOCAL_KEY_UNLOCKED = true;
                await loadBrowserRsaPair();
                await loadFabricIdentityRecord();
                try { await refreshIdentity(); } catch {}
                try { await syncBrowserPublicKeyOnLedger(); } catch {}
                try { loadProfileData(); } catch {}
                renderNotices();
                if (restoringSameKeys) {
                    showToast("Recovery bundle verified. This device already had the same local keys.", "success");
                    log("✅ Recovery bundle verified; this device already had matching local keys.");
                } else {
                    showToast("Recovery bundle restored on this device.", "success");
                    log("✅ Recovery bundle restored on this device.");
                }
                return true;
            } catch (err) {
                if (String((err && err.message) || err || "") === "RECOVERY_BUNDLE_CANCELLED") return false;
                const msg = localKeyErrorText(err);
                showToast(msg, "danger");
                log("⚠️ Recovery bundle restore: " + msg);
                return false;
            }
        }

        async function ensureRecoveryBundleForSession({ mandatory = false } = {}) {
            if (!(AUTH_SESSION && AUTH_SESSION.recovery_bundle_required && !AUTH_SESSION.recovery_bundle_created)) return mandatory ? true : false;
            if (mandatory && typeof runMandatoryRecoveryBundleGate === "function") {
                return await runMandatoryRecoveryBundleGate();
            }
            const confirmed = await uiConfirm({
                title: "Create recovery bundle",
                body: "This account is not fully protected until a recovery bundle is created. The bundle contains the device-only data decryption key, the Fabric signing key, and the Fabric certificate encrypted locally with a separate recovery passphrase.",
                okText: "Create now",
                cancelText: mandatory ? "Sign out" : "Later",
                okClass: "btn-primary"
            });
            if (!confirmed) {
                if (mandatory) {
                    await handleLogout();
                    throw new Error("RECOVERY_BUNDLE_REQUIRED");
                }
                return false;
            }
            const created = await createRecoveryBundle({ mandatory });
            if (!created && mandatory) {
                await handleLogout();
                throw new Error("RECOVERY_BUNDLE_REQUIRED");
            }
            return created;
        }

		    async function hasStoredEncryptedPrivateKey() {
		        const protectedRecord = await readProtectedLocalKeyRecord().catch(() => null);
            return !!(protectedRecord && protectedRecord.publicKey);
		    }

    const DEVELOPER_LOG_STORAGE_KEY = "securedataDeveloperLogsV1";
    const DEVELOPER_LOG_LEGACY_KEYS = ["securedataDeveloperLogs", "securedataDevLog"];
    const DEVELOPER_LOG_MAX_ITEMS = 300;
    const DEVELOPER_LOG_GUEST_KEY = "__guest__";

    function developerLogCurrentUsername() {
        return String((AUTH_SESSION && AUTH_SESSION.username) || "").trim();
    }

    function readDeveloperLogs() {
        try {
            const raw = localStorage.getItem(DEVELOPER_LOG_STORAGE_KEY) || "";
            if (!raw) return {};
            const parsed = JSON.parse(raw);
            return (parsed && typeof parsed === "object") ? parsed : {};
        } catch {
            return {};
        }
    }

    function writeDeveloperLogs(state) {
        try {
            if (!state || Object.keys(state).length === 0) {
                localStorage.removeItem(DEVELOPER_LOG_STORAGE_KEY);
                return;
            }
            localStorage.setItem(DEVELOPER_LOG_STORAGE_KEY, JSON.stringify(state));
        } catch {}
    }

    function purgeDeveloperLogLegacyKeys() {
        try {
            DEVELOPER_LOG_LEGACY_KEYS.forEach((k) => localStorage.removeItem(k));
        } catch {}
    }

    function purgeDeveloperLogGuestBucket() {
        const logs = readDeveloperLogs();
        if (logs && Object.prototype.hasOwnProperty.call(logs, DEVELOPER_LOG_GUEST_KEY)) {
            delete logs[DEVELOPER_LOG_GUEST_KEY];
            writeDeveloperLogs(logs);
        }
    }

    function clearCurrentUserDeveloperLog() {
        const username = developerLogCurrentUsername();
        if (!username) return;
        const logs = readDeveloperLogs();
        if (logs && Object.prototype.hasOwnProperty.call(logs, username)) {
            delete logs[username];
            writeDeveloperLogs(logs);
        }
        renderDeveloperLog();
    }

    function renderDeveloperLog() {
        const box = document.getElementById("logBox");
        const hint = document.getElementById("logScopeHint");
        const card = document.getElementById("logCard");
        const username = developerLogCurrentUsername();

        if (!username) {
            // Never show any log content to an unauthenticated viewer, even
            // their own guest-bucket entries - those could have been written
            // by a previous local user. Simply hide the panel.
            if (box) box.textContent = "";
            if (hint) hint.textContent = "Sign in to see your private activity log.";
            if (card) card.classList.add("d-none");
            return;
        }

        if (card) card.classList.remove("d-none");
        const logs = readDeveloperLogs();
        const items = Array.isArray(logs[username]) ? logs[username] : [];
        if (box) {
            box.textContent = items.length ? `${items.join("\n")}\n` : "No entries yet for this account.";
            box.scrollTop = box.scrollHeight;
        }
        if (hint) {
            hint.textContent = `Private to ${username} on this device. History persists across sessions.`;
        }
    }

    function _developerLogInDropWindow() {
        // `_LOG_DROP_UNTIL_MS` is defined in 01-core.js and is refreshed on
        // every auth transition. Any log() call that lands inside that
        // window is most likely an async continuation from the PREVIOUS
        // session - dropping it prevents cross-user leakage.
        try {
            return typeof _LOG_DROP_UNTIL_MS === "number" && Date.now() < _LOG_DROP_UNTIL_MS;
        } catch { return false; }
    }

    function log(msg) {
        const ts = new Date().toISOString();
        const entry = `[${ts}] ${msg}`;
        try { console.log("[securedata]", entry); } catch {}

        const username = developerLogCurrentUsername();
        if (!username) {
            // Do NOT persist anything while signed out - prevents cross-user
            // leakage through a shared "__guest__" bucket.
            return;
        }

        if (_developerLogInDropWindow()) {
            // Recent session transition - skip the write. The entry is
            // still on the browser console for debugging.
            try { console.debug("[securedata][drop-race]", entry); } catch {}
            return;
        }

        const logs = readDeveloperLogs();
        const items = Array.isArray(logs[username]) ? logs[username].slice() : [];
        items.push(entry);
        logs[username] = items.slice(-DEVELOPER_LOG_MAX_ITEMS);
        writeDeveloperLogs(logs);
        renderDeveloperLog();
    }

    // Expose for unit tests (Playwright runs this in a real browser).
    try { window.__devlogTestHooks = { log, readDeveloperLogs, writeDeveloperLogs, renderDeveloperLog }; } catch {}
