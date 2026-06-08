import functools
import http.server
import socketserver
import threading
import unittest
from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "tests" / "recovery_harness.html"


class QuietHttpHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return


class ThreadingHttpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class RecoveryBundleBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(QuietHttpHandler, directory=str(ROOT))
        cls.httpd = ThreadingHttpServer(("127.0.0.1", 0), handler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        assert HARNESS_PATH.exists(), "recovery harness is missing"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server_thread.join(timeout=5)

    def _prime_test_state(self, page):
        page.evaluate(
            """async () => {
                window.__downloads = [];
                window.__logs = [];
                window.__toasts = [];
                AUTH_SESSION = {
                    username: "alice",
                    org: "org1",
                    msp_id: "Org1MSP",
                    recovery_bundle_required: true,
                    recovery_bundle_created: false,
                    webauthn_verified_at: new Date().toISOString()
                };
                window.AUTH_SESSION = AUTH_SESSION;
                IDENTITY = {
                    registered: true,
                    publicKey: "",
                    mspID: "Org1MSP",
                    clientID: "alice-client"
                };
                setActiveProfile("alice");
                applyAuthSession = () => {};
                ensureRecentWebAuthnAuth = async () => true;
                agentSubmit = async () => true;
                refreshIdentity = async () => IDENTITY;
                loadProfileData = () => {};
                renderNotices = () => {};
                showToast = (msg, tone) => { window.__toasts.push({ msg, tone }); };
                log = (msg) => { window.__logs.push(String(msg)); };
                uiAlert = async () => true;
                uiConfirm = async () => true;
                _refreshAuthSessionState = async () => AUTH_SESSION;
                _downloadBlob = (name, blob) => {
                    window.__downloads.push({ name, size: blob.size });
                };
                return true;
            }"""
        )

    def test_bundle_creation_survives_reload_without_memory_cache(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{self.base_url}/tests/recovery_harness.html", wait_until="domcontentloaded")
            page.wait_for_function("() => typeof createRecoveryBundle === 'function'")

            self._prime_test_state(page)
            state = page.evaluate(
                """async () => {
                    await createBrowserRsaKeyPair();
                    await generateFabricSigningKeyPair();
                    await setFabricCertificatePem("-----BEGIN CERTIFICATE-----\\nTEST-CERT\\n-----END CERTIFICATE-----", "alice-handle");
                    const escrow = await readLocalStoreRecord(recoveryDeviceEscrowRecordId());
                    return {
                        rsaReady: !!(await readProtectedLocalKeyRecord()),
                        fabricReady: !!(await readLocalStoreRecord(fabricIdentityRecordId())),
                        escrowReady: !!escrow
                    };
                }"""
            )
            self.assertTrue(state["rsaReady"])
            self.assertTrue(state["fabricReady"])
            self.assertTrue(state["escrowReady"])

            page.reload(wait_until="domcontentloaded")
            page.wait_for_function("() => typeof createRecoveryBundle === 'function'")
            self._prime_test_state(page)
            created = page.evaluate(
                """async () => {
                    uiPrompt = async (opts = {}) => {
                        const title = String(opts.title || "");
                        if (title === "Recovery passphrase" || title === "Confirm recovery passphrase") {
                            return "RecoveryPass!alice";
                        }
                        return null;
                    };
                    await loadBrowserRsaPair();
                    await loadFabricIdentityRecord();
                    return await createRecoveryBundle({ mandatory: true });
                }"""
            )

            self.assertTrue(created)
            downloads = page.evaluate("() => window.__downloads.slice()")
            logs = page.evaluate("() => window.__logs.slice()")
            session = page.evaluate(
                """() => ({
                    created: !!(AUTH_SESSION && AUTH_SESSION.recovery_bundle_created),
                    createdAt: (AUTH_SESSION && AUTH_SESSION.recovery_bundle_created_at) || ""
                })"""
            )

            self.assertEqual(len(downloads), 1)
            self.assertIn("securedata-recovery.json", downloads[0]["name"])
            self.assertTrue(session["created"])
            self.assertTrue(session["createdAt"])
            self.assertTrue(any("Recovery bundle created" in item for item in logs))
            self.assertFalse(any("RECOVERY_EXPORT_UNAVAILABLE" in item for item in logs))

            browser.close()

    def test_agent_submit_refreshes_missing_csrf_before_fabric_post(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{self.base_url}/tests/recovery_harness.html", wait_until="domcontentloaded")
            page.wait_for_function("() => typeof agentSubmit === 'function'")

            result = page.evaluate(
                """async () => {
                    const calls = [];
                    AUTH_SESSION = {
                        username: "alice",
                        org: "org1",
                        msp_id: "Org1MSP",
                        webauthn_verified_at: new Date().toISOString()
                    };
                    window.AUTH_SESSION = AUTH_SESSION;
                    applyAuthSession = () => {};
                    window.fetch = async (url, opts = {}) => {
                        const target = String(url || "");
                        const headers = opts.headers || {};
                        const csrf = headers["X-CSRF-Token"] || headers["x-csrf-token"] || "";
                        calls.push({ url: target, method: String(opts.method || "GET"), csrf });
                        if (target.includes("/auth/session")) {
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({
                                    ok: true,
                                    authenticated: true,
                                    session: {
                                        username: "alice",
                                        org: "org1",
                                        msp_id: "Org1MSP",
                                        csrf_token: "csrf-fresh",
                                        webauthn_verified_at: new Date().toISOString()
                                    }
                                }),
                                text: async () => ""
                            };
                        }
                        if (target.includes("/fabric/submit")) {
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({ ok: true, result: { status: "OK" } }),
                                text: async () => ""
                            };
                        }
                        return {
                            ok: false,
                            status: 404,
                            json: async () => ({ ok: false, error: "not found" }),
                            text: async () => ""
                        };
                    };
                    await agentSubmit("MarkRecoveryBundleCreated", ["2026-04-24T00:00:00Z", "2", "test"], { maxAttempts: 1 });
                    return {
                        calls,
                        csrf: AUTH_SESSION && AUTH_SESSION.csrf_token,
                        windowCsrf: window.AUTH_SESSION && window.AUTH_SESSION.csrf_token
                    };
                }"""
            )

            fabric_calls = [item for item in result["calls"] if "/fabric/submit" in item["url"]]
            self.assertEqual(result["csrf"], "csrf-fresh")
            self.assertEqual(result["windowCsrf"], "csrf-fresh")
            self.assertTrue(any("/auth/session" in item["url"] for item in result["calls"]))
            self.assertEqual(len(fabric_calls), 1)
            self.assertEqual(fabric_calls[0]["csrf"], "csrf-fresh")

            browser.close()

    def test_agent_submit_retries_after_stale_csrf_failure(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{self.base_url}/tests/recovery_harness.html", wait_until="domcontentloaded")
            page.wait_for_function("() => typeof agentSubmit === 'function'")

            result = page.evaluate(
                """async () => {
                    const calls = [];
                    AUTH_SESSION = {
                        username: "alice",
                        org: "org1",
                        msp_id: "Org1MSP",
                        csrf_token: "csrf-stale",
                        webauthn_verified_at: new Date().toISOString()
                    };
                    window.AUTH_SESSION = AUTH_SESSION;
                    applyAuthSession = () => {};
                    const jsonResponse = (payload, status = 200) => new Response(JSON.stringify(payload), {
                        status,
                        headers: { "Content-Type": "application/json" }
                    });
                    window.fetch = async (url, opts = {}) => {
                        const target = String(url || "");
                        const headers = opts.headers || {};
                        const csrf = headers["X-CSRF-Token"] || headers["x-csrf-token"] || "";
                        calls.push({ url: target, method: String(opts.method || "GET"), csrf });
                        if (target.includes("/auth/session")) {
                            return jsonResponse({
                                ok: true,
                                authenticated: true,
                                session: {
                                    username: "alice",
                                    org: "org1",
                                    msp_id: "Org1MSP",
                                    csrf_token: "csrf-fresh",
                                    webauthn_verified_at: new Date().toISOString()
                                }
                            });
                        }
                        if (target.includes("/fabric/submit")) {
                            if (csrf === "csrf-stale") {
                                return jsonResponse({ ok: false, error: "csrf validation failed" }, 403);
                            }
                            return jsonResponse({ ok: true, result: { status: "OK" } });
                        }
                        return jsonResponse({ ok: false, error: "not found" }, 404);
                    };
                    await agentSubmit("MarkRecoveryBundleCreated", ["2026-04-24T00:00:00Z", "2", "test"], { maxAttempts: 1 });
                    return {
                        calls,
                        csrf: AUTH_SESSION && AUTH_SESSION.csrf_token,
                        windowCsrf: window.AUTH_SESSION && window.AUTH_SESSION.csrf_token
                    };
                }"""
            )

            fabric_calls = [item for item in result["calls"] if "/fabric/submit" in item["url"]]
            self.assertEqual(result["csrf"], "csrf-fresh")
            self.assertEqual(result["windowCsrf"], "csrf-fresh")
            self.assertEqual([item["csrf"] for item in fabric_calls], ["csrf-stale", "csrf-fresh"])
            self.assertTrue(any("/auth/session" in item["url"] for item in result["calls"]))

            browser.close()

    def test_bundle_creation_self_heals_legacy_device_without_export_material(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{self.base_url}/tests/recovery_harness.html", wait_until="domcontentloaded")
            page.wait_for_function("() => typeof createRecoveryBundle === 'function'")

            self._prime_test_state(page)
            page.evaluate(
                """async () => {
                    window.__reissueCalls = [];
                    window.fetch = async (url, opts = {}) => {
                        const target = String(url || "");
                        if (target.includes("/auth/recovery/reissue-local-identities")) {
                            const body = opts && opts.body ? JSON.parse(opts.body) : {};
                            window.__reissueCalls.push(body);
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({
                                    ok: true,
                                    fabric_certificate: "-----BEGIN CERTIFICATE-----\\nREISSUED-CERT\\n-----END CERTIFICATE-----",
                                    session: {
                                        username: "alice",
                                        display_name: "alice",
                                        org: "org1",
                                        msp_id: "Org1MSP",
                                        client_id: "alice-client",
                                        role: "Researcher",
                                        department: "Chemistry",
                                        status: "active",
                                        recovery_bundle_required: true,
                                        recovery_bundle_created: false,
                                        recovery_bundle_created_at: "",
                                        passkey_count: 1,
                                        session_started_at: new Date().toISOString(),
                                    },
                                }),
                                text: async () => "",
                            };
                        }
                        if (target.includes("/auth/session")) {
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({ ok: true, session: window.AUTH_SESSION }),
                                text: async () => "",
                            };
                        }
                        return {
                            ok: false,
                            status: 404,
                            json: async () => ({ ok: false, error: "not found" }),
                            text: async () => "",
                        };
                    };
                    const rsaPair = await crypto.subtle.generateKey(
                        {
                            name: "RSA-OAEP",
                            modulusLength: 2048,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            hash: "SHA-256",
                        },
                        true,
                        ["encrypt", "decrypt"]
                    );
                    const rsaPkcs8 = await crypto.subtle.exportKey("pkcs8", rsaPair.privateKey);
                    const rsaWorkingPrivateKey = await crypto.subtle.importKey(
                        "pkcs8",
                        rsaPkcs8,
                        { name: "RSA-OAEP", hash: "SHA-256" },
                        false,
                        ["decrypt"]
                    );
                    const rsaPublicPem = await exportWebCryptoPublicKeyPem(rsaPair.publicKey);
                    const storedPublicKey = formatStoredWebCryptoPublicKey(rsaPublicPem);
                    const fingerprint = await computePublicKeyFingerprint(storedPublicKey);
                    await writeProtectedLocalKeyRecord({
                        version: 4,
                        kind: "webcrypto",
                        publicKey: storedPublicKey,
                        fingerprint,
                        privateKey: rsaWorkingPrivateKey,
                    });

                    const fabricPair = await crypto.subtle.generateKey(
                        { name: "ECDSA", namedCurve: "P-256" },
                        true,
                        ["sign", "verify"]
                    );
                    const fabricSpki = await crypto.subtle.exportKey("spki", fabricPair.publicKey);
                    const fabricPkcs8 = await crypto.subtle.exportKey("pkcs8", fabricPair.privateKey);
                    const fabricWorkingPrivateKey = await crypto.subtle.importKey(
                        "pkcs8",
                        fabricPkcs8,
                        { name: "ECDSA", namedCurve: "P-256" },
                        false,
                        ["sign"]
                    );
                    await writeLocalStoreRecord(fabricIdentityRecordId(), {
                        privateKey: fabricWorkingPrivateKey,
                        publicSpkiB64: _bytesToBase64(new Uint8Array(fabricSpki)),
                        certificatePem: "-----BEGIN CERTIFICATE-----\\nLEGACY-CERT\\n-----END CERTIFICATE-----",
                        userHandle: "alice-handle",
                    });
                    RECOVERY_EXPORT_CACHE = { dataEncryption: null, fabricSigning: null, createdAt: "" };
                    return true;
                }"""
            )

            page.reload(wait_until="domcontentloaded")
            page.wait_for_function("() => typeof createRecoveryBundle === 'function'")
            self._prime_test_state(page)
            created = page.evaluate(
                """async () => {
                    window.__reissueCalls = [];
                    window.fetch = async (url, opts = {}) => {
                        const target = String(url || "");
                        if (target.includes("/auth/recovery/reissue-local-identities")) {
                            const body = opts && opts.body ? JSON.parse(opts.body) : {};
                            window.__reissueCalls.push(body);
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({
                                    ok: true,
                                    fabric_certificate: "-----BEGIN CERTIFICATE-----\\nREISSUED-CERT\\n-----END CERTIFICATE-----",
                                    session: Object.assign({}, AUTH_SESSION || {}, {
                                        username: "alice",
                                        display_name: "alice",
                                        org: "org1",
                                        msp_id: "Org1MSP",
                                        client_id: "alice-client",
                                        role: "Researcher",
                                        department: "Chemistry",
                                        status: "active",
                                        recovery_bundle_required: true,
                                        recovery_bundle_created: false,
                                        recovery_bundle_created_at: "",
                                        passkey_count: 1,
                                    }),
                                }),
                                text: async () => "",
                            };
                        }
                        if (target.includes("/auth/session")) {
                            return {
                                ok: true,
                                status: 200,
                                json: async () => ({ ok: true, session: AUTH_SESSION }),
                                text: async () => "",
                            };
                        }
                        return {
                            ok: false,
                            status: 404,
                            json: async () => ({ ok: false, error: "not found" }),
                            text: async () => "",
                        };
                    };
                    uiPrompt = async (opts = {}) => {
                        const title = String(opts.title || "");
                        if (title === "Recovery passphrase" || title === "Confirm recovery passphrase") {
                            return "RecoveryPass!alice";
                        }
                        return null;
                    };
                    await loadBrowserRsaPair();
                    await loadFabricIdentityRecord();
                    return await createRecoveryBundle({ mandatory: true });
                }"""
            )

            self.assertTrue(created)
            downloads = page.evaluate("() => window.__downloads.slice()")
            logs = page.evaluate("() => window.__logs.slice()")
            reissue_calls = page.evaluate("() => window.__reissueCalls.slice()")
            session = page.evaluate(
                """() => ({
                    created: !!(AUTH_SESSION && AUTH_SESSION.recovery_bundle_created),
                    createdAt: (AUTH_SESSION && AUTH_SESSION.recovery_bundle_created_at) || ""
                })"""
            )

            self.assertEqual(len(downloads), 1)
            self.assertEqual(len(reissue_calls), 1)
            self.assertTrue(reissue_calls[0]["content_public_key"].startswith("SECUREDATA-ECDH-P256-HKDF-SHA256"))
            self.assertIn("BEGIN CERTIFICATE REQUEST", reissue_calls[0]["fabric_csr_pem"])
            self.assertTrue(session["created"])
            self.assertTrue(session["createdAt"])
            self.assertTrue(any("safely reissued" in item for item in logs))

            browser.close()


if __name__ == "__main__":
    unittest.main()
