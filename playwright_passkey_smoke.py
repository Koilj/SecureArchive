import json
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


UI_URL = os.getenv("SMOKE_UI_URL", "http://localhost:8000/")
API_URL = os.getenv("SMOKE_API_URL", "http://localhost:5500")
DEFAULT_APPROVED_CATEGORY = os.getenv("SMOKE_APPROVED_CATEGORY", "Artificial Intelligence")
ORG1_USERS_DIR = Path(
    os.getenv(
        "SMOKE_ORG1_USERS_DIR",
        "/home/ruslan/fabric-dev/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users",
    )
)


def log(msg: str):
    print(msg, flush=True)


def now_tag() -> str:
    return str(int(time.time()))


def normalize_whoami(payload: dict) -> dict:
    return {
        "client_id": payload.get("clientID") or payload.get("clientId") or payload.get("id") or "",
        "msp_id": payload.get("mspID") or payload.get("mspId") or "",
        "role": payload.get("role") or "",
        "department": payload.get("department") or "",
    }


def device_context(browser):
    context = browser.new_context(ignore_https_errors=True, accept_downloads=True)
    context.add_init_script(
        f"window.localStorage.setItem('securedataApiUrl', {json.dumps(API_URL)});"
    )
    page = context.new_page()
    page.on("console", lambda msg: print(f"[browser:{msg.type}] {msg.text}", flush=True))
    client = context.new_cdp_session(page)
    client.send("WebAuthn.enable")
    authenticator_id = client.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )["authenticatorId"]
    return context, page, client, authenticator_id


def open_login(page):
    page.goto(UI_URL, wait_until="domcontentloaded")
    page.wait_for_selector("#loginScreen", timeout=120000)
    page.wait_for_selector("#loginSubmit", timeout=120000)
    page.wait_for_function(
        "() => !!window.bootstrap && !!window.CryptoJS && !!window.JSEncrypt",
        timeout=120000,
    )


SESSION_EXPR = """() => {
    const session = (typeof AUTH_SESSION !== "undefined" && AUTH_SESSION)
        ? AUTH_SESSION
        : (window.AUTH_SESSION || null);
    return session ? JSON.parse(JSON.stringify(session)) : null;
}"""


def current_session(page) -> dict:
    return page.evaluate(SESSION_EXPR)


def refresh_session(page) -> dict:
    return page_eval(
        page,
        """async () => {
            try {
                const res = await authFetch(`${API_URL}/auth/session`);
                const data = await res.json().catch(() => null);
                if (!res.ok || !data || !data.ok || !data.session) {
                    return null;
                }
                if (typeof AUTH_SESSION !== "undefined") {
                    AUTH_SESSION = data.session;
                }
                window.AUTH_SESSION = data.session;
                if (typeof applyAuthSession === "function") {
                    try { applyAuthSession(); } catch {}
                }
                return JSON.parse(JSON.stringify(data.session));
            } catch {
                return null;
            }
        }""",
    )


def ensure_recovery_bundle(page, username: str):
    session = current_session(page) or {}
    if session.get("recovery_bundle_created"):
        return session
    passphrase = f"RecoveryPass!{username}"
    page_eval(
        page,
        """(pw) => {
            window.__pwRecoveryPassphrase = pw;
            if (!window.__pwRecoveryHelpersWrapped) {
                const origConfirm = window.uiConfirm;
                const origPrompt = window.uiPrompt;
                window.uiConfirm = async function(opts = {}) {
                    const title = String((opts && opts.title) || "");
                    const body = String((opts && opts.body) || "");
                    if (title === "Create recovery bundle" || body.includes("not fully protected until a recovery bundle is created")) {
                        return true;
                    }
                    return origConfirm.apply(this, arguments);
                };
                window.uiPrompt = async function(opts = {}) {
                    const title = String((opts && opts.title) || "");
                    if (title === "Recovery passphrase" || title === "Confirm recovery passphrase") {
                        return String(window.__pwRecoveryPassphrase || "");
                    }
                    return origPrompt.apply(this, arguments);
                };
                window.__pwRecoveryHelpersWrapped = true;
            }
            return true;
        }""",
        passphrase,
    )
    started = False
    prompt_count = 0
    deadline = time.time() + 120
    auto_flow_grace_deadline = time.time() + 12
    while time.time() < deadline:
        session = current_session(page) or {}
        if started and not session.get("recovery_bundle_created"):
            session = refresh_session(page) or session
        if session.get("recovery_bundle_created"):
            return session
        prompt_ready = False
        confirm_ready = False
        try:
            prompt_ready = bool(
                page_eval(
                    page,
                    """() => {
                        const input = document.querySelector('#promptModalInput');
                        const ok = document.querySelector('#promptModalOk');
                        if (!input || !ok) return false;
                        const wrap = document.querySelector('#promptModal');
                        const inputVisible = !!(input.offsetParent || input.getClientRects().length);
                        const modalVisible = !!(wrap && (wrap.classList.contains('show') || wrap.style.display === 'block'));
                        return inputVisible || modalVisible;
                    }""",
                )
            )
        except Exception:
            prompt_ready = False
        try:
            confirm_ready = bool(
                page_eval(
                    page,
                    """() => {
                        const ok = document.querySelector('#confirmModalOk');
                        if (!ok) return false;
                        const wrap = document.querySelector('#confirmModal');
                        const okVisible = !!(ok.offsetParent || ok.getClientRects().length);
                        const modalVisible = !!(wrap && (wrap.classList.contains('show') || wrap.style.display === 'block'));
                        return okVisible || modalVisible;
                    }""",
                )
            )
        except Exception:
            confirm_ready = False
        if not started:
            try:
                if confirm_ready:
                    page.click("#confirmModalOk", timeout=1000)
                    started = True
                    time.sleep(0.25)
                    continue
            except Exception:
                pass
            try:
                if prompt_ready:
                    page.fill("#promptModalInput", passphrase)
                    page.click("#promptModalOk", timeout=1000)
                    started = True
                    prompt_count += 1
                    time.sleep(0.25)
                    continue
            except Exception:
                pass
            if time.time() >= auto_flow_grace_deadline:
                page_eval(page, "() => showMainTab('#pane-security')")
                try:
                    page.click('button[onclick="createRecoveryBundle()"]', timeout=1000)
                    started = True
                    time.sleep(0.25)
                    continue
                except Exception:
                    page_eval(
                        page,
                        """() => {
                            if (typeof createRecoveryBundle === "function") {
                                window.__pwRecoveryBundlePromise = createRecoveryBundle({ mandatory: true });
                                return true;
                            }
                            return false;
                        }""",
                    )
                    started = True
                    time.sleep(0.25)
                    continue
        try:
            if confirm_ready:
                page.click("#confirmModalOk", timeout=1000)
                time.sleep(0.25)
                continue
        except Exception:
            pass
        try:
            if prompt_ready:
                page.fill("#promptModalInput", passphrase)
                page.click("#promptModalOk", timeout=1000)
                prompt_count += 1
                time.sleep(0.25)
                continue
        except Exception:
            pass
        time.sleep(0.25)
    state = page_eval(
        page,
        """() => ({
            confirmVisible: !!document.querySelector('#confirmModal.show'),
            confirmTitle: (document.querySelector('#confirmModalTitle')?.textContent || '').trim(),
            confirmBody: (document.querySelector('#confirmModalBody')?.textContent || '').trim(),
            promptVisible: !!document.querySelector('#promptModal.show'),
            promptTitle: (document.querySelector('#promptModalTitle')?.textContent || '').trim(),
            promptLabel: (document.querySelector('#promptModalLabel')?.textContent || '').trim(),
            activeTab: document.querySelector('.tab-pane.show.active')?.id || '',
        })""",
    )
    raise RuntimeError(
        f"recovery bundle flow did not complete for {username}; prompts_handled={prompt_count}; state={state!r}"
    )


def activate_device(page, *, invite_token: str | None = None, bootstrap: bool = False):
    open_login(page)
    page.click("#loginModeBtnRegister")
    page.wait_for_selector("#loginModeRegister:not(.d-none)", timeout=120000)
    if bootstrap:
        invite_token = page_eval(
            page,
            """async () => {
                const res = await authFetch(`${API_URL}/auth/bootstrap-ticket`, { method: "POST" });
                const data = await res.json().catch(() => null);
                if (!res.ok || !data || !data.ok || !data.invite_token) {
                    throw new Error((data && data.error) ? data.error : "bootstrap ticket failed");
                }
                return data.invite_token;
            }""",
        )
        page.fill("#loginInviteToken", invite_token)
    else:
        if not invite_token:
            raise RuntimeError("invite token is required")
        page.fill("#loginInviteToken", invite_token)
    page.click("#activateSubmit")
    try:
        page.wait_for_function(
            """() => {
                const session = (typeof AUTH_SESSION !== "undefined" && AUTH_SESSION)
                    ? AUTH_SESSION
                    : window.AUTH_SESSION;
                return !!(session && session.username);
            }""",
            timeout=120000,
        )
    except PlaywrightTimeoutError as exc:
        error_text = page_eval(
            page,
            "() => (document.querySelector('#loginError') && document.querySelector('#loginError').textContent || '').trim()",
        )
        if error_text:
            raise RuntimeError(f"device activation failed: {error_text}") from exc
        raise
    session = current_session(page)
    session = ensure_recovery_bundle(page, session.get("username") or "")
    return invite_token, session


def passkey_login(page, username: str):
    open_login(page)
    page.fill("#loginUsername", username)
    page.click("#loginSubmit")
    page.wait_for_function(
        """() => {
            const session = (typeof AUTH_SESSION !== "undefined" && AUTH_SESSION)
                ? AUTH_SESSION
                : window.AUTH_SESSION;
            return !!(session && session.username);
        }""",
        timeout=120000,
    )
    session = current_session(page)
    if not session.get("recovery_bundle_created"):
        session = ensure_recovery_bundle(page, username)
    return session


def page_eval(page, expression: str, arg=None):
    if arg is None:
        return page.evaluate(expression)
    return page.evaluate(expression, arg)


def issue_invite(page, username: str, *, department: str = "IT Department", role: str = "Researcher", org: str = "org1") -> dict:
    return page_eval(
        page,
        """async (payload) => {
            const res = await authFetch(`${API_URL}/auth/users`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await res.json().catch(() => null);
            if (!res.ok || !data || !data.ok) {
                throw new Error((data && data.error) ? data.error : "invite creation failed");
            }
            return data.user;
        }""",
        {"username": username, "department": department, "role": role, "org": org},
    )


def whoami(page) -> dict:
    raw = page_eval(page, "() => agentEval('WhoAmI', [])")
    if not isinstance(raw, dict):
        raise RuntimeError(f"unexpected WhoAmI response: {raw!r}")
    return normalize_whoami(raw)


def upload_sample_asset(page, filename: str, body: bytes, *, title: str, authors: str, discipline: str):
    page_eval(page, "() => showMainTab('#pane-assets')")
    page.wait_for_selector("#pane-assets.show.active", timeout=120000)
    page.wait_for_selector("#fileDesc", state="visible", timeout=120000)
    page.fill("#fileDesc", "playwright smoke upload")
    page.fill("#metaTitle", title)
    page.fill("#metaAuthors", authors)
    page.fill("#metaDiscipline", discipline)
    page.fill("#metaLicense", "CC-BY-4.0")
    page.fill("#metaDOI", "")
    page.fill("#metaKeywords", "smoke,passkey")
    page.set_input_files(
        "#fileInput",
        [{"name": filename, "mimeType": "text/plain", "buffer": body}],
    )
    page_eval(
        page,
        """() => {
            if (typeof uploadFile === "function") {
                window.__pwUploadPromise = uploadFile();
                return true;
            }
            return false;
        }""",
    )
    try:
        page.wait_for_function(
            """() => {
                const btn = document.querySelector('#btnUpload');
                const result = document.querySelector('#uploadResult');
                return !!(btn && !btn.disabled && result && !result.classList.contains('d-none'));
            }""",
            timeout=180000,
        )
    except PlaywrightTimeoutError as exc:
        state = page_eval(
            page,
            """() => ({
                btnDisabled: !!document.querySelector('#btnUpload')?.disabled,
                fileCount: document.querySelector('#fileInput')?.files?.length || 0,
                uploadResultHidden: document.querySelector('#uploadResult')?.classList.contains('d-none') ?? true,
                uploadResultText: (document.querySelector('#uploadResult')?.textContent || '').trim(),
                noticesText: (document.querySelector('#topNotices')?.textContent || '').trim(),
                activeTab: document.querySelector('.tab-pane.show.active')?.id || '',
                confirmVisible: !!document.querySelector('#confirmModal.show'),
                confirmTitle: (document.querySelector('#confirmModalTitle')?.textContent || '').trim(),
                confirmBody: (document.querySelector('#confirmModalBody')?.textContent || '').trim(),
                promptVisible: !!document.querySelector('#promptModal.show'),
                promptTitle: (document.querySelector('#promptModalTitle')?.textContent || '').trim(),
                promptLabel: (document.querySelector('#promptModalLabel')?.textContent || '').trim(),
                logText: (document.querySelector('#logBox')?.textContent || '').trim(),
            })""",
        )
        raise RuntimeError(f"upload flow did not complete: {state!r}") from exc


def wait_for_asset(page, title: str, *, timeout_seconds: int = 90) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        assets = page_eval(page, "() => agentEval('GetMyAssets', [])")
        if isinstance(assets, list):
            for asset in assets:
                meta = asset.get("metadata") or asset.get("Metadata") or {}
                if (meta.get("title") or asset.get("title") or asset.get("Title")) == title:
                    return asset
        time.sleep(2)
    raise RuntimeError(f"asset with title {title!r} not found")


def wait_for_key_access(page, asset_id: str, *, timeout_seconds: int = 60) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = page_eval(
            page,
            """(assetId) => agentSubmit('RequestMyEncryptedKey', [assetId])""",
            asset_id,
        )
        if isinstance(result, dict) and (result.get("status") or result.get("Status")) == "OK":
            return result
        time.sleep(2)
    raise RuntimeError(f"encrypted key for asset {asset_id} was not granted in time")


def download_asset(page, asset_id: str) -> dict:
    with page.expect_download(timeout=120000) as download_info:
        page_eval(
            page,
            """async (assetId) => {
                await downloadAsset(assetId);
                return true;
            }""",
            asset_id,
        )
    download = download_info.value
    path = download.path()
    return {
        "suggested_filename": download.suggested_filename,
        "path": str(path) if path else "",
    }


def wait_for_download_audit(page, user_id: str, asset_id: str, *, timeout_seconds: int = 60) -> list[dict]:
    deadline = time.time() + timeout_seconds
    last_items = []
    while time.time() < deadline:
        res = page_eval(page, "(uid) => agentEval('QueryDownloadAuditsByUser', [uid])", user_id)
        items = (res or {}).get("items") or (res or {}).get("Items") or []
        if isinstance(items, list):
            last_items = items
            if any((item.get("assetID") or item.get("AssetID") or "") == asset_id for item in items if isinstance(item, dict)):
                return items
        time.sleep(2)
    raise RuntimeError(f"download audit for asset {asset_id!r} and user {user_id!r} was not recorded in time: {last_items!r}")


def read_asset(page, asset_id: str) -> dict | None:
    asset = page_eval(page, "(id) => agentEval('ReadAsset', [id])", asset_id)
    return asset if isinstance(asset, dict) else None


def normalize_request(payload: dict) -> dict:
    return {
        "asset_id": str(payload.get("AssetID") or payload.get("assetID") or payload.get("assetId") or payload.get("asset_id") or ""),
        "requester_id": str(
            payload.get("RequesterID")
            or payload.get("requesterID")
            or payload.get("requesterId")
            or payload.get("requester_id")
            or payload.get("Requester")
            or payload.get("requester")
            or ""
        ),
        "status": str(payload.get("Status") or payload.get("status") or "").strip().upper(),
        "raw": payload,
    }


def wait_for_access_request(owner_page, requester_page, asset_id: str, requester_id: str, *, timeout_seconds: int = 60) -> dict:
    deadline = time.time() + timeout_seconds
    last_owner_requests = []
    last_requester_requests = []
    while time.time() < deadline:
        owner_requests_raw = page_eval(owner_page, "() => agentEval('GetPendingRequests', [])")
        requester_requests_raw = page_eval(requester_page, "() => agentEval('GetMyRequests', [])")

        owner_requests = [
            normalize_request(item)
            for item in (owner_requests_raw if isinstance(owner_requests_raw, list) else [])
            if isinstance(item, dict)
        ]
        requester_requests = [
            normalize_request(item)
            for item in (requester_requests_raw if isinstance(requester_requests_raw, list) else [])
            if isinstance(item, dict)
        ]

        last_owner_requests = owner_requests
        last_requester_requests = requester_requests

        owner_match = next(
            (
                item
                for item in owner_requests
                if item["asset_id"] == asset_id and item["status"] in {"PENDING", "APPROVED"}
            ),
            None,
        )
        requester_match = next(
            (
                item
                for item in requester_requests
                if item["asset_id"] == asset_id and item["status"] in {"PENDING", "APPROVED"}
            ),
            None,
        )

        canonical_requester_id = (
            (requester_match or {}).get("requester_id")
            or (owner_match or {}).get("requester_id")
            or requester_id
        )
        if requester_match:
            return {
                "requester_id": canonical_requester_id,
                "owner_visible": bool(owner_match),
                "owner_request": (owner_match or {}).get("raw"),
                "requester_request": requester_match.get("raw"),
            }

        time.sleep(2)

    raise RuntimeError(
        "access request was not visible in time: "
        f"owner_requests={last_owner_requests!r}; requester_requests={last_requester_requests!r}"
    )


def approve_asset_category(page, asset_id: str, *, timeout_seconds: int = 60) -> dict:
    deadline = time.time() + timeout_seconds
    last_asset = None
    while time.time() < deadline:
        asset = read_asset(page, asset_id)
        if isinstance(asset, dict):
            last_asset = asset
            suggested = (asset.get("SuggestedCategory") or asset.get("suggestedCategory") or "").strip()
            current = (asset.get("Category") or asset.get("category") or "").strip()
            if suggested and suggested.lower() not in {"unverified", "unknown"}:
                approved = suggested
            elif current and current.lower() not in {"unverified", "unknown"}:
                approved = current
            else:
                approved = DEFAULT_APPROVED_CATEGORY
            result = page_eval(page, "([id, category]) => agentSubmit('ApproveCategory', [id, category])", [asset_id, approved])
            while time.time() < deadline:
                refreshed = read_asset(page, asset_id)
                if isinstance(refreshed, dict):
                    review = bool(refreshed.get("NeedsManualReview") or refreshed.get("needsManualReview"))
                    refreshed_category = (refreshed.get("Category") or refreshed.get("category") or "").strip()
                    if not review and refreshed_category == approved:
                        return {"approved_category": approved, "result": result, "asset": refreshed}
                    last_asset = refreshed
                time.sleep(2)
            raise RuntimeError(f"asset {asset_id!r} did not reflect approved category in time: {last_asset!r}")
        time.sleep(2)
    raise RuntimeError(f"asset {asset_id!r} not ready for category approval: {last_asset!r}")


def grant_access_direct(page, asset_id: str, requester_id: str, *, timeout_seconds: int = 90) -> dict:
    material = page_eval(
        page,
        """async ([assetId, requesterId]) => {
            const ownerKeyResp = await agentSubmit("RequestMyEncryptedKey", [assetId], { maxAttempts: 1 });
            const ownerStatus = (ownerKeyResp && (ownerKeyResp.status || ownerKeyResp.Status)) || "";
            if (ownerStatus !== "OK") {
                throw new Error(`owner key status=${ownerStatus}`);
            }
            const ownerEncKey = ownerKeyResp.key || (ownerKeyResp.result && ownerKeyResp.result.key) || "";
            if (!ownerEncKey) {
                throw new Error("owner encrypted key is missing");
            }

            const aesKey = await agentRsaDecrypt(ownerEncKey);
            if (!aesKey) {
                throw new Error("failed to decrypt owner AES key");
            }

            const requesterPub = await agentEval("GetUserPublicKey", [requesterId]);
            if (!requesterPub) {
                throw new Error("requester public key not found");
            }

            const encryptedForRequester = await rsaEncryptForStoredPublicKey(requesterPub, String(aesKey).trim());
            if (!encryptedForRequester) {
                throw new Error("failed to encrypt AES key for requester");
            }

            return { encrypted_for_requester: encryptedForRequester };
        }""",
        [asset_id, requester_id],
    )
    encrypted_for_requester = str((material or {}).get("encrypted_for_requester") or "")
    if not encrypted_for_requester:
        raise RuntimeError("failed to prepare requester key envelope")

    deadline = time.time() + timeout_seconds
    last_asset = None
    last_error = ""
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        asset = read_asset(page, asset_id)
        if isinstance(asset, dict):
            last_asset = asset
        try:
            result = page_eval(
                page,
                """async ([assetId, requesterId, encrypted]) => {
                    return await agentSubmit("GrantAccess", [assetId, requesterId, encrypted], { maxAttempts: 1 });
                }""",
                [asset_id, requester_id, encrypted_for_requester],
            )
            return {
                "attempts": attempts,
                "result": result,
                "asset": last_asset,
            }
        except Exception as exc:
            last_error = str(exc)
            retryable = (
                "category is not approved yet" in last_error.lower()
                or "request not found" in last_error.lower()
                or "mvcc_read_conflict" in last_error.lower()
                or "status code 11" in last_error.lower()
            )
            if not retryable:
                raise RuntimeError(f"grant access failed: {last_error}") from exc
        time.sleep(2)

    raise RuntimeError(
        f"grant access did not succeed in time after {attempts} attempts: {last_error}; last_asset={last_asset!r}"
    )


def main():
    suffix = now_tag()
    alice_username = f"smokealice{suffix}"
    bob_username = f"smokebob{suffix}"
    title = f"Smoke Asset {suffix}"
    filename = "20260414_Alice_Smoke.txt"

    report = {
        "bootstrap_user": "SecurityService",
        "alice_username": alice_username,
        "bob_username": bob_username,
        "ui_url": UI_URL,
        "api_url": API_URL,
        "steps": [],
    }

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            sec_ctx, sec_page, sec_cdp, sec_auth = device_context(browser)
            alice_ctx, alice_page, alice_cdp, alice_auth = device_context(browser)
            bob_ctx, bob_page, bob_cdp, bob_auth = device_context(browser)
            report["webauthn_authenticators"] = [sec_auth, alice_auth, bob_auth]

            log("Bootstrapping SecurityService with passkey activation...")
            bootstrap_invite, security_session = activate_device(
                sec_page,
                bootstrap=True,
            )
            report["steps"].append(
                {
                    "name": "bootstrap_activate_securityservice",
                    "username": security_session.get("username"),
                    "role": security_session.get("role"),
                    "invite_length": len(bootstrap_invite),
                }
            )
            if security_session.get("username") != "SecurityService":
                raise RuntimeError("SecurityService activation did not yield SecurityService session")

            log("Issuing researcher invite tickets from SecurityService session...")
            alice_invite = issue_invite(sec_page, alice_username)
            bob_invite = issue_invite(sec_page, bob_username)
            report["steps"].append(
                {
                    "name": "issue_invites",
                    "alice_invite_id": alice_invite.get("invite_id"),
                    "bob_invite_id": bob_invite.get("invite_id"),
                }
            )

            log("Activating Alice device...")
            _, alice_session = activate_device(
                alice_page,
                invite_token=alice_invite["invite_token"],
            )
            if alice_session.get("username") != alice_username:
                raise RuntimeError("Alice activation failed")

            log("Activating Bob device...")
            _, bob_session = activate_device(
                bob_page,
                invite_token=bob_invite["invite_token"],
            )
            if bob_session.get("username") != bob_username:
                raise RuntimeError("Bob activation failed")
            report["steps"].append({"name": "activate_devices", "alice": alice_session, "bob": bob_session})

            log("Verifying passkey login after logout for Alice...")
            page_eval(alice_page, "() => handleLogout()")
            alice_login_session = passkey_login(alice_page, alice_username)
            if alice_login_session.get("username") != alice_username:
                raise RuntimeError("Alice passkey login failed after logout")
            report["steps"].append({"name": "alice_passkey_login", "session": alice_login_session})

            log("Running WhoAmI for SecurityService, Alice, Bob...")
            who_security = whoami(sec_page)
            who_alice = whoami(alice_page)
            who_bob = whoami(bob_page)
            if who_security["role"] != "SecurityService":
                raise RuntimeError("SecurityService WhoAmI role mismatch")
            if not who_alice["client_id"] or not who_bob["client_id"]:
                raise RuntimeError("WhoAmI did not return client IDs")
            report["steps"].append(
                {
                    "name": "whoami",
                    "security": who_security,
                    "alice": who_alice,
                    "bob": who_bob,
                }
            )

            log("Uploading encrypted asset from Alice device...")
            upload_sample_asset(
                alice_page,
                filename=filename,
                body=f"playwright smoke payload {suffix}".encode("utf-8"),
                title=title,
                authors="Alice",
                discipline="IT Department",
            )
            alice_asset = wait_for_asset(alice_page, title)
            asset_id = alice_asset.get("id") or alice_asset.get("ID")
            if not asset_id:
                raise RuntimeError("Uploaded asset has no id")
            report["steps"].append({"name": "upload_asset", "asset_id": asset_id})

            log("Approving uploaded asset category from Alice...")
            approved = approve_asset_category(alice_page, asset_id)
            report["steps"].append(
                {
                    "name": "approve_category",
                    "asset_id": asset_id,
                    "approved_category": approved.get("approved_category"),
                }
            )

            log("Submitting access request from Bob...")
            bob_request = page_eval(
                bob_page,
                """(assetId) => agentSubmit('RequestAccessWithReason', [assetId, 'playwright smoke request'])""",
                asset_id,
            )
            report["steps"].append({"name": "request_access", "result": bob_request})

            log("Waiting for access request to become visible in ledger...")
            request_state = wait_for_access_request(alice_page, bob_page, asset_id, who_bob["client_id"])
            report["steps"].append(
                {
                    "name": "request_visible",
                    "requester_id": request_state.get("requester_id"),
                    "owner_visible": bool(request_state.get("owner_visible")),
                }
            )

            log("Granting access from Alice to Bob...")
            grant_result = grant_access_direct(alice_page, asset_id, request_state.get("requester_id") or who_bob["client_id"])
            granted_key = wait_for_key_access(bob_page, asset_id)
            report["steps"].append(
                {
                    "name": "grant_access",
                    "requester_id": request_state.get("requester_id") or who_bob["client_id"],
                    "grant_attempts": grant_result.get("attempts"),
                    "key_status": granted_key.get("status") or granted_key.get("Status"),
                }
            )

            log("Downloading the asset from Bob to verify decrypt + integrity + audit logging...")
            download_info = download_asset(bob_page, asset_id)
            download_audits = wait_for_download_audit(bob_page, who_bob["client_id"], asset_id)
            report["steps"].append(
                {
                    "name": "download_asset",
                    "download": download_info,
                    "download_audit_count": len(download_audits),
                }
            )

            log("Checking ledger-backed user list for passkey metadata...")
            auth_users = page_eval(
                sec_page,
                """async () => {
                    const res = await authFetch(`${API_URL}/auth/users`);
                    const data = await res.json().catch(() => null);
                    if (!res.ok || !data || !data.ok) {
                        throw new Error((data && data.error) ? data.error : "auth/users failed");
                    }
                    return data.users || [];
                }""",
            )
            by_name = {item.get("username"): item for item in auth_users if isinstance(item, dict)}
            if not by_name.get(alice_username, {}).get("has_passkey"):
                raise RuntimeError("Alice ledger profile is missing passkey metadata")
            if not by_name.get(bob_username, {}).get("has_passkey"):
                raise RuntimeError("Bob ledger profile is missing passkey metadata")
            report["steps"].append(
                {
                    "name": "ledger_passkey_metadata",
                    "alice_has_passkey": by_name[alice_username]["has_passkey"],
                    "bob_has_passkey": by_name[bob_username]["has_passkey"],
                }
            )

            log("Verifying no server-side Fabric wallet directory was created for activated users...")
            alice_wallet_dir = ORG1_USERS_DIR / f"{alice_username}@org1.example.com"
            bob_wallet_dir = ORG1_USERS_DIR / f"{bob_username}@org1.example.com"
            if alice_wallet_dir.exists() or bob_wallet_dir.exists():
                raise RuntimeError(
                    f"server-side wallet directory unexpectedly exists: {alice_wallet_dir} / {bob_wallet_dir}"
                )
            report["steps"].append(
                {
                    "name": "no_server_wallet_dirs",
                    "alice_wallet_dir": str(alice_wallet_dir),
                    "bob_wallet_dir": str(bob_wallet_dir),
                }
            )

            report["ok"] = True
        except PlaywrightTimeoutError as exc:
            report["ok"] = False
            report["error"] = f"timeout: {exc}"
            raise
        except Exception as exc:
            report["ok"] = False
            report["error"] = str(exc)
            raise
        finally:
            print(json.dumps(report, indent=2, sort_keys=True), flush=True)
            browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"SMOKE FAILED: {exc}")
        sys.exit(1)
            browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"SMOKE FAILED: {exc}")
        sys.exit(1)
