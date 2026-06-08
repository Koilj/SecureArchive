import json
import os
import sys

from playwright.sync_api import sync_playwright


UI_URL = os.getenv("SMOKE_UI_URL", "http://localhost:8000/")


def main():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send(
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
        )
        page.goto(UI_URL, wait_until="domcontentloaded")
        result = page.evaluate(
            """async () => {
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const userId = crypto.getRandomValues(new Uint8Array(16));
                try {
                    const cred = await navigator.credentials.create({
                        publicKey: {
                            challenge,
                            rp: { name: "Probe RP", id: window.location.hostname },
                            user: { id: userId, name: "probe-user", displayName: "probe-user" },
                            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                            timeout: 60000,
                            attestation: "none",
                            authenticatorSelection: {
                                residentKey: "preferred",
                                userVerification: "required",
                            },
                        },
                    });
                    return {
                        ok: true,
                        id: cred.id,
                        type: cred.type,
                    };
                } catch (err) {
                    return {
                        ok: false,
                        name: err && err.name ? err.name : "",
                        message: err && err.message ? err.message : String(err),
                        isSecureContext: window.isSecureContext,
                        hostname: window.location.hostname,
                    };
                }
            }"""
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        browser.close()
        if not result.get("ok"):
            raise RuntimeError(result.get("message") or "webauthn probe failed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"PROBE FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
