import importlib.util
import os
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "server.py"
ECDH_PUBLIC_KEY = 'SECUREDATA-ECDH-P256-HKDF-SHA256\n{"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"x","y":"y"}'


def load_server_module():
    env_keys = {
        "AI_MODEL_DIR": "/tmp/securedata-missing-model",
        "AI_ENCODER_FILE": "/tmp/securedata-missing-model/encoder.pickle",
        "AI_THRESHOLDS_FILE": "/tmp/securedata-missing-model/thresholds.json",
        "IPFS_NODE_URLS": "http://127.0.0.1:59999",
        "IPFS_MIN_REPLICAS": "2",
        "IPFS_TARGET_REPLICAS": "2",
        "AUTO_SUGGEST": "0",
    }
    saved = {key: os.environ.get(key) for key in env_keys}
    module_name = f"server_reissue_test_{time.time_ns()}"
    try:
        for key, value in env_keys.items():
            os.environ[key] = value
        spec = importlib.util.spec_from_file_location(module_name, SERVER_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class RecoveryReissueEndpointTests(unittest.TestCase):
    def test_reissue_is_blocked_when_user_already_has_encrypted_assets(self):
        server = load_server_module()
        base_session = {
            "username": "alice",
            "display_name": "alice",
            "client_id": "alice-id",
            "msp_id": "Org1MSP",
            "role": "Researcher",
            "department": "Chemistry",
            "status": "active",
            "recovery_bundle_required": True,
            "recovery_bundle_created": False,
        }
        server._current_server_session = lambda: {"sid": "sid-test", "payload": dict(base_session), "csrf_token": "csrf-test"}
        server._current_auth_user = lambda: dict(base_session)
        server._require_recent_webauthn_auth = lambda max_age_seconds=None: True
        server._current_chain_profile = lambda: {
            "username": "alice",
            "userID": "alice-id",
            "mspID": "Org1MSP",
            "role": "Researcher",
            "department": "Chemistry",
            "recoveryBundle": {"required": True, "created": False},
        }
        server._security_agent_eval = lambda function, args: [
            {"id": "asset-1", "ownerID": "alice-id", "keys": {"alice-id": "wrapped-key"}}
        ] if function == "GetAllAssets" else []

        client = server.app.test_client()
        response = client.post(
            "/auth/recovery/reissue-local-identities",
            json={
                "content_public_key": ECDH_PUBLIC_KEY,
                "content_key_fingerprint": "fp-1",
                "fabric_csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----",
            },
            headers={"X-CSRF-Token": "csrf-test"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 409)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error_code"], "RECOVERY_REISSUE_BLOCKED_DATA_EXISTS")
        self.assertEqual(payload["owned_assets"], ["asset-1"])

    def test_reissue_updates_session_and_submits_chaincode_when_safe(self):
        server = load_server_module()
        session_box = {
            "payload": {
                "username": "alice",
                "display_name": "alice",
                "client_id": "alice-id",
                "msp_id": "Org1MSP",
                "role": "Researcher",
                "department": "Chemistry",
                "status": "active",
                "recovery_bundle_required": True,
                "recovery_bundle_created": False,
            }
        }
        submit_calls = []
        ca_modify_calls = []
        event_calls = []
        updated_profile = {
            "username": "alice",
            "userID": "alice-id",
            "mspID": "Org1MSP",
            "role": "Researcher",
            "department": "Chemistry",
            "fabricCert": "-----BEGIN CERTIFICATE-----\nNEW-CERT\n-----END CERTIFICATE-----",
            "recoveryBundle": {"required": True, "created": False, "createdAt": ""},
            "webAuthnCredentials": [{"credentialID": "cred-1", "publicKeyPEM": "pem"}],
        }

        server._current_server_session = lambda: {"sid": "sid-test", "payload": dict(session_box["payload"]), "csrf_token": "csrf-test"}
        server._current_auth_user = lambda: dict(session_box["payload"])
        server._require_recent_webauthn_auth = lambda max_age_seconds=None: True
        server._current_chain_profile = lambda: {
            "username": "alice",
            "userID": "alice-id",
            "mspID": "Org1MSP",
            "role": "Researcher",
            "department": "Chemistry",
            "recoveryBundle": {"required": True, "created": False},
        }
        server._security_agent_eval = lambda function, args: [] if function == "GetAllAssets" else []
        server._fabric_ca_modify_identity_secret = lambda **kwargs: ca_modify_calls.append(kwargs)
        server._fabric_ca_enroll_csr = lambda **kwargs: "-----BEGIN CERTIFICATE-----\nNEW-CERT\n-----END CERTIFICATE-----"
        server._fabric_client_id_from_cert = lambda cert: "alice-id"
        server._security_agent_submit = lambda function, args: submit_calls.append((function, list(args))) or {"ok": True}
        server._chain_profile_by_username = lambda username: dict(updated_profile)
        server._set_session_from_payload = lambda payload: session_box.__setitem__("payload", dict(payload))
        server._record_auth_event = lambda event_type, username, actor="", details="": event_calls.append((event_type, username, actor, details))

        client = server.app.test_client()
        response = client.post(
            "/auth/recovery/reissue-local-identities",
            json={
                "content_public_key": ECDH_PUBLIC_KEY,
                "content_key_fingerprint": "fp-1",
                "fabric_csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----",
            },
            headers={"X-CSRF-Token": "csrf-test"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["client_id"], "alice-id")
        self.assertEqual(payload["fabric_certificate"], "-----BEGIN CERTIFICATE-----\nNEW-CERT\n-----END CERTIFICATE-----")
        self.assertEqual(payload["session"]["username"], "alice")
        self.assertEqual(payload["session"]["client_id"], "alice-id")
        self.assertEqual(payload["session"]["fabric_cert"], "-----BEGIN CERTIFICATE-----\nNEW-CERT\n-----END CERTIFICATE-----")
        self.assertEqual(len(ca_modify_calls), 1)
        self.assertEqual(ca_modify_calls[0]["max_enrollments"], "-1")
        self.assertEqual(
            submit_calls,
            [
                (
                    "ReissueActivatedUserLocalIdentities",
                    [
                        "alice-id",
                        "alice",
                        ECDH_PUBLIC_KEY,
                        "fp-1",
                        "-----BEGIN CERTIFICATE-----\nNEW-CERT\n-----END CERTIFICATE-----",
                    ],
                )
            ],
        )
        self.assertTrue(any(item[0] == "recovery_reissue_success" for item in event_calls))


if __name__ == "__main__":
    unittest.main()
