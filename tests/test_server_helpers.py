"""Pure-helper tests for server.py — no Fabric/IPFS required."""
import importlib.util
import base64
import json
import os
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "server.py"


def load_server_module():
    env_keys = {
        "AI_MODEL_DIR": "/tmp/securedata-missing-model",
        "AI_ENCODER_FILE": "/tmp/securedata-missing-model/encoder.pickle",
        "AI_THRESHOLDS_FILE": "/tmp/securedata-missing-model/thresholds.json",
        "IPFS_NODE_URLS": "http://127.0.0.1:59999,http://127.0.0.1:59998",
        "IPFS_MIN_REPLICAS": "2",
        "IPFS_TARGET_REPLICAS": "2",
        "AUTO_SUGGEST": "0",
    }
    saved = {key: os.environ.get(key) for key in env_keys}
    module_name = f"server_helpers_test_{time.time_ns()}"
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


class ServerHelpersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server_module()

    # ---------------------------
    # Text normalisation
    # ---------------------------
    def test_norm_simple_text_strips_controls_and_zero_width(self):
        srv = self.server
        out = srv._norm_simple_text("A\u200Bplain\x00 text  ", 50)
        self.assertEqual(out, "Aplain text")

    def test_norm_simple_text_truncates(self):
        srv = self.server
        long = "x" * 100
        self.assertEqual(len(srv._norm_simple_text(long, 20)), 20)

    # ---------------------------
    # Filename policy
    # ---------------------------
    def test_allowed_file(self):
        srv = self.server
        self.assertTrue(srv.allowed_file("20260101_Alice_Topic.pdf"))
        self.assertTrue(srv.allowed_file("20260101_Alice_Topic.pdf.enc"))
        self.assertFalse(srv.allowed_file("malware.exe"))
        self.assertFalse(srv.allowed_file("noext"))
        self.assertFalse(srv.allowed_file(""))

    def test_validate_filename_policy_enforces_pattern_and_size(self):
        srv = self.server
        ok, msg = srv.validate_filename_policy("20260101_Alice_Topic.pdf", 123)
        self.assertTrue(ok, msg)

        ok, msg = srv.validate_filename_policy("bad.pdf", 10)
        self.assertFalse(ok)
        self.assertIn("YYYYMMDD", msg)

        ok, msg = srv.validate_filename_policy("20260101_Alice_Topic.pdf", 0)
        self.assertFalse(ok)
        self.assertEqual(msg, "File is empty.")

        ok, _ = srv.validate_filename_policy("20260101_Alice_Topic.pdf.enc", 42)
        self.assertTrue(ok)

    # ---------------------------
    # Encrypted payload validation
    # ---------------------------
    def test_validate_encrypted_blob(self):
        srv = self.server
        ok, _ = srv._validate_encrypted_blob(base64.b64encode(b"0" * 16) + b"::" + base64.b64encode(b"ciphertext"))
        self.assertTrue(ok)

        envelope = {
            "type": "securedata.content-envelope",
            "version": 2,
            "alg": "AES-256-GCM",
            "ivB64": base64.b64encode(b"1" * 12).decode("ascii"),
            "aad": {"assetId": "asset_test"},
            "ciphertextB64": base64.b64encode(b"ciphertext-with-gcm-tag").decode("ascii"),
        }
        ok, _ = srv._validate_encrypted_blob(json.dumps(envelope).encode("utf-8"))
        self.assertTrue(ok)

        ok, msg = srv._validate_encrypted_blob(b"")
        self.assertFalse(ok)
        self.assertIn("empty", msg)

        ok, msg = srv._validate_encrypted_blob(b"no-separator-here")
        self.assertFalse(ok)
        self.assertIn("::", msg)

        ok, msg = srv._validate_encrypted_blob(b"\xff\xfe\x00")
        self.assertFalse(ok)
        self.assertIn("UTF-8", msg)

    # ---------------------------
    # AI helpers
    # ---------------------------
    def test_is_actionable_ai_category(self):
        srv = self.server
        self.assertTrue(srv._is_actionable_ai_category("Machine Learning"))
        self.assertFalse(srv._is_actionable_ai_category(""))
        self.assertFalse(srv._is_actionable_ai_category("Unverified"))
        self.assertFalse(srv._is_actionable_ai_category("UNCLASSIFIED"))
        self.assertFalse(srv._is_actionable_ai_category("error"))

    def test_normalize_ai_confidence_bounds(self):
        srv = self.server
        self.assertEqual(srv._normalize_ai_confidence(75), 75.0)
        self.assertEqual(srv._normalize_ai_confidence("12.5"), 12.5)
        self.assertIsNone(srv._normalize_ai_confidence(-1))
        self.assertIsNone(srv._normalize_ai_confidence(101))
        self.assertIsNone(srv._normalize_ai_confidence("nan"))
        self.assertIsNone(srv._normalize_ai_confidence("nan-ish"))

    def test_ai_suggestion_threshold_gate(self):
        srv = self.server
        saved = srv.AUTO_SUGGEST_MIN_CONF
        try:
            srv.AUTO_SUGGEST_MIN_CONF = 80.0
            self.assertTrue(srv._ai_suggestion_meets_threshold("Machine Learning", 80.0))
            self.assertFalse(srv._ai_suggestion_meets_threshold("Machine Learning", 79.99))
            self.assertFalse(srv._ai_suggestion_meets_threshold("Unclassified", 99.0))
            self.assertFalse(srv._ai_suggestion_meets_threshold("Machine Learning", None))
        finally:
            srv.AUTO_SUGGEST_MIN_CONF = saved

    def test_predict_category_returns_unclassified_when_ai_offline(self):
        srv = self.server
        srv._ai_service_available = False
        label, conf = srv.predict_category_and_confidence("hello world")
        self.assertEqual(label, "Unclassified")
        self.assertIsNone(conf)

    # ---------------------------
    # IPFS URL parsing
    # ---------------------------
    def test_derive_ipfs_base_url_strips_api_suffix(self):
        srv = self.server
        self.assertEqual(
            srv._derive_ipfs_base_url("http://node:5001/api/v0/add"),
            "http://node:5001",
        )
        self.assertEqual(
            srv._derive_ipfs_base_url("http://node:5001"),
            "http://node:5001",
        )
        self.assertEqual(srv._derive_ipfs_base_url(""), "")

    def test_parse_ipfs_nodes_deduplicates(self):
        srv = self.server
        # Module-level IPFS_NODES was set from env in setUpClass; spot-check.
        ids = [node["id"] for node in srv.IPFS_NODES]
        self.assertEqual(len(ids), len(set(ids)))
        for node in srv.IPFS_NODES:
            self.assertTrue(node["api_url"].endswith("/api/v0"))

    def test_ipfs_storage_policy_requires_available_status(self):
        srv = self.server
        self.assertTrue(srv._ipfs_storage_available({"available": True}))
        self.assertTrue(srv._ipfs_storage_available({"healthy_replicas": 2, "required_replicas": 2}))
        self.assertFalse(srv._ipfs_storage_available({"healthy_replicas": 1, "required_replicas": 2, "available": False}))
        self.assertFalse(srv._ipfs_storage_available({}))

    # ---------------------------
    # ML / agent headers
    # ---------------------------
    def test_ml_headers_includes_role_and_optional_bearer(self):
        srv = self.server
        headers = srv._ml_headers()
        self.assertEqual(headers.get("X-Agent-Role"), "MLService")
        self.assertEqual(headers.get("Content-Type"), "application/json")

    def test_ml_agent_base_url_falls_back_to_security(self):
        srv = self.server
        saved_ml = srv.ML_AGENT_URL
        saved_env = os.environ.get("SECURITY_AGENT_URL")
        try:
            srv.ML_AGENT_URL = ""
            os.environ["SECURITY_AGENT_URL"] = "http://unified:9000/"
            self.assertEqual(srv._ml_agent_base_url(), "http://unified:9000")
        finally:
            srv.ML_AGENT_URL = saved_ml
            if saved_env is None:
                os.environ.pop("SECURITY_AGENT_URL", None)
            else:
                os.environ["SECURITY_AGENT_URL"] = saved_env

    # ---------------------------
    # Invite token round-trip
    # ---------------------------
    def test_invite_token_round_trip(self):
        srv = self.server
        future = "2099-12-31T23:59:59Z"
        token = srv._issue_invite_token({
            "username": "alice",
            "department": "IT",
            "role": "Researcher",
            "org": "org1",
            "invite_id": "id-1",
            "secret": "s3cret",
            "exp": future,
        })
        payload = srv._verify_invite_token(token)
        self.assertEqual(payload["username"], "alice")
        self.assertEqual(payload["invite_id"], "id-1")

    def test_invite_token_rejects_tampering(self):
        srv = self.server
        future = "2099-12-31T23:59:59Z"
        token = srv._issue_invite_token({
            "username": "alice",
            "department": "IT",
            "role": "Researcher",
            "org": "org1",
            "invite_id": "id-1",
            "secret": "s3cret",
            "exp": future,
        })
        body, sig = token.split(".", 1)
        tampered = body + "X" + "." + sig
        with self.assertRaises(ValueError):
            srv._verify_invite_token(tampered)

    def test_invite_token_rejects_expired(self):
        srv = self.server
        token = srv._issue_invite_token({
            "username": "alice",
            "department": "IT",
            "role": "Researcher",
            "org": "org1",
            "invite_id": "id-1",
            "secret": "s3cret",
            "exp": "2000-01-01T00:00:00Z",
        })
        with self.assertRaises(ValueError):
            srv._verify_invite_token(token)

    # ---------------------------
    # Endpoints (pure - no Fabric)
    # ---------------------------
    def test_health_endpoint(self):
        srv = self.server
        srv._ai_service_available = False
        with srv.app.test_client() as client:
            resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["ai"], "disabled")

    def test_current_server_session_backfills_csrf_for_legacy_record(self):
        srv = self.server
        sid = f"legacy-{time.time_ns()}"
        with srv.app.test_request_context("/auth/session"):
            srv.session["sid"] = sid
            with srv._SERVER_SESSIONS_LOCK:
                srv._SERVER_SESSIONS[sid] = {
                    "sid": sid,
                    "payload": {"username": "alice"},
                    "session_started_at": srv._utc_now_iso(),
                    "expires_at": srv.datetime.now(srv.timezone.utc) + srv._server_session_lifetime(),
                }
            try:
                record = srv._current_server_session()
                self.assertIsNotNone(record)
                self.assertTrue(record.get("csrf_token"))
                self.assertEqual(record.get("download_grants"), {})
                with srv._SERVER_SESSIONS_LOCK:
                    stored = srv._SERVER_SESSIONS[sid]
                    self.assertEqual(stored.get("csrf_token"), record.get("csrf_token"))
                    self.assertEqual(stored.get("download_grants"), {})
            finally:
                with srv._SERVER_SESSIONS_LOCK:
                    srv._SERVER_SESSIONS.pop(sid, None)

    def test_audit_disp_requires_security_session(self):
        srv = self.server
        with srv.app.test_client() as client:
            resp = client.get("/audit/disp")
        # Not authenticated → 401.
        self.assertEqual(resp.status_code, 401)

    def test_audit_disp_returns_buffered_records_for_security(self):
        srv = self.server
        srv._SERVER_AUDIT.clear()
        srv._SERVER_AUDIT.append({"endpoint": "/upload", "decision": "allow"})
        srv._SERVER_AUDIT.append({"endpoint": "/ai_suggest", "decision": "allow"})

        saved_session = srv._current_server_session
        saved_user = srv._current_auth_user
        try:
            srv._current_server_session = lambda: {"sid": "test", "payload": {"username": "sec"}}
            srv._current_auth_user = lambda: {"username": "sec", "role": "SecurityService"}
            with srv.app.test_client() as client:
                resp = client.get("/audit/disp")
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertTrue(payload["ok"])
            self.assertEqual(len(payload["items"]), 2)
            # Most recent first (reversed).
            self.assertEqual(payload["items"][0]["endpoint"], "/ai_suggest")
        finally:
            srv._current_server_session = saved_session
            srv._current_auth_user = saved_user
            srv._SERVER_AUDIT.clear()


class FabricCaTrustBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server_module()

    def _write_cert(self, path: Path, tag: str):
        path.write_text(f"-----BEGIN CERTIFICATE-----\n{tag}\n-----END CERTIFICATE-----\n", encoding="utf-8")

    def test_merges_root_and_leaf_into_bundle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            org_dir = Path(tmp)
            self._write_cert(org_dir / "ca-cert.pem", "ROOT-CA")
            self._write_cert(org_dir / "tls-cert.pem", "TLS-LEAF")
            bundle = self.server._resolve_fabric_ca_trust_bundle(org_dir)
            body = Path(bundle).read_text(encoding="utf-8")
            # Both certificates must be present so Python's ssl module has the
            # issuer for chain verification and Go / curl have the leaf too.
            self.assertIn("ROOT-CA", body)
            self.assertIn("TLS-LEAF", body)
            self.assertEqual(body.count("BEGIN CERTIFICATE"), 2)

    def test_falls_back_to_single_available_cert(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            org_dir = Path(tmp)
            self._write_cert(org_dir / "ca-cert.pem", "ROOT-ONLY")
            bundle = self.server._resolve_fabric_ca_trust_bundle(org_dir)
            self.assertTrue(Path(bundle).is_file())
            self.assertEqual(Path(bundle).name, "ca-cert.pem")

    def test_regenerates_bundle_when_inputs_change(self):
        import tempfile, time as _t
        with tempfile.TemporaryDirectory() as tmp:
            org_dir = Path(tmp)
            self._write_cert(org_dir / "ca-cert.pem", "ROOT-CA")
            self._write_cert(org_dir / "tls-cert.pem", "TLS-V1")
            bundle = Path(self.server._resolve_fabric_ca_trust_bundle(org_dir))
            self.assertIn("TLS-V1", bundle.read_text(encoding="utf-8"))
            # Rotate the leaf and bump its mtime so the cache is invalidated.
            _t.sleep(0.01)
            self._write_cert(org_dir / "tls-cert.pem", "TLS-V2")
            os.utime(org_dir / "tls-cert.pem", None)
            bundle2 = Path(self.server._resolve_fabric_ca_trust_bundle(org_dir))
            self.assertEqual(bundle, bundle2)
            self.assertIn("TLS-V2", bundle2.read_text(encoding="utf-8"))


class FabricCaRemoveFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server_module()

    def test_remove_falls_back_to_revoke_when_ca_refuses(self):
        """Error Code 56 from CA triggers revoke + disable fallback."""
        srv = self.server
        calls = []

        def fake_remove(cmd, env, cwd, timeout=120):
            calls.append(("remove", list(cmd)))
            raise RuntimeError("Error Code: 56 - Identity removal is disabled")

        def fake_admin_ctx(org):
            return ({"ca_name": "ca-org1", "ca_cert": "/tmp/trust.pem"}, {})

        saved_run = srv._run_local_command
        saved_ctx = srv._fabric_ca_admin_context
        try:
            srv._fabric_ca_admin_context = fake_admin_ctx

            def dispatch(cmd, env=None, cwd=None, timeout=120):
                verb = cmd[1] if len(cmd) > 1 else ""
                if verb == "identity" and "remove" in cmd:
                    return fake_remove(cmd, env, cwd, timeout)
                calls.append((verb, list(cmd)))

            srv._run_local_command = dispatch
            srv._fabric_ca_remove_identity(username="alice", org="org1")
        finally:
            srv._run_local_command = saved_run
            srv._fabric_ca_admin_context = saved_ctx

        verbs = [c[0] for c in calls]
        self.assertIn("remove", verbs)
        # After the remove failure the fallback must both revoke and modify.
        self.assertIn("revoke", verbs)
        self.assertIn("identity", verbs)  # fabric-ca-client identity modify
        modify_call = next(c for c in calls if c[0] == "identity")
        self.assertIn("modify", modify_call[1])
        self.assertIn("--maxenrollments", modify_call[1])
        self.assertIn("0", modify_call[1])

    def test_remove_no_fallback_for_unrelated_error(self):
        srv = self.server

        def boom(*_args, **_kwargs):
            raise RuntimeError("unexpected I/O failure")

        saved_run = srv._run_local_command
        saved_ctx = srv._fabric_ca_admin_context
        try:
            srv._fabric_ca_admin_context = lambda org: ({"ca_name": "ca-org1", "ca_cert": "/tmp/trust.pem"}, {})
            srv._run_local_command = boom
            with self.assertRaises(RuntimeError) as cm:
                srv._fabric_ca_remove_identity(username="bob", org="org1")
            self.assertIn("unexpected I/O failure", str(cm.exception))
        finally:
            srv._run_local_command = saved_run
            srv._fabric_ca_admin_context = saved_ctx

    def test_revoke_is_idempotent_on_known_terminal_states(self):
        srv = self.server
        for msg in (
            "Identity not found",
            "has no certificates",
            "certificate already revoked",
        ):
            def raise_msg(*_a, _m=msg, **_kw):
                raise RuntimeError(_m)
            saved_run = srv._run_local_command
            saved_ctx = srv._fabric_ca_admin_context
            try:
                srv._fabric_ca_admin_context = lambda org: ({"ca_name": "ca-org1", "ca_cert": "/tmp/trust.pem"}, {})
                srv._run_local_command = raise_msg
                # Must not raise.
                srv._fabric_ca_revoke_identity(username="alice", org="org1")
            finally:
                srv._run_local_command = saved_run
                srv._fabric_ca_admin_context = saved_ctx


class AgentServiceIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server_module()

    def test_unknown_role_rejected(self):
        srv = self.server
        with self.assertRaises(ValueError):
            srv._agent_eval_as_role("NotARole", "WhoAmI", [])

    def test_known_roles_include_mlservice(self):
        srv = self.server
        self.assertIn("MLService", srv._VALID_AGENT_ROLES)
        self.assertIn("SecurityService", srv._VALID_AGENT_ROLES)

    def test_eval_as_role_sends_role_header(self):
        """Verifies the X-Agent-Role header is injected into the agent request."""
        srv = self.server
        captured = {}

        class FakeResponse:
            status_code = 200
            ok = True
            def json(self):
                return {"ok": True, "result": {"clientID": "x509::CN=ml", "mspID": "Org1MSP"}}

        import requests as _req
        saved_post = _req.post
        try:
            def fake_post(url, headers=None, json=None, timeout=None):
                captured["url"] = url
                captured["headers"] = dict(headers or {})
                captured["json"] = json
                return FakeResponse()
            _req.post = fake_post
            out = srv._agent_eval_as_role("MLService", "WhoAmI", [])
        finally:
            _req.post = saved_post

        self.assertEqual(captured["headers"].get("X-Agent-Role"), "MLService")
        self.assertEqual(captured["json"]["function"], "WhoAmI")
        self.assertEqual(out.get("clientID"), "x509::CN=ml")


if __name__ == "__main__":
    unittest.main()
