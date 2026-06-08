"""Real IPFS integration tests.

These tests require Kubo (`ipfs`) on PATH. They spin up two real Kubo daemons
in isolated temp repos on random ports, peer them, and exercise server.py's
replication + pinning logic end-to-end. If Kubo isn't installed they are
skipped cleanly so CI doesn't hard-fail.

Covers:
  * /add returns a real CIDv0 (Qm... 46 chars) that matches `_looks_like_ipfs_cid`
  * `replicate_bytes_to_ipfs` pins on every configured node
  * Two independent Kubo nodes return the same CID for the same payload
  * Pinned content survives `repo/gc`
  * `ensure_ipfs_replication` repairs a missing pin by re-adding from a healthy peer
  * `/health/ipfs` exposes repo size / disk pressure / pin counts
"""
import contextlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "server.py"
IPFS_BIN = shutil.which("ipfs")


# ---------------------------------------------------------------------------
# Real Kubo fixture
# ---------------------------------------------------------------------------
def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(cmd: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _kubo_init(repo_path: str, api_port: int, gw_port: int, sw_port: int) -> None:
    env = os.environ.copy()
    env["IPFS_PATH"] = repo_path
    _run([IPFS_BIN, "init", "--profile=server", "--empty-repo"], env=env)
    for key, val in [
        ("Addresses.API", f'"/ip4/127.0.0.1/tcp/{api_port}"'),
        ("Addresses.Gateway", f'"/ip4/127.0.0.1/tcp/{gw_port}"'),
        ("Addresses.Swarm", f'["/ip4/127.0.0.1/tcp/{sw_port}"]'),
        ("Addresses.Announce", "[]"),
        ("Addresses.NoAnnounce", "[]"),
        ("Swarm.DisableNatPortMap", "true"),
        ("Routing.Type", '"dhtclient"'),
        ("Import.CidVersion", "0"),
        ("Datastore.StorageMax", '"1GB"'),
    ]:
        _run([IPFS_BIN, "config", "--json", key, val], env=env)
    _run([IPFS_BIN, "bootstrap", "rm", "--all"], env=env)


def _wait_api(port: int, deadline: float) -> None:
    url = f"http://127.0.0.1:{port}/api/v0/id"
    while time.time() < deadline:
        try:
            r = requests.post(url, timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"kubo API at :{port} did not come up within deadline")


@contextlib.contextmanager
def real_kubo_nodes(count: int = 2):
    """Spin up `count` real, peered Kubo daemons; yield their API base URLs."""
    if not IPFS_BIN:
        raise unittest.SkipTest("kubo (ipfs) is not installed on PATH")

    tmp_dirs: list[str] = []
    procs: list[subprocess.Popen] = []
    api_urls: list[str] = []
    sw_ports: list[int] = []
    try:
        for idx in range(count):
            tmp = tempfile.mkdtemp(prefix=f"kubo-test-{idx}-")
            tmp_dirs.append(tmp)
            api_port = _reserve_port()
            gw_port = _reserve_port()
            sw_port = _reserve_port()
            sw_ports.append(sw_port)
            _kubo_init(tmp, api_port, gw_port, sw_port)
            env = os.environ.copy()
            env["IPFS_PATH"] = tmp
            # --offline would disable bitswap; we want bitswap between our own
            # two daemons, just no public DHT / bootstrap.
            proc = subprocess.Popen(
                [IPFS_BIN, "daemon", "--enable-gc"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(proc)
            api_urls.append(f"http://127.0.0.1:{api_port}")

        deadline = time.time() + 30
        for url in api_urls:
            _wait_api(int(url.rsplit(":", 1)[1]), deadline)

        if count >= 2:
            first_id = requests.post(api_urls[0] + "/api/v0/id", timeout=5).json()["ID"]
            first_addr = f"/ip4/127.0.0.1/tcp/{sw_ports[0]}/p2p/{first_id}"
            for i in range(1, count):
                try:
                    requests.post(
                        api_urls[i] + "/api/v0/swarm/connect",
                        params={"arg": first_addr},
                        timeout=5,
                    )
                except Exception:
                    pass

        yield api_urls
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# server.py fixture
# ---------------------------------------------------------------------------
def load_server_module(ipfs_urls: str, *, min_replicas: int = 2, target_replicas: int = 2):
    env_keys = {
        "AI_MODEL_DIR": "/tmp/securedata-missing-model",
        "AI_ENCODER_FILE": "/tmp/securedata-missing-model/encoder.pickle",
        "AI_THRESHOLDS_FILE": "/tmp/securedata-missing-model/thresholds.json",
        "IPFS_NODE_URLS": ipfs_urls,
        "IPFS_MIN_REPLICAS": str(min_replicas),
        "IPFS_TARGET_REPLICAS": str(target_replicas),
        "IPFS_STATUS_PATH": tempfile.NamedTemporaryFile(
            prefix="securedata-ipfs-real-status-",
            suffix=".json",
            delete=False,
        ).name,
        "AUTO_SUGGEST": "0",
    }
    saved = {key: os.environ.get(key) for key in env_keys}
    module_name = f"server_ipfs_real_{time.time_ns()}"
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@unittest.skipUnless(IPFS_BIN, "kubo (ipfs) binary not installed")
class RealIpfsIntegrationTests(unittest.TestCase):
    """End-to-end tests against two real Kubo daemons."""

    @classmethod
    def setUpClass(cls):
        cls._ctx = real_kubo_nodes(count=2)
        cls.urls = cls._ctx.__enter__()
        cls.server = load_server_module(",".join(cls.urls), min_replicas=2, target_replicas=2)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._ctx.__exit__(None, None, None)
        except Exception:
            pass

    # ----------------------------- helpers -----------------------------------
    def _cat(self, url: str, cid: str, *, timeout: float = 15.0) -> bytes:
        resp = requests.post(url + "/api/v0/cat", params={"arg": cid}, timeout=timeout)
        resp.raise_for_status()
        return resp.content

    def _pinned(self, url: str, cid: str) -> bool:
        resp = requests.post(
            url + "/api/v0/pin/ls",
            params={"arg": cid, "type": "recursive"},
            timeout=5,
        )
        if resp.status_code != 200:
            return False
        keys = (resp.json() or {}).get("Keys") or {}
        return isinstance(keys, dict) and cid in keys

    # ----------------------------- cases -------------------------------------
    def test_01_upload_returns_real_cidv0(self):
        """server.replicate_bytes_to_ipfs uploads to every node and returns a valid CID."""
        # random payload keeps the test idempotent across repeated runs (dedup does not hide failures)
        payload = os.urandom(1024) + b"|real-ipfs-test-01"
        status = self.server.replicate_bytes_to_ipfs(
            payload, filename="t1.enc", asset_id="asset_real_01"
        )
        self.assertTrue(self.server._looks_like_ipfs_cid(status["cid"]),
                        f"invalid CID shape: {status['cid']!r}")
        self.assertTrue(status["cid"].startswith("Qm"),
                        f"expected CIDv0 Qm... got {status['cid']}")
        self.assertEqual(status["healthy_replicas"], 2)
        self.assertEqual(status["required_replicas"], 2)
        self.assertFalse(status["degraded"])
        self.assertTrue(status["available"])
        self.assertEqual(status["last_error"], "")

        for url in self.urls:
            self.assertTrue(self._pinned(url, status["cid"]), f"not pinned on {url}")
            self.assertEqual(self._cat(url, status["cid"]), payload)

    def test_02_content_addressing_across_nodes(self):
        """Same payload → same CID on every independent daemon."""
        payload = b"content-addressed-across-nodes-" + os.urandom(32)
        cids = []
        for url in self.urls:
            resp = requests.post(
                url + "/api/v0/add",
                params={"pin": "true", "cid-version": "0"},
                files={"file": ("x.bin", payload)},
                timeout=30,
            )
            resp.raise_for_status()
            cids.append(resp.json()["Hash"])
        self.assertEqual(len(set(cids)), 1, f"CIDs differ between nodes: {cids}")
        self.assertTrue(cids[0].startswith("Qm"))

    def test_03_pin_survives_garbage_collection(self):
        """The whole point of pinning: `repo gc` must NOT evict pinned content."""
        payload = os.urandom(2048) + b"|gc-survival"
        status = self.server.replicate_bytes_to_ipfs(
            payload, filename="t3.enc", asset_id="asset_real_gc"
        )
        cid = status["cid"]

        for url in self.urls:
            gc_resp = requests.post(url + "/api/v0/repo/gc", timeout=30)
            self.assertLess(gc_resp.status_code, 500, f"gc failed: {gc_resp.text[:200]}")

        for url in self.urls:
            self.assertTrue(self._pinned(url, cid), f"pin disappeared on {url} after gc")
            self.assertEqual(self._cat(url, cid), payload, f"content gone on {url} after gc")

    def test_04_replication_repair_after_pin_drop(self):
        """ensure_ipfs_replication recovers a missing replica by re-adding from a healthy peer."""
        # Upload only to the first node.
        payload = os.urandom(4096) + b"|repair"
        resp = requests.post(
            self.urls[0] + "/api/v0/add",
            params={"pin": "true", "cid-version": "0"},
            files={"file": ("repair.bin", payload)},
            timeout=30,
        )
        resp.raise_for_status()
        cid = resp.json()["Hash"]
        self.assertTrue(cid.startswith("Qm"))

        # Sanity: second node starts without the pin.
        self.assertFalse(self._pinned(self.urls[1], cid))

        # Ask server.py to reconcile.
        status = self.server.ensure_ipfs_replication(cid, asset_ids=["asset_real_repair"])
        self.assertEqual(status["healthy_replicas"], 2, f"status={status}")

        # Second node must now be pinned + serve content.
        self.assertTrue(self._pinned(self.urls[1], cid))
        self.assertEqual(self._cat(self.urls[1], cid), payload)

    def test_05_health_surfaces_cluster_telemetry(self):
        """/health/ipfs returns per-node disk stats + cluster totals."""
        health = self.server.check_ipfs_health(timeout=5.0)
        self.assertTrue(health["ok"], f"health={health}")
        self.assertEqual(health["configured_nodes"], 2)
        self.assertEqual(health["healthy_nodes"], 2)
        self.assertIn("total_repo_size_bytes", health)
        self.assertIn("total_free_bytes", health)
        self.assertIn("total_pins", health)
        self.assertIn("disk_pressure", health)
        self.assertFalse(health["disk_pressure"])  # 1GB StorageMax, we've added <1MB

        for node in health["nodes"]:
            self.assertTrue(node["ok"], f"node unhealthy: {node}")
            self.assertIn("repo_size_bytes", node)
            self.assertIn("storage_max_bytes", node)
            self.assertGreater(node["storage_max_bytes"], 0)
            self.assertGreaterEqual(node["num_pins"], 0)

    def test_06_strict_cid_rejects_non_cid(self):
        """CID validator rejects obvious non-CID strings even when the env is permissive."""
        srv = self.server
        self.assertTrue(srv._looks_like_ipfs_cid("QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"))
        self.assertFalse(srv._looks_like_ipfs_cid("not-a-cid"))
        # Raw sha256 hex - the old mock output - is rejected.
        self.assertFalse(srv._looks_like_ipfs_cid("a" * 64))
        with self.assertRaises(RuntimeError):
            srv._validate_ipfs_cid("garbage", source="unit")

    def test_07_download_matches_upload_bytes(self):
        """Round-trip: replicate → cat_from_ipfs returns the exact same bytes."""
        payload = os.urandom(8192) + b"|roundtrip"
        status = self.server.replicate_bytes_to_ipfs(
            payload, filename="t7.enc", asset_id="asset_real_roundtrip"
        )
        got = self.server.cat_from_ipfs(status["cid"])
        self.assertEqual(got, payload)


if __name__ == "__main__":
    unittest.main()
