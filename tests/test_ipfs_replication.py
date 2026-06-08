import contextlib
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "server.py"
MOCK_IPFS_PATH = ROOT / "mock_ipfs_node.py"


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def mock_ipfs_nodes(count: int):
    processes = []
    temp_dirs = []
    urls = []
    try:
        for idx in range(count):
            port = _reserve_port()
            temp_dir = tempfile.TemporaryDirectory(prefix=f"mock-ipfs-{idx + 1}-")
            temp_dirs.append(temp_dir)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(MOCK_IPFS_PATH),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--data-dir",
                    temp_dir.name,
                    "--node-name",
                    f"node-{idx + 1}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            line = (proc.stdout.readline() if proc.stdout else "").strip()
            if proc.poll() is not None or '"status": "listening"' not in line:
                raise RuntimeError(f"mock ipfs node failed to start on port {port}: {line}")
            processes.append(proc)
            urls.append(f"http://127.0.0.1:{port}")
        yield urls
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            if proc.stdout:
                proc.stdout.close()
        for temp_dir in temp_dirs:
            temp_dir.cleanup()


def load_server_module(ipfs_urls: str, *, min_replicas: int = 2, target_replicas: int = 2):
    env_keys = {
        "AI_MODEL_DIR": "/tmp/securedata-missing-model",
        "AI_ENCODER_FILE": "/tmp/securedata-missing-model/encoder.pickle",
        "AI_THRESHOLDS_FILE": "/tmp/securedata-missing-model/thresholds.json",
        "IPFS_NODE_URLS": ipfs_urls,
        "IPFS_MIN_REPLICAS": str(min_replicas),
        "IPFS_TARGET_REPLICAS": str(target_replicas),
        "AUTO_SUGGEST": "0",
    }
    saved = {key: os.environ.get(key) for key in env_keys}
    module_name = f"server_test_{time.time_ns()}"
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


class IpfsReplicationTests(unittest.TestCase):
    def test_single_node_upload_is_degraded_but_not_rejected(self):
        with mock_ipfs_nodes(1) as urls:
            server = load_server_module(urls[0], min_replicas=2, target_replicas=2)

            status = server.replicate_bytes_to_ipfs(b"single-node-payload", filename="payload.enc", asset_id="asset_single")
            health = server.check_ipfs_health(timeout=1.0)

            self.assertEqual(status["healthy_replicas"], 1)
            self.assertEqual(status["required_replicas"], 2)
            self.assertTrue(status["degraded"])
            self.assertFalse(status["available"])
            self.assertFalse(server._ipfs_storage_available(status))
            self.assertIn("recommended minimum is 2", status["last_error"])
            self.assertFalse(health["ok"])
            self.assertIn("Configure at least 2 independent IPFS nodes.", health["detail"])

    def test_two_nodes_satisfy_replication_requirement(self):
        with mock_ipfs_nodes(2) as urls:
            server = load_server_module(",".join(urls), min_replicas=2, target_replicas=2)

            status = server.replicate_bytes_to_ipfs(b"two-node-payload", filename="payload.enc", asset_id="asset_dual")
            health = server.check_ipfs_health(timeout=1.0)

            self.assertEqual(status["healthy_replicas"], 2)
            self.assertEqual(status["required_replicas"], 2)
            self.assertFalse(status["degraded"])
            self.assertTrue(status["available"])
            self.assertEqual(status["last_error"], "")
            self.assertTrue(health["ok"])


if __name__ == "__main__":
    unittest.main()
