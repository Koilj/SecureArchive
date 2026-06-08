"""Unit-test-only mock of the Kubo (IPFS) HTTP API.

This is NOT a real IPFS node:
  * no libp2p / bitswap / DHT
  * no UnixFS DAG - each payload is stored as a single opaque file
  * no garbage collection / reference graph

It only covers the endpoints server.py calls, and it emits CIDv0-shaped
("Qm...") identifiers computed as base58(multihash(sha256(payload))) so the
real CID validator in server.py still accepts them. For real integration
tests use tests/test_ipfs_real.py against actual `ipfs daemon` processes.
"""
import argparse
import hashlib
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# Bitcoin-style base58 alphabet (same as CIDv0 / multibase base58btc).
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode bytes as base58btc (no external deps)."""
    n = int.from_bytes(data, "big") if data else 0
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    # Preserve leading zero bytes as leading "1" characters.
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out or "1"


def _fake_cidv0(payload: bytes) -> str:
    """Deterministic CIDv0-shaped identifier (Qm... 46 chars).

    Not the same as real IPFS's UnixFS CID - the DAG encoding is different -
    but it satisfies `_IPFS_CIDV0_RE` in server.py and is stable across
    mock replicas, which is all unit tests need.
    """
    digest = hashlib.sha256(payload).digest()
    # Multihash envelope: code=sha2-256 (0x12), length=32 (0x20), then digest.
    multihash = bytes([0x12, 0x20]) + digest
    return _base58_encode(multihash)


def read_multipart_file(handler: BaseHTTPRequestHandler) -> tuple[str, bytes]:
    content_type = handler.headers.get("Content-Type", "")
    if "boundary=" not in content_type:
        raise ValueError("missing multipart boundary")
    boundary = content_type.split("boundary=", 1)[1].strip().strip('"')
    if not boundary:
        raise ValueError("empty multipart boundary")
    boundary_bytes = ("--" + boundary).encode("utf-8")
    body = handler.rfile.read(int(handler.headers.get("Content-Length", "0") or "0"))
    parts = body.split(boundary_bytes)
    for part in parts:
        chunk = part.strip()
        if not chunk or chunk == b"--":
            continue
        header_blob, sep, payload = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = header_blob.decode("utf-8", errors="ignore")
        if 'name="file"' not in headers:
            continue
        filename = "payload.bin"
        marker = 'filename="'
        if marker in headers:
            filename = headers.split(marker, 1)[1].split('"', 1)[0] or filename
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        if payload.endswith(b"--"):
            payload = payload[:-2]
        return filename, payload
    raise ValueError("multipart file field was not found")


class MockIpfsHandler(BaseHTTPRequestHandler):
    server_version = "MockIPFS/1.0"

    def log_message(self, fmt: str, *args):
        return

    @property
    def storage_dir(self) -> Path:
        return Path(self.server.storage_dir)  # type: ignore[attr-defined]

    @property
    def node_name(self) -> str:
        return str(self.server.node_name)  # type: ignore[attr-defined]

    def _json(self, payload: dict, status: int = HTTPStatus.OK):
        raw = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _bytes(self, payload: bytes, status: int = HTTPStatus.OK, content_type: str = "application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _file_path(self, cid: str) -> Path:
        safe_cid = "".join(ch for ch in cid if ch.isalnum() or ch in ("-", "_"))
        return self.storage_dir / safe_cid

    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/api/v0/version":
            self._json({"Version": "mock-ipfs-1.0", "Commit": self.node_name})
            return
        if parsed.path == "/api/v0/id":
            self._json({"ID": f"mock-{self.node_name}", "Addresses": [], "AgentVersion": "mock-ipfs/1.0", "Protocols": []})
            return
        if parsed.path == "/api/v0/stats/repo":
            total = 0
            count = 0
            for p in self.storage_dir.iterdir() if self.storage_dir.exists() else []:
                try:
                    total += p.stat().st_size
                    count += 1
                except Exception:
                    pass
            self._json({"RepoSize": total, "StorageMax": 5_000_000_000, "NumObjects": count, "RepoPath": str(self.storage_dir), "Version": "fs-repo@mock"})
            return
        if parsed.path == "/api/v0/add":
            try:
                filename, payload = read_multipart_file(self)
            except Exception as exc:
                self._json({"Message": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            cid = _fake_cidv0(payload)
            self._file_path(cid).write_bytes(payload)
            self._json({"Name": filename, "Hash": cid, "Size": str(len(payload))})
            return
        if parsed.path == "/api/v0/cat":
            cid = (params.get("arg") or [""])[0]
            file_path = self._file_path(cid)
            if not cid or not file_path.exists():
                self._json({"Message": "cid not found"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self._bytes(file_path.read_bytes())
            return
        if parsed.path == "/api/v0/pin/ls":
            cid = (params.get("arg") or [""])[0]
            if cid and self._file_path(cid).exists():
                self._json({"Keys": {cid: {"Type": "recursive"}}})
                return
            self._json({"Message": "not pinned"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/v0/pin/add":
            cid = (params.get("arg") or [""])[0]
            if cid and self._file_path(cid).exists():
                self._json({"Pins": [cid]})
                return
            self._json({"Message": "cid not found"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._json({"Message": f"unsupported endpoint: {parsed.path}"}, status=HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser(description="Run a tiny IPFS-compatible mock node for local e2e tests.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--node-name", default="")
    args = parser.parse_args()

    storage_dir = Path(args.data_dir)
    storage_dir.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer((args.host, args.port), MockIpfsHandler)
    server.storage_dir = str(storage_dir)  # type: ignore[attr-defined]
    server.node_name = args.node_name or f"mock-{args.port}"  # type: ignore[attr-defined]
    print(
        json.dumps(
            {
                "status": "listening",
                "host": args.host,
                "port": args.port,
                "data_dir": str(storage_dir),
                "node_name": server.node_name,
            },
            ensure_ascii=True,
        ),
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
