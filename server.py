import os
import re
import time
import threading
import json
import base64
import secrets
import subprocess
import unicodedata
import atexit
import hashlib
import hmac
import logging
import math
import requests
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, Response, session
from flask_cors import CORS
from cryptography import x509

from utils import format_model_input
from disp_sanitizer import sanitize_upload_metadata, sanitize_metadata_only, audit_record
from webauthn_utils import (
    b64url_encode,
    b64url_decode,
    verify_registration_response,
    verify_authentication_response,
)

log = logging.getLogger("securedata.server")


# DISP policy knobs
_MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))  # 25MB

_SIMPLE_CONTROL = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_SIMPLE_ZW_BIDI = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
_SIMPLE_WS = re.compile(r"\s+")


def _norm_simple_text(v: str, max_len: int, *, collapse: bool = True) -> str:
    s = "" if v is None else str(v)
    try:
        s = unicodedata.normalize("NFKC", s)
    except Exception:
        pass
    s = _SIMPLE_CONTROL.sub("", s)
    s = _SIMPLE_ZW_BIDI.sub("", s)
    if collapse:
        s = _SIMPLE_WS.sub(" ", s).strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


# Config
SECUREDATA_RUN_DIR = Path(os.getenv("SECUREDATA_RUN_DIR", str(Path.home() / ".securedata-run"))).expanduser()
_RUNTIME_SECRETS_PATH = Path(os.getenv("SECUREDATA_SECRETS_PATH", str(SECUREDATA_RUN_DIR / "secrets.json"))).expanduser()
_AUDIT_DIR = Path(os.getenv("SECUREDATA_AUDIT_DIR", str(SECUREDATA_RUN_DIR / "audit"))).expanduser()
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001/api/v0/add")
IPFS_CAT_URL = os.getenv("IPFS_CAT_URL", "http://127.0.0.1:5001/api/v0/cat")
IPFS_VERSION_URL = os.getenv("IPFS_VERSION_URL", "http://127.0.0.1:5001/api/v0/version")
IPFS_NODE_URLS = os.getenv("IPFS_NODE_URLS", "").strip()
IPFS_MIN_REPLICAS = max(2, int(os.getenv("IPFS_MIN_REPLICAS", "2")))
IPFS_TARGET_REPLICAS = max(IPFS_MIN_REPLICAS, int(os.getenv("IPFS_TARGET_REPLICAS", "3")))
IPFS_RECHECK_SECONDS = max(30, int(os.getenv("IPFS_RECHECK_SECONDS", "120")))
IPFS_REQUEST_TIMEOUT = max(3.0, float(os.getenv("IPFS_REQUEST_TIMEOUT", "20")))
IPFS_STATUS_PATH = Path(os.getenv("IPFS_STATUS_PATH", str(SECUREDATA_RUN_DIR / "ipfs-status.json"))).expanduser()
IPFS_CID_VERSION = os.getenv("IPFS_CID_VERSION", "0").strip() or "0"
IPFS_STRICT_CID = os.getenv("IPFS_STRICT_CID", "1").strip() not in ("0", "", "false", "no")
IPFS_REMOTE_PIN_ENDPOINT = os.getenv("IPFS_REMOTE_PIN_ENDPOINT", "").strip().rstrip("/")
IPFS_REMOTE_PIN_TOKEN = os.getenv("IPFS_REMOTE_PIN_TOKEN", "").strip()
IPFS_REMOTE_PIN_NAME_PREFIX = os.getenv("IPFS_REMOTE_PIN_NAME_PREFIX", "securedata-").strip()
WEBAUTHN_REAUTH_TTL_SECONDS = max(60, int(os.getenv("WEBAUTHN_REAUTH_TTL_SECONDS", "300")))


def _load_runtime_secrets() -> dict:
    try:
        if _RUNTIME_SECRETS_PATH.exists():
            data = json.loads(_RUNTIME_SECRETS_PATH.read_text("utf-8"))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if str(v)}
    except Exception as exc:
        log.warning("could not read runtime secrets from %s: %s", _RUNTIME_SECRETS_PATH, exc)
    return {}


def _save_runtime_secrets(data: dict) -> None:
    _RUNTIME_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _RUNTIME_SECRETS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    tmp.replace(_RUNTIME_SECRETS_PATH)
    try:
        _RUNTIME_SECRETS_PATH.chmod(0o600)
    except Exception:
        pass


_RUNTIME_SECRETS = _load_runtime_secrets()


def _runtime_secret(name: str, *, nbytes: int = 32) -> str:
    env_value = os.getenv(name, "").strip()
    if env_value:
        _RUNTIME_SECRETS[name] = env_value
        os.environ[name] = env_value
        _save_runtime_secrets(_RUNTIME_SECRETS)
        return env_value
    if name in _RUNTIME_SECRETS and str(_RUNTIME_SECRETS[name]).strip():
        value = str(_RUNTIME_SECRETS[name]).strip()
        os.environ[name] = value
        return value
    if os.getenv("SECUREDATA_REQUIRE_EXPLICIT_SECRETS", "0") == "1":
        raise RuntimeError(f"{name} is required; set it in the environment or create {_RUNTIME_SECRETS_PATH}")
    value = secrets.token_urlsafe(nbytes)
    _RUNTIME_SECRETS[name] = value
    os.environ[name] = value
    _save_runtime_secrets(_RUNTIME_SECRETS)
    log.warning("Generated persistent local secret %s in %s", name, _RUNTIME_SECRETS_PATH)
    return value


# ML agent now routes through the unified Fabric gateway (same URL as SecurityService)
# with X-Agent-Role: MLService header to select the MLService Fabric identity.
ML_AGENT_URL = os.getenv("ML_AGENT_URL", "")  # empty = use unified agent
ML_AGENT_TOKEN = os.getenv("ML_AGENT_TOKEN", "")

# ============================
# Auto-suggest daemon (polling)
# ============================
AUTO_SUGGEST = os.getenv("AUTO_SUGGEST", "0") == "1"
AUTO_SUGGEST_INTERVAL = float(os.getenv("AUTO_SUGGEST_INTERVAL", "10"))
AUTO_SUGGEST_MIN_CONF = float(os.getenv("AUTO_SUGGEST_MIN_CONF", "80.0"))

def _ml_agent_base_url() -> str:
    if ML_AGENT_URL:
        return ML_AGENT_URL.rstrip("/")
    # Fall through to unified agent (same URL as SecurityService)
    return os.getenv("SECURITY_AGENT_URL", "http://127.0.0.1:8090").rstrip("/")

def _ml_headers():
    headers = {"Content-Type": "application/json", "X-Agent-Role": "MLService"}
    token = ML_AGENT_TOKEN or os.getenv("SECURITY_AGENT_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def ml_eval(function: str, args: list[str]):
    url = _ml_agent_base_url() + "/eval"
    r = requests.post(url, headers=_ml_headers(), json={"function": function, "args": args}, timeout=10)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("error") or f"ml_eval failed: {data}")
    return data.get("result")

def ml_submit(function: str, args: list[str]):
    url = _ml_agent_base_url() + "/submit"
    r = requests.post(url, headers=_ml_headers(), json={"function": function, "args": args}, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("error") or f"ml_submit failed: {data}")
    return data.get("result")

def _strip_asset_prefix(asset_id: str) -> str:
    if asset_id.startswith("asset_"):
        return asset_id[len("asset_"):]
    return asset_id

def _should_suggest(a: dict) -> bool:
    cat = (a.get("category") or "").strip().lower()
    if cat not in ("", "unverified", "unknown"):
        return False
    if (a.get("suggestedCategory") or "").strip():
        return False
    return True

def _is_actionable_ai_category(value: str) -> bool:
    label = _norm_simple_text(value, 64, collapse=True).strip().lower()
    if not label:
        return False
    return label not in {"unverified", "unknown", "unclassified", "error"}

def _normalize_ai_confidence(value) -> float | None:
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(conf):
        return None
    if conf < 0 or conf > 100:
        return None
    return conf


def _ai_suggestion_meets_threshold(suggested: str, confidence: float | None) -> bool:
    if not _is_actionable_ai_category(suggested):
        return False
    if confidence is None:
        return False
    return float(confidence) >= AUTO_SUGGEST_MIN_CONF


def auto_suggest_once():
    try:
        assets = ml_eval("GetAllAssetsPublic", []) or []
    except Exception as e:
        log.warning("AI_AUTO: GetAllAssetsPublic failed: %s", e)
        return

    for a in assets:
        try:
            if not isinstance(a, dict) or not _should_suggest(a):
                continue

            asset_id_chain = a.get("assetID") or a.get("id") or ""
            asset_id = _strip_asset_prefix(asset_id_chain)
            if not asset_id:
                continue

            meta = a.get("metadata") or {}
            meta_authors = ""
            if isinstance(meta, dict):
                authors_val = meta.get("authors", "")
                if isinstance(authors_val, list):
                    meta_authors = ", ".join(str(item) for item in authors_val if str(item).strip())
                else:
                    meta_authors = str(authors_val or "")
            payload = {
                "asset_id": asset_id,
                "metadata": {
                    "title": meta.get("title", "") if isinstance(meta, dict) else "",
                    "description": a.get("description", "") or "",
                    "author": meta_authors,
                    "department": (meta.get("discipline", "") if isinstance(meta, dict) else ""),
                    "keywords": (meta.get("keywords", []) if isinstance(meta, dict) else []),
                },
            }

            suggested, conf = predict_category_and_confidence(payload["metadata"])
            if not suggested or conf is None:
                continue
            if not _is_actionable_ai_category(suggested):
                continue
            if conf < AUTO_SUGGEST_MIN_CONF:
                log.info("AI_AUTO: skip %s conf=%.2f < %.2f", asset_id, conf, AUTO_SUGGEST_MIN_CONF)
                continue

            try:
                ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf:.2f}", "auto-ai"])
            except Exception:
                ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf:.2f}"])

            log.info("AI_AUTO: suggested asset=%s -> %s conf=%.2f", asset_id, suggested, conf)
        except Exception as e:
            log.warning("AI_AUTO: failed on asset=%s: %s", a.get("assetID"), e)

def auto_suggest_loop():
    time.sleep(0.5)
    log.info("AI_AUTO: enabled interval=%ss min_conf=%s", AUTO_SUGGEST_INTERVAL, AUTO_SUGGEST_MIN_CONF)
    while True:
        auto_suggest_once()
        time.sleep(AUTO_SUGGEST_INTERVAL)

def start_auto_suggest_if_enabled():
    if not AUTO_SUGGEST:
        return
    t = threading.Thread(target=auto_suggest_loop, daemon=True)
    t.start()

ALLOWED_EXTENSIONS = {"pdf", "csv", "json", "txt", "xlsx", "docx", "enc"}


# -----------------------------
# AI SERVICE (external microservice)
# -----------------------------
AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://127.0.0.1:8100")
AI_SERVICE_TIMEOUT = float(os.getenv("AI_SERVICE_TIMEOUT", "15"))
MODEL_DIR = os.getenv("AI_MODEL_DIR", "scibert_multilabel_v3")

_ai_service_available = False

# How aggressively to retry the AI health probe. SciBERT needs ~15-30s to load,
# so when server.py auto-starts the AI service we keep probing in the
# background until the model is ready (or the retry budget is exhausted).
AI_HEALTH_MAX_ATTEMPTS = int(os.getenv("AI_HEALTH_MAX_ATTEMPTS", "20"))
AI_HEALTH_INITIAL_DELAY = float(os.getenv("AI_HEALTH_INITIAL_DELAY", "1.0"))
AI_HEALTH_MAX_DELAY = float(os.getenv("AI_HEALTH_MAX_DELAY", "8.0"))


def _probe_ai_service_once(timeout: float = 3.0) -> tuple[bool, str]:
    try:
        r = requests.get(AI_SERVICE_URL.rstrip("/") + "/health", timeout=timeout)
        data = r.json()
        if bool(data.get("ok") and data.get("model_loaded")):
            return True, ""
        return False, "model not loaded"
    except Exception as exc:
        return False, str(exc)


def _check_ai_service(*, attempts: int = 1, initial_delay: float = 1.0, max_delay: float = 8.0) -> bool:
    """
    Probe the AI service with exponential backoff. Returns True on success.
    Sets module-level `_ai_service_available` flag.
    """
    global _ai_service_available
    delay = max(0.1, float(initial_delay))
    last_err = ""
    for attempt in range(1, max(1, attempts) + 1):
        ok, err = _probe_ai_service_once()
        if ok:
            _ai_service_available = True
            log.info("AI service is available at %s", AI_SERVICE_URL)
            return True
        last_err = err
        if attempt < attempts:
            log.info(
                "AI service not ready (attempt %d/%d): %s; retrying in %.1fs",
                attempt, attempts, err, delay,
            )
            time.sleep(delay)
            delay = min(max_delay, delay * 2.0)
    _ai_service_available = False
    log.warning("AI service at %s is not available: %s", AI_SERVICE_URL, last_err)
    return False

def build_ai_text(title: str, authors: str, abstract: str, keywords="") -> str:
    return format_model_input(title=title, authors=authors, abstract=abstract, keywords=keywords)

def predict_category_and_confidence(text_or_features, top_k: int = 0):
    """
    Multilabel inference via AI service.
    Возвращает:
      - suggested_label: str
      - confidence_pct: float | None
    Опционально: top_k>0 => ещё вернём список топ-K (label, conf)
    """
    if not _ai_service_available:
        if top_k > 0:
            return "Unclassified", None, []
        return "Unclassified", None

    payload = {"top_k": top_k}
    if isinstance(text_or_features, str):
        payload["text"] = text_or_features
    elif isinstance(text_or_features, dict):
        payload["features"] = text_or_features
    else:
        payload["text"] = str(text_or_features) if text_or_features else ""

    try:
        r = requests.post(
            AI_SERVICE_URL.rstrip("/") + "/predict",
            json=payload,
            timeout=AI_SERVICE_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        suggested = data.get("suggested_label", "Unclassified")
        confidence = data.get("confidence")
        if top_k > 0:
            return str(suggested), confidence, data.get("top_k", [])
        return str(suggested), confidence
    except Exception as e:
        log.error("AI Service Error: %s", e)
        if top_k > 0:
            return "Error", 0.0, []
        return "Error", 0.0


# NOTE: the AI health probe is kicked off from __main__ via
# _probe_ai_service_in_background(); we deliberately do NOT probe at import
# time so that `import server` during tests stays cheap and quiet.


# -----------------------------
# IPFS helpers
# -----------------------------
def _derive_ipfs_base_url(raw: str) -> str:
    text = str(raw or "").strip().rstrip("/")
    if not text:
        return ""
    marker = "/api/v0"
    pos = text.find(marker)
    if pos >= 0:
        return text[:pos]
    return text


def _default_ipfs_base_url() -> str:
    for candidate in (IPFS_API_URL, IPFS_CAT_URL, IPFS_VERSION_URL):
        base = _derive_ipfs_base_url(candidate)
        if base:
            return base
    return "http://127.0.0.1:5001"


def _parse_ipfs_nodes() -> list[dict]:
    raw_nodes = [part.strip() for part in IPFS_NODE_URLS.split(",") if part.strip()]
    if not raw_nodes:
        raw_nodes = [_default_ipfs_base_url()]
    out: list[dict] = []
    seen: set[str] = set()
    for idx, raw in enumerate(raw_nodes, start=1):
        base = _derive_ipfs_base_url(raw)
        if not base or base in seen:
            continue
        seen.add(base)
        parsed = urlparse(base)
        label = parsed.netloc or parsed.path or f"node-{idx}"
        out.append(
            {
                "id": _norm_simple_text(label, 128, collapse=True) or f"node-{idx}",
                "base_url": base.rstrip("/"),
                "api_url": base.rstrip("/") + "/api/v0",
            }
        )
    return out


IPFS_NODES = _parse_ipfs_nodes()
_IPFS_STATUS_LOCK = threading.Lock()
_IPFS_STATUS_CACHE: dict[str, dict] = {}


def _load_ipfs_status_cache():
    global _IPFS_STATUS_CACHE
    try:
        if IPFS_STATUS_PATH.exists():
            raw = json.loads(IPFS_STATUS_PATH.read_text("utf-8"))
            if isinstance(raw, dict):
                _IPFS_STATUS_CACHE = raw
    except Exception as exc:
        app.logger.warning("failed to load ipfs status cache: %s", exc)
        _IPFS_STATUS_CACHE = {}


def _save_ipfs_status_cache():
    try:
        IPFS_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = IPFS_STATUS_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(_IPFS_STATUS_CACHE, fh, ensure_ascii=True, indent=2, sort_keys=True)
        tmp.replace(IPFS_STATUS_PATH)
    except Exception as exc:
        app.logger.warning("failed to persist ipfs status cache: %s", exc)


def _ipfs_endpoint(node: dict, path: str) -> str:
    return node["api_url"].rstrip("/") + "/" + path.lstrip("/")


def _ipfs_request(node: dict, path: str, *, timeout: float | None = None, files=None, params=None):
    return requests.post(
        _ipfs_endpoint(node, path),
        files=files,
        params=params or {},
        timeout=timeout or IPFS_REQUEST_TIMEOUT,
    )


# CIDv0 is base58-encoded sha256-multihash: "Qm" + 44 base58 chars (46 total).
# CIDv1 is multibase-prefixed; Kubo's default multibase is base32 (lowercase "b...").
_IPFS_CIDV0_RE = re.compile(r"^Qm[1-9A-HJ-NP-Za-km-z]{44}$")
_IPFS_CIDV1_RE = re.compile(r"^[bBfFkKuUzZ][A-Za-z0-9+=_\-]{20,127}$")


def _looks_like_ipfs_cid(text: str) -> bool:
    """True if `text` looks like a valid IPFS CID (v0 Qm... or v1 multibase)."""
    s = (text or "").strip()
    if not s:
        return False
    return bool(_IPFS_CIDV0_RE.match(s) or _IPFS_CIDV1_RE.match(s))


def _validate_ipfs_cid(cid: str, *, source: str = "IPFS node") -> str:
    """Normalise + optionally enforce real-CID shape. Raises on blatant garbage."""
    cid = _norm_simple_text(cid, 256, collapse=False)
    if not cid:
        raise RuntimeError(f"{source}: empty CID")
    if IPFS_STRICT_CID and not _looks_like_ipfs_cid(cid):
        raise RuntimeError(
            f"{source}: returned value {cid!r} is not a valid IPFS CID "
            f"(expected CIDv0 'Qm…' or CIDv1 multibase). "
            f"Set IPFS_STRICT_CID=0 to bypass (not recommended in production)."
        )
    return cid


def _ipfs_add_bytes(node: dict, file_bytes: bytes, filename: str) -> str:
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    params = {"pin": "true", "cid-version": IPFS_CID_VERSION}
    if IPFS_CID_VERSION != "0":
        # CIDv1 uploads benefit from raw-leaves for smaller DAGs and better dedup.
        params["raw-leaves"] = "true"
    resp = _ipfs_request(node, "add", files=files, params=params)
    if resp.status_code != 200:
        raise RuntimeError(f"{node['id']}: /add returned {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return _validate_ipfs_cid(data.get("Hash", ""), source=f"{node['id']}: /add")


def _ipfs_cat(node: dict, cid: str) -> bytes:
    resp = _ipfs_request(node, "cat", params={"arg": cid})
    if resp.status_code != 200:
        raise RuntimeError(f"{node['id']}: /cat returned {resp.status_code}: {resp.text[:200]}")
    return resp.content


def _ipfs_pin_ls(node: dict, cid: str) -> bool:
    resp = _ipfs_request(node, "pin/ls", params={"arg": cid, "type": "recursive"})
    if resp.status_code == 200:
        data = resp.json()
        keys = data.get("Keys") if isinstance(data, dict) else None
        return isinstance(keys, dict) and cid in keys
    if resp.status_code in {400, 404, 500}:
        return False
    raise RuntimeError(f"{node['id']}: /pin/ls returned {resp.status_code}: {resp.text[:200]}")


def _ipfs_pin_add(node: dict, cid: str) -> bool:
    resp = _ipfs_request(node, "pin/add", params={"arg": cid})
    if resp.status_code == 200:
        return True
    if resp.status_code in {400, 404, 500}:
        return False
    raise RuntimeError(f"{node['id']}: /pin/add returned {resp.status_code}: {resp.text[:200]}")


def _ipfs_node_health(node: dict, *, timeout: float = 5.0) -> dict:
    try:
        resp = _ipfs_request(node, "version", timeout=timeout)
        text = (resp.text or "").strip()
        if resp.status_code != 200:
            return {
                "id": node["id"],
                "ok": False,
                "status": resp.status_code,
                "detail": text[:200] or f"HTTP {resp.status_code}",
            }
        payload = resp.json()
        version = _norm_simple_text(payload.get("Version", ""), 64)
        commit = _norm_simple_text(payload.get("Commit", ""), 64)
        detail = "IPFS reachable"
        if version and commit:
            detail = f"Version {version} ({commit})"
        elif version:
            detail = f"Version {version}"
        elif text:
            detail = text[:160]

        # Repo stats: disk pressure telemetry. `pin/add` / `add` will start
        # failing once RepoSize >= StorageMax, so surfacing it here makes the
        # dashboard actionable before replication silently degrades.
        repo_size = 0
        storage_max = 0
        num_objects = 0
        num_pins = 0
        try:
            stats_resp = _ipfs_request(node, "stats/repo", timeout=timeout)
            if stats_resp.status_code == 200:
                stats_payload = stats_resp.json() or {}
                repo_size = int(stats_payload.get("RepoSize", 0) or 0)
                storage_max = int(stats_payload.get("StorageMax", 0) or 0)
                num_objects = int(stats_payload.get("NumObjects", 0) or 0)
        except Exception:
            # stats/repo is optional; don't fail health just because it's missing.
            pass
        try:
            pins_resp = _ipfs_request(node, "pin/ls", params={"type": "recursive", "quiet": "true"}, timeout=timeout)
            if pins_resp.status_code == 200:
                keys = (pins_resp.json() or {}).get("Keys") or {}
                if isinstance(keys, dict):
                    num_pins = len(keys)
        except Exception:
            pass

        free_bytes = max(0, storage_max - repo_size) if storage_max else 0
        # "disk_pressure" is true when we're within 10% of StorageMax - the
        # default GC will start culling unpinned blocks, and new pins can fail.
        disk_pressure = bool(storage_max and repo_size >= int(storage_max * 0.9))

        return {
            "id": node["id"],
            "ok": True,
            "status": resp.status_code,
            "version": version,
            "commit": commit,
            "detail": detail,
            "repo_size_bytes": repo_size,
            "storage_max_bytes": storage_max,
            "free_bytes": free_bytes,
            "num_objects": num_objects,
            "num_pins": num_pins,
            "disk_pressure": disk_pressure,
        }
    except Exception as exc:
        return {"id": node["id"], "ok": False, "status": 0, "detail": str(exc)}


# -----------------------------
# Remote pinning (optional, IPFS Pinning Service API)
# -----------------------------
# The Pinning Service API is the cross-vendor standard: web3.storage,
# filebase, pinata and others expose the same POST /pins contract. When
# IPFS_REMOTE_PIN_ENDPOINT + IPFS_REMOTE_PIN_TOKEN are configured, each
# successful local pin is also mirrored there so the content survives a
# total loss of the local Kubo cluster.
def _remote_pin_enabled() -> bool:
    return bool(IPFS_REMOTE_PIN_ENDPOINT and IPFS_REMOTE_PIN_TOKEN)


def _remote_pin_headers() -> dict:
    return {
        "Authorization": f"Bearer {IPFS_REMOTE_PIN_TOKEN}",
        "Content-Type": "application/json",
    }


def _remote_pin_add(cid: str, *, name: str = "") -> dict:
    """POST /pins to the configured pinning service; returns status dict.

    Silently no-ops when the service isn't configured. Never raises - we log
    the error and keep going, since the local cluster is still the source of
    truth.
    """
    if not _remote_pin_enabled():
        return {"enabled": False}
    try:
        body = {"cid": cid, "name": (name or f"{IPFS_REMOTE_PIN_NAME_PREFIX}{cid}")[:255]}
        resp = requests.post(
            f"{IPFS_REMOTE_PIN_ENDPOINT}/pins",
            headers=_remote_pin_headers(),
            json=body,
            timeout=max(5.0, IPFS_REQUEST_TIMEOUT),
        )
        if resp.status_code in (200, 201, 202):
            return {"enabled": True, "ok": True, "status": resp.status_code}
        # Most services return 409 if the pin already exists - treat as success.
        if resp.status_code == 409:
            return {"enabled": True, "ok": True, "status": 409, "detail": "already pinned"}
        app.logger.warning("remote pin %s failed: HTTP %s %s", cid, resp.status_code, resp.text[:200])
        return {"enabled": True, "ok": False, "status": resp.status_code, "detail": resp.text[:200]}
    except Exception as exc:
        app.logger.warning("remote pin %s errored: %s", cid, exc)
        return {"enabled": True, "ok": False, "status": 0, "detail": str(exc)}


def _merge_ipfs_status_record(cid: str, updates: dict | None = None) -> dict:
    with _IPFS_STATUS_LOCK:
        current = dict(_IPFS_STATUS_CACHE.get(cid) or {})
        if updates:
            for key, value in updates.items():
                if key == "asset_ids":
                    prev = current.get("asset_ids") or []
                    merged = sorted({str(item) for item in (prev + list(value or [])) if str(item).strip()})
                    current["asset_ids"] = merged
                else:
                    current[key] = value
        current["cid"] = cid
        _IPFS_STATUS_CACHE[cid] = current
        _save_ipfs_status_cache()
        return dict(current)


def _ipfs_status_snapshot(cid: str) -> dict:
    with _IPFS_STATUS_LOCK:
        return dict(_IPFS_STATUS_CACHE.get(cid) or {})


def _status_from_replica_rows(cid: str, rows: list[dict], *, asset_ids: list[str] | None = None, error: str = "") -> dict:
    healthy = sum(1 for row in rows if row.get("healthy"))
    record = {
        "cid": cid,
        "healthy_replicas": healthy,
        "required_replicas": IPFS_MIN_REPLICAS,
        "target_replicas": min(max(1, IPFS_TARGET_REPLICAS), max(1, len(IPFS_NODES))),
        "replicas": rows,
        "degraded": healthy < IPFS_MIN_REPLICAS,
        "available": healthy >= IPFS_MIN_REPLICAS,
        "last_checked_at": _utc_now_iso(),
        "last_error": _norm_simple_text(error, 512, collapse=True),
        "asset_ids": asset_ids or [],
    }
    return _merge_ipfs_status_record(cid, record)


def _ensure_ipfs_nodes_configured():
    if not IPFS_NODES:
        raise RuntimeError("no IPFS nodes are configured")


def replicate_bytes_to_ipfs(file_bytes: bytes, filename: str = "payload.enc", *, asset_id: str = "") -> dict:
    _ensure_ipfs_nodes_configured()
    cid = ""
    replicas: list[dict] = []
    for node in IPFS_NODES:
        try:
            node_cid = _ipfs_add_bytes(node, file_bytes, filename)
            if not cid:
                cid = node_cid
            elif node_cid != cid:
                raise RuntimeError(f"CID mismatch: expected {cid}, got {node_cid}")
            replicas.append({"node_id": node["id"], "healthy": True, "detail": "ciphertext pinned", "verified_at": _utc_now_iso()})
        except Exception as exc:
            replicas.append({"node_id": node["id"], "healthy": False, "detail": str(exc), "verified_at": _utc_now_iso()})
    if not cid:
        raise RuntimeError("no IPFS node accepted the ciphertext")
    healthy_replicas = sum(1 for row in replicas if row.get("healthy"))
    shortfall = ""
    if healthy_replicas < IPFS_MIN_REPLICAS:
        if len(IPFS_NODES) < IPFS_MIN_REPLICAS:
            shortfall = (
                f"stored on {healthy_replicas} replica(s), but only {len(IPFS_NODES)} IPFS node(s) are configured; "
                f"recommended minimum is {IPFS_MIN_REPLICAS}"
            )
        else:
            shortfall = (
                f"ciphertext stored on only {healthy_replicas} replica(s); "
                f"minimum required is {IPFS_MIN_REPLICAS}"
            )
    # Best-effort mirror to an external pinning service (when configured). The
    # local cluster is still the source of truth; remote failures are warnings.
    remote_pin = _remote_pin_add(cid, name=f"{IPFS_REMOTE_PIN_NAME_PREFIX}{asset_id or cid}") if _remote_pin_enabled() else {"enabled": False}
    extra: dict = {}
    if remote_pin.get("enabled"):
        extra["remote_pin"] = remote_pin
    status = _status_from_replica_rows(
        cid,
        replicas,
        asset_ids=[asset_id] if asset_id else [],
        error=shortfall,
    )
    if extra:
        status = _merge_ipfs_status_record(cid, extra)
    return status


def _ipfs_storage_available(status: dict) -> bool:
    if not isinstance(status, dict):
        return False
    if bool(status.get("available")):
        return True
    try:
        return int(status.get("healthy_replicas") or 0) >= int(status.get("required_replicas") or IPFS_MIN_REPLICAS)
    except Exception:
        return False


def ensure_ipfs_replication(cid: str, *, asset_ids: list[str] | None = None) -> dict:
    cid = _validate_ipfs_cid(cid, source="replication input")
    replicas: list[dict] = []
    healthy_nodes: list[dict] = []
    missing_nodes: list[dict] = []
    for node in IPFS_NODES:
        try:
            pinned = _ipfs_pin_ls(node, cid)
            row = {
                "node_id": node["id"],
                "healthy": bool(pinned),
                "detail": "pinned" if pinned else "missing",
                "verified_at": _utc_now_iso(),
            }
            replicas.append(row)
            if pinned:
                healthy_nodes.append(node)
            else:
                missing_nodes.append(node)
        except Exception as exc:
            replicas.append({"node_id": node["id"], "healthy": False, "detail": str(exc), "verified_at": _utc_now_iso()})
            missing_nodes.append(node)
    source_bytes = None
    if healthy_nodes:
        try:
            source_bytes = _ipfs_cat(healthy_nodes[0], cid)
        except Exception as exc:
            app.logger.warning("failed to read healthy cid %s from %s: %s", cid, healthy_nodes[0]["id"], exc)
    if source_bytes:
        for node in missing_nodes:
            try:
                node_cid = _ipfs_add_bytes(node, source_bytes, f"{cid}.enc")
                if node_cid != cid:
                    raise RuntimeError(f"CID mismatch after repair: expected {cid}, got {node_cid}")
                for row in replicas:
                    if row.get("node_id") == node["id"]:
                        row["healthy"] = True
                        row["detail"] = "re-pinned from healthy replica"
                        row["verified_at"] = _utc_now_iso()
                        break
            except Exception as exc:
                for row in replicas:
                    if row.get("node_id") == node["id"]:
                        row["healthy"] = False
                        row["detail"] = str(exc)
                        row["verified_at"] = _utc_now_iso()
                        break
    else:
        for node in missing_nodes:
            try:
                if _ipfs_pin_add(node, cid):
                    for row in replicas:
                        if row.get("node_id") == node["id"]:
                            row["healthy"] = True
                            row["detail"] = "pinned by CID fetch"
                            row["verified_at"] = _utc_now_iso()
                            break
            except Exception as exc:
                for row in replicas:
                    if row.get("node_id") == node["id"]:
                        row["detail"] = str(exc)
                        row["verified_at"] = _utc_now_iso()
                        break
    return _status_from_replica_rows(cid, replicas, asset_ids=asset_ids or [])


def cat_from_ipfs(cid: str) -> bytes:
    cid = _validate_ipfs_cid(cid, source="download input")
    preferred: list[str] = []
    cached = _ipfs_status_snapshot(cid)
    for row in cached.get("replicas") or []:
        if row.get("healthy"):
            preferred.append(str(row.get("node_id") or ""))
    ordered = []
    seen: set[str] = set()
    for node_id in preferred:
        for node in IPFS_NODES:
            if node["id"] == node_id and node_id not in seen:
                ordered.append(node)
                seen.add(node_id)
    for node in IPFS_NODES:
        if node["id"] not in seen:
            ordered.append(node)
            seen.add(node["id"])
    last_error = "cid not available on configured IPFS nodes"
    for node in ordered:
        try:
            data = _ipfs_cat(node, cid)
            _status_from_replica_rows(
                cid,
                [{"node_id": item["id"], "healthy": item["id"] == node["id"], "detail": "download source" if item["id"] == node["id"] else "not checked", "verified_at": _utc_now_iso()} for item in IPFS_NODES],
                asset_ids=_ipfs_status_snapshot(cid).get("asset_ids") or [],
            )
            return data
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(last_error)


def check_ipfs_health(timeout: float = 5.0) -> dict:
    nodes = [_ipfs_node_health(node, timeout=timeout) for node in IPFS_NODES]
    healthy_nodes = [item for item in nodes if item.get("ok")]
    configured_ok = len(IPFS_NODES) >= IPFS_MIN_REPLICAS
    ok = configured_ok and len(healthy_nodes) >= IPFS_MIN_REPLICAS
    detail = (
        f"{len(healthy_nodes)}/{len(IPFS_NODES)} nodes healthy; "
        f"minimum required replicas: {IPFS_MIN_REPLICAS}"
    )
    if not configured_ok:
        detail = f"{detail}. Configure at least {IPFS_MIN_REPLICAS} independent IPFS nodes."

    # Cluster-level telemetry: totals across every node we actually talked to.
    total_repo_size = sum(int(n.get("repo_size_bytes", 0) or 0) for n in nodes)
    total_free = sum(int(n.get("free_bytes", 0) or 0) for n in nodes)
    total_storage_max = sum(int(n.get("storage_max_bytes", 0) or 0) for n in nodes)
    total_pins = sum(int(n.get("num_pins", 0) or 0) for n in nodes)
    disk_pressure = any(bool(n.get("disk_pressure")) for n in nodes)
    if disk_pressure:
        detail = f"{detail}. WARNING: at least one node is near StorageMax - pins will start failing."

    return {
        "ok": ok,
        "status": 200 if ok else 503,
        "detail": detail,
        "required_replicas": IPFS_MIN_REPLICAS,
        "target_replicas": IPFS_TARGET_REPLICAS,
        "configured_nodes": len(IPFS_NODES),
        "healthy_nodes": len(healthy_nodes),
        "nodes": nodes,
        "total_repo_size_bytes": total_repo_size,
        "total_free_bytes": total_free,
        "total_storage_max_bytes": total_storage_max,
        "total_pins": total_pins,
        "disk_pressure": disk_pressure,
        "remote_pin_enabled": _remote_pin_enabled(),
    }


def _all_assets_with_cids() -> list[dict]:
    result = _security_agent_eval("GetAllAssetsPublic", [])
    if not isinstance(result, list):
        return []
    out = []
    for item in result:
        if not isinstance(item, dict):
            continue
        cid = _norm_simple_text(item.get("cidHash") or item.get("CIDHash") or "", 256, collapse=False)
        asset_id = _norm_simple_text(item.get("id") or item.get("assetID") or item.get("ID") or "", 128, collapse=False)
        if cid:
            out.append({"cid": cid, "asset_id": asset_id})
    return out


def ipfs_repair_once():
    assets = _all_assets_with_cids()
    grouped: dict[str, list[str]] = {}
    for item in assets:
        grouped.setdefault(item["cid"], [])
        if item["asset_id"]:
            grouped[item["cid"]].append(item["asset_id"])
    for cid, asset_ids in grouped.items():
        try:
            status = ensure_ipfs_replication(cid, asset_ids=asset_ids)
            if status.get("degraded") or status.get("last_error"):
                _append_jsonl_audit("ipfs-repair", {
                    "cid": cid,
                    "asset_ids": asset_ids,
                    "healthy_replicas": status.get("healthy_replicas"),
                    "required_replicas": status.get("required_replicas"),
                    "degraded": status.get("degraded"),
                    "last_error": status.get("last_error", ""),
                })
        except Exception as exc:
            _merge_ipfs_status_record(
                cid,
                {
                    "cid": cid,
                    "last_checked_at": _utc_now_iso(),
                    "last_error": _norm_simple_text(str(exc), 512, collapse=True),
                    "asset_ids": asset_ids,
                },
            )
            _append_jsonl_audit("ipfs-repair", {
                "cid": cid,
                "asset_ids": asset_ids,
                "degraded": True,
                "last_error": _norm_simple_text(str(exc), 512, collapse=True),
            })


def ipfs_repair_loop():
    time.sleep(2.0)
    while True:
        try:
            ipfs_repair_once()
        except Exception as exc:
            app.logger.warning("ipfs replication loop failed: %s", exc)
        time.sleep(IPFS_RECHECK_SECONDS)


def start_ipfs_replication_monitor():
    _load_ipfs_status_cache()
    thread = threading.Thread(target=ipfs_repair_loop, daemon=True)
    thread.start()


# -----------------------------
# Validation helpers
# -----------------------------
def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    name = filename.lower()
    if name.endswith(".enc"):
        name = name[:-4]
    if "." not in name:
        return False
    ext = name.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def validate_filename_policy(filename: str, file_size_bytes: int):
    if not filename:
        return False, "Filename is empty."
    real_name = filename
    if real_name.lower().endswith(".enc"):
        real_name = real_name[:-4]
    if not allowed_file(real_name):
        return False, "File extension is not allowed by policy."
    ext = real_name.rsplit(".", 1)[1].lower()
    pattern = r"^\d{8}_[a-zA-Z]+_[a-zA-Z0-9]+\." + re.escape(ext) + r"$"
    if not re.match(pattern, real_name):
        return False, "Filename must match YYYYMMDD_Author_Topic.ext"
    if file_size_bytes == 0:
        return False, "File is empty."
    return True, "Passed"

def _validate_encrypted_blob(payload_bytes: bytes) -> tuple[bool, str]:
    if not payload_bytes:
        return False, "Encrypted payload is empty"
    if len(payload_bytes) > _MAX_UPLOAD_BYTES:
        return False, "Encrypted payload exceeds MAX_UPLOAD_BYTES"
    try:
        s = payload_bytes.decode("utf-8", errors="strict")
    except Exception:
        return False, "Encrypted payload must be UTF-8 text"
    stripped = s.strip()
    if stripped.startswith("{"):
        try:
            env = json.loads(stripped)
        except Exception:
            return False, "Encrypted payload envelope is not valid JSON"
        if not isinstance(env, dict):
            return False, "Encrypted payload envelope invalid"
        if env.get("type") != _CONTENT_ENVELOPE_V2_TYPE or env.get("version") != 2 or env.get("alg") != _CONTENT_ENVELOPE_V2_ALG:
            return False, "Encrypted payload envelope algorithm unsupported"
        iv_b64 = str(env.get("ivB64") or "")
        ct_b64 = str(env.get("ciphertextB64") or "")
        aad = env.get("aad")
        if not isinstance(aad, dict):
            return False, "Encrypted payload envelope missing AAD"
        try:
            iv = base64.b64decode(iv_b64, validate=True)
            ct = base64.b64decode(ct_b64, validate=True)
        except Exception:
            return False, "Encrypted payload envelope base64 invalid"
        if len(iv) != 12:
            return False, "Encrypted payload envelope IV must be 12 bytes"
        if len(ct) < 17:
            return False, "Encrypted payload envelope ciphertext is too short"
        return True, "OK"
    if "::" not in s:
        return False, "Encrypted payload format invalid (missing ::)"
    iv_b64, ct_b64 = s.split("::", 1)
    if not iv_b64.strip() or not ct_b64.strip():
        return False, "Encrypted payload format invalid"
    try:
        iv = base64.b64decode(iv_b64.strip(), validate=True)
        ct = base64.b64decode(ct_b64.strip(), validate=True)
    except Exception:
        return False, "Encrypted payload legacy base64 invalid"
    if len(iv) != 16 or not ct:
        return False, "Encrypted payload legacy AES-CBC fields invalid"
    return True, "OK"


def _content_envelope_aad(payload_bytes: bytes) -> dict:
    try:
        s = payload_bytes.decode("utf-8", errors="strict").strip()
        if not s.startswith("{"):
            return {}
        env = json.loads(s)
        if isinstance(env, dict) and env.get("type") == _CONTENT_ENVELOPE_V2_TYPE and env.get("version") == 2:
            aad = env.get("aad")
            return aad if isinstance(aad, dict) else {}
    except Exception:
        return {}
    return {}


# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)
_APP_ROOT = Path(__file__).resolve().parent
_ALLOWED_WEB_ORIGINS = [
    origin.strip()
    for origin in os.getenv("WEB_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",")
    if origin.strip()
]
_AUTH_AUDIT = deque(maxlen=int(os.getenv("AUTH_AUDIT_MAX", "500")))
_SERVER_AUDIT = deque(maxlen=500)
_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{2,63}$")
_SERVER_SESSIONS_LOCK = threading.Lock()
_SERVER_SESSIONS: dict[str, dict] = {}
_AUTH_CHALLENGES_LOCK = threading.Lock()
_AUTH_CHALLENGES: dict[str, dict] = {}
_AUTH_CHALLENGE_TTL_SECONDS = int(os.getenv("AUTH_CHALLENGE_TTL_SECONDS", "120"))
_FABRIC_OFFLINE_FLOWS_LOCK = threading.Lock()
_FABRIC_OFFLINE_FLOWS: dict[str, dict] = {}
_FABRIC_OFFLINE_FLOW_TTL_SECONDS = int(os.getenv("FABRIC_OFFLINE_FLOW_TTL_SECONDS", "180"))
_SECURITY_AGENT_URL = os.getenv("SECURITY_AGENT_URL", "http://127.0.0.1:8090")
_SECURITY_AGENT_TOKEN = _runtime_secret("SECURITY_AGENT_TOKEN", nbytes=32)
_FABRIC_PATH = os.getenv("FABRIC_PATH", "/home/ruslan/fabric-dev/fabric-samples/test-network")
_FABRIC_BIN_DIR = str((Path(_FABRIC_PATH).resolve().parent / "bin"))
_VALID_ROLES = {"Researcher", "SecurityService"}
_AGENT_BIN_PATH = Path(os.getenv("FABRIC_AGENT_BIN", str(_APP_ROOT / "agent-go" / "securedata-agent")))
_AGENT_WORKDIR = _APP_ROOT / "agent-go"
_AGENT_AUTOSTART = os.getenv("AGENT_AUTOSTART", "1") == "1"
_AGENT_PROCESS = None
_BOOTSTRAP_ENROLLMENT_SECRET = os.getenv("BOOTSTRAP_ENROLLMENT_SECRET", os.getenv("BOOTSTRAP_PASSWORD", "securitypw"))
_WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
_WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
_INVITE_SIGNING_KEY = _runtime_secret("INVITE_SIGNING_KEY", nbytes=32)
_INVITE_TTL_HOURS = int(os.getenv("INVITE_TTL_HOURS", "24"))
_CSRF_HEADER = "X-CSRF-Token"
_DOWNLOAD_GRANT_TTL_SECONDS = int(os.getenv("DOWNLOAD_GRANT_TTL_SECONDS", "300"))
_CONTENT_ENVELOPE_V2_TYPE = "securedata.content-envelope"
_CONTENT_ENVELOPE_V2_ALG = "AES-256-GCM"
_KEY_ENVELOPE_V2_PREFIX = "SDC2:KEY:"

CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": _ALLOWED_WEB_ORIGINS}},
    allow_headers=["Content-Type", _CSRF_HEADER],
)
app.secret_key = _runtime_secret("FLASK_SECRET", nbytes=32)
app.config["MAX_CONTENT_LENGTH"] = _MAX_UPLOAD_BYTES + (2 * 1024 * 1024)
app.config["SESSION_COOKIE_NAME"] = "securedata_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _audit_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name or "audit")).strip(".-") or "audit"
    return _AUDIT_DIR / f"{safe}.jsonl"


def _append_jsonl_audit(name: str, record: dict) -> None:
    try:
        item = dict(record or {})
        item.setdefault("time", _utc_now_iso())
        path = _audit_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception as exc:
        log.warning("failed to append %s audit: %s", name, exc)


def _tail_jsonl_audit(name: str, limit: int = 500) -> list[dict]:
    path = _audit_path(name)
    if not path.exists():
        return []
    try:
        lines = path.read_text("utf-8").splitlines()[-max(1, int(limit)):]
    except Exception as exc:
        log.warning("failed to read %s audit: %s", name, exc)
        return []
    out: list[dict] = []
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                out.append(item)
        except Exception:
            continue
    return out


def parse_rfc3339_loose(value: str) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("timestamp is required")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _request_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def _record_auth_event(event: str, user: str, *, actor: str = "", details: str = ""):
    rec = {
        "time": _utc_now_iso(),
        "event": str(event or ""),
        "user": str(user or ""),
        "actor": str(actor or ""),
        "details": str(details or ""),
        "ip": _request_ip(),
    }
    _AUTH_AUDIT.append(rec)
    _append_jsonl_audit("auth", rec)


def _auth_stats(username: str) -> dict:
    events = _tail_jsonl_audit("auth", int(os.getenv("AUTH_AUDIT_STATS_MAX", "5000"))) or list(_AUTH_AUDIT)
    login_events = [item for item in events if item.get("event") == "login_success" and item.get("user") == username]
    return {
        "last_login": login_events[-1]["time"] if login_events else "",
        "login_count": len(login_events),
    }


def _drop_server_session(sid: str | None):
    if not sid:
        return
    with _SERVER_SESSIONS_LOCK:
        _SERVER_SESSIONS.pop(sid, None)


def _clear_authenticated_session():
    _drop_server_session(session.get("sid"))
    session.clear()


def _cleanup_all_server_sessions():
    with _SERVER_SESSIONS_LOCK:
        sids = list(_SERVER_SESSIONS.keys())
    for sid in sids:
        _drop_server_session(sid)


def _server_session_lifetime() -> timedelta:
    return app.config.get("PERMANENT_SESSION_LIFETIME", timedelta(hours=12))


def _set_session_from_payload(payload: dict):
    old_sid = session.get("sid")
    sid = secrets.token_urlsafe(32)
    started_at = _utc_now_iso()
    next_payload = dict(payload)
    next_payload.setdefault("webauthn_verified_at", started_at)
    record = {
        "sid": sid,
        "payload": next_payload,
        "session_started_at": started_at,
        "expires_at": datetime.now(timezone.utc) + _server_session_lifetime(),
        "csrf_token": secrets.token_urlsafe(32),
        "download_grants": {},
    }
    with _SERVER_SESSIONS_LOCK:
        _SERVER_SESSIONS[sid] = record
    session.clear()
    session.permanent = True
    session["sid"] = sid
    if old_sid and old_sid != sid:
        _drop_server_session(old_sid)


def _current_server_session() -> dict | None:
    sid = session.get("sid")
    if not sid:
        return None
    now = datetime.now(timezone.utc)
    expired: list[str] = []
    with _SERVER_SESSIONS_LOCK:
        for key, rec in list(_SERVER_SESSIONS.items()):
            if rec.get("expires_at") and rec["expires_at"] <= now:
                expired.append(key)
        record = _SERVER_SESSIONS.get(sid)
    for key in expired:
        _drop_server_session(key)
    if not record:
        session.clear()
        return None
    if record.get("expires_at") and record["expires_at"] <= now:
        _drop_server_session(sid)
        session.clear()
        return None
    with _SERVER_SESSIONS_LOCK:
        live = _SERVER_SESSIONS.get(sid)
        if live is not None:
            if not live.get("csrf_token"):
                live["csrf_token"] = secrets.token_urlsafe(32)
            if not isinstance(live.get("download_grants"), dict):
                live["download_grants"] = {}
            record = dict(live)
    return dict(record)


def _refresh_server_session_identity() -> dict | None:
    record = _current_server_session()
    if not record:
        return None
    payload = dict(record.get("payload") or {})
    username = str(payload.get("username") or "").strip()
    sid = str(record.get("sid") or "")
    if username and sid:
        try:
            profile = _chain_profile_by_username(username)
            if isinstance(profile, dict):
                refreshed = _session_payload_from_chain_profile(profile)
                for key in ("webauthn_verified_at",):
                    if payload.get(key):
                        refreshed[key] = payload.get(key)
                payload = refreshed
                with _SERVER_SESSIONS_LOCK:
                    if sid in _SERVER_SESSIONS:
                        _SERVER_SESSIONS[sid]["payload"] = dict(payload)
                record["payload"] = payload
        except Exception:
            pass
    return record


def _current_auth_user() -> dict | None:
    record = _current_server_session()
    if not record:
        return None
    payload = dict(record.get("payload") or {})
    username = payload.get("username", "")
    stats = _auth_stats(username)
    return {
        "username": username,
        "display_name": payload.get("display_name") or username,
        "role": payload.get("role", ""),
        "department": payload.get("department", ""),
        "fabric_profile": username,
        "org": payload.get("org", ""),
        "msp_id": payload.get("msp_id", ""),
        "client_id": payload.get("client_id", ""),
        "status": payload.get("status", "active"),
        "created_at": payload.get("created_at", ""),
        "recovery_bundle_required": bool(payload.get("recovery_bundle_required")),
        "recovery_bundle_created": bool(payload.get("recovery_bundle_created")),
        "recovery_bundle_created_at": payload.get("recovery_bundle_created_at", ""),
        "passkey_count": int(payload.get("passkey_count") or 0),
        "webauthn_verified_at": payload.get("webauthn_verified_at", ""),
        "last_login": stats["last_login"],
        "login_count": stats["login_count"],
        "session_started_at": record.get("session_started_at", ""),
        "csrf_token": record.get("csrf_token", ""),
    }


def _csrf_valid(record: dict | None) -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if not record:
        return False
    expected = str(record.get("csrf_token") or "").strip()
    supplied = str(request.headers.get(_CSRF_HEADER) or "").strip()
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _record_download_grant(asset_id: str):
    asset_id = _norm_simple_text(asset_id, 128, collapse=True)
    if not asset_id:
        return
    sid = session.get("sid")
    if not sid:
        return
    now = time.time()
    with _SERVER_SESSIONS_LOCK:
        rec = _SERVER_SESSIONS.get(sid)
        if not rec:
            return
        grants = dict(rec.get("download_grants") or {})
        cutoff = now - _DOWNLOAD_GRANT_TTL_SECONDS
        grants = {k: float(v) for k, v in grants.items() if float(v or 0) >= cutoff}
        grants[asset_id] = now
        rec["download_grants"] = grants


def _has_recent_download_grant(asset_id: str) -> bool:
    asset_id = _norm_simple_text(asset_id, 128, collapse=True)
    if not asset_id:
        return False
    record = _current_server_session()
    if not record:
        return False
    grants = dict(record.get("download_grants") or {})
    ts = float(grants.get(asset_id) or 0)
    return ts > 0 and (time.time() - ts) <= _DOWNLOAD_GRANT_TTL_SECONDS


def _mark_session_webauthn_verified(verified_at: str | None = None):
    record = _current_server_session()
    if not record:
        return
    sid = str(record.get("sid") or "")
    if not sid:
        return
    ts = verified_at or _utc_now_iso()
    with _SERVER_SESSIONS_LOCK:
        if sid in _SERVER_SESSIONS:
            payload = dict(_SERVER_SESSIONS[sid].get("payload") or {})
            payload["webauthn_verified_at"] = ts
            _SERVER_SESSIONS[sid]["payload"] = payload


def _has_recent_webauthn_auth(max_age_seconds: int | None = None) -> bool:
    record = _current_server_session()
    if not record:
        return False
    payload = dict(record.get("payload") or {})
    verified_at = str(payload.get("webauthn_verified_at") or "").strip()
    if not verified_at:
        return False
    try:
        verified_dt = parse_rfc3339_loose(verified_at)
    except Exception:
        return False
    age = datetime.now(timezone.utc) - verified_dt
    return age <= timedelta(seconds=max_age_seconds or WEBAUTHN_REAUTH_TTL_SECONDS)


def _require_recent_webauthn_auth(max_age_seconds: int | None = None):
    if not _has_recent_webauthn_auth(max_age_seconds=max_age_seconds):
        raise PermissionError("recent WebAuthn verification is required")


def _cleanup_expired_challenges():
    now = datetime.now(timezone.utc)
    with _AUTH_CHALLENGES_LOCK:
        expired = [cid for cid, rec in _AUTH_CHALLENGES.items() if rec.get("expires_at") and rec["expires_at"] <= now]
        for cid in expired:
            _AUTH_CHALLENGES.pop(cid, None)


def _cleanup_expired_offline_flows():
    now = datetime.now(timezone.utc)
    with _FABRIC_OFFLINE_FLOWS_LOCK:
        expired = [fid for fid, rec in _FABRIC_OFFLINE_FLOWS.items() if rec.get("expires_at") and rec["expires_at"] <= now]
        for fid in expired:
            _FABRIC_OFFLINE_FLOWS.pop(fid, None)


def _new_challenge_record(*, kind: str, username: str, extra: dict | None = None) -> dict:
    challenge = secrets.token_bytes(32)
    challenge_b64 = b64url_encode(challenge)
    record = {
        "id": secrets.token_urlsafe(18),
        "kind": kind,
        "username": username,
        "challenge": challenge_b64,
        "created_at": _utc_now_iso(),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=max(30, _AUTH_CHALLENGE_TTL_SECONDS)),
    }
    if extra:
        record.update(extra)
    with _AUTH_CHALLENGES_LOCK:
        _AUTH_CHALLENGES[record["id"]] = record
    return record


def _consume_challenge(challenge_id: str, *, expected_kind: str, username: str | None = None) -> dict:
    _cleanup_expired_challenges()
    with _AUTH_CHALLENGES_LOCK:
        record = _AUTH_CHALLENGES.pop(challenge_id, None)
    if not record:
        raise ValueError("challenge expired")
    if record.get("kind") != expected_kind:
        raise ValueError("challenge kind mismatch")
    if username and record.get("username") != username:
        raise ValueError("challenge username mismatch")
    return record


def _store_offline_flow(payload: dict) -> str:
    _cleanup_expired_offline_flows()
    flow_id = secrets.token_urlsafe(18)
    record = dict(payload)
    record["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=max(30, _FABRIC_OFFLINE_FLOW_TTL_SECONDS))
    with _FABRIC_OFFLINE_FLOWS_LOCK:
        _FABRIC_OFFLINE_FLOWS[flow_id] = record
    return flow_id


def _get_offline_flow(flow_id: str) -> dict:
    _cleanup_expired_offline_flows()
    with _FABRIC_OFFLINE_FLOWS_LOCK:
        record = _FABRIC_OFFLINE_FLOWS.get(flow_id)
    if not record:
        raise ValueError("fabric signing flow expired")
    return dict(record)


def _update_offline_flow(flow_id: str, updates: dict):
    with _FABRIC_OFFLINE_FLOWS_LOCK:
        record = _FABRIC_OFFLINE_FLOWS.get(flow_id)
        if not record:
            raise ValueError("fabric signing flow expired")
        record.update(updates or {})


def _delete_offline_flow(flow_id: str):
    with _FABRIC_OFFLINE_FLOWS_LOCK:
        _FABRIC_OFFLINE_FLOWS.pop(flow_id, None)


def _session_payload_from_chain_profile(profile: dict) -> dict:
    recovery = profile.get("recoveryBundle") or profile.get("RecoveryBundle") or {}
    webauthn = profile.get("webAuthnIdentity") or profile.get("WebAuthnIdentity") or {}
    credentials = webauthn.get("credentials") or profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or []
    return {
        "username": str(profile.get("username") or ""),
        "display_name": str(profile.get("username") or ""),
        "org": "org2" if str(profile.get("mspID") or profile.get("mspId") or "").strip() == "Org2MSP" else "org1",
        "msp_id": str(profile.get("mspID") or profile.get("mspId") or "Org1MSP"),
        "client_id": str(profile.get("userID") or profile.get("userId") or ""),
        "role": str(profile.get("role") or "Researcher"),
        "department": str(profile.get("department") or ""),
        "status": "blocked" if bool(profile.get("isBlocked") or profile.get("IsBlocked")) else "active",
        "created_at": str(profile.get("created_at") or profile.get("createdAt") or _utc_now_iso()),
        "fabric_cert": str(profile.get("fabricCert") or profile.get("FabricCert") or ""),
        "recovery_bundle_required": bool(recovery.get("required")),
        "recovery_bundle_created": bool(recovery.get("created")),
        "recovery_bundle_created_at": str(recovery.get("createdAt") or ""),
        "passkey_count": len([item for item in credentials if isinstance(item, dict)]),
    }


def _current_chain_profile() -> dict:
    user = _current_auth_user()
    if not user:
        raise ValueError("unauthorized")
    profile = _chain_profile_by_username(user.get("username", ""))
    if not isinstance(profile, dict):
        raise ValueError("user profile not found on ledger")
    return profile


def _local_identity_reissue_blockers(user_id: str) -> dict:
    wanted_user_id = str(user_id or "").strip()
    if not wanted_user_id:
        return {"owned_asset_ids": [], "shared_asset_ids": []}
    result = _security_agent_eval("GetAllAssets", [])
    assets = result if isinstance(result, list) else []
    owned_asset_ids: list[str] = []
    shared_asset_ids: list[str] = []
    seen_owned: set[str] = set()
    seen_shared: set[str] = set()
    for item in assets:
        if not isinstance(item, dict):
            continue
        asset_id = _norm_simple_text(item.get("id") or item.get("ID") or item.get("assetID") or "", 128, collapse=False)
        owner_id = str(item.get("ownerID") or item.get("OwnerID") or "").strip()
        if owner_id == wanted_user_id:
            if asset_id and asset_id not in seen_owned:
                owned_asset_ids.append(asset_id)
                seen_owned.add(asset_id)
            continue
        keys = item.get("keys") or item.get("Keys") or {}
        if not isinstance(keys, dict):
            continue
        encrypted_key = str(keys.get(wanted_user_id) or "").strip()
        if encrypted_key and asset_id and asset_id not in seen_shared:
            shared_asset_ids.append(asset_id)
            seen_shared.add(asset_id)
    return {
        "owned_asset_ids": owned_asset_ids,
        "shared_asset_ids": shared_asset_ids,
    }


def _normalize_webauthn_credential(cred: dict) -> dict:
    transports = []
    for item in cred.get("transports") or []:
        text = _norm_simple_text(item, 32, collapse=True)
        if text:
            transports.append(text)
    sign_count_raw = cred.get("signCount", 0)
    try:
        sign_count = max(0, int(sign_count_raw))
    except Exception:
        sign_count = 0
    return {
        "credentialID": _norm_simple_text(cred.get("credentialID", ""), 256, collapse=False),
        "publicKeyPEM": str(cred.get("publicKeyPEM", "") or ""),
        "signCount": sign_count,
        "transports": transports,
        "aaguid": _norm_simple_text(cred.get("aaguid", ""), 128, collapse=False),
        "attestationFormat": _norm_simple_text(cred.get("attestationFormat", ""), 64, collapse=True),
        "label": _norm_simple_text(cred.get("label", ""), 128, collapse=True),
        "rpID": _norm_simple_text(cred.get("rpID", ""), 255, collapse=True),
        "createdAt": _norm_simple_text(cred.get("createdAt", ""), 64, collapse=True),
        "lastUsedAt": _norm_simple_text(cred.get("lastUsedAt", ""), 64, collapse=True),
    }


def _normalize_webauthn_credentials(items: list[dict]) -> list[dict]:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        normalized = _normalize_webauthn_credential(item)
        if normalized["credentialID"] and normalized["publicKeyPEM"]:
            out.append(normalized)
    return out


def _security_agent_submit(function: str, args: list[str]):
    url = _SECURITY_AGENT_URL.rstrip("/") + "/submit"
    resp = requests.post(
        url,
        headers=_security_agent_headers(),
        json={"function": function, "args": [str(a) for a in (args or [])]},
        timeout=30,
    )
    data = resp.json()
    if not resp.ok or not data.get("ok"):
        raise RuntimeError(data.get("error") or f"security agent submit failed: {data}")
    return data.get("result")


def _chain_profile_by_username(username: str) -> dict | None:
    try:
        result = _security_agent_eval("GetUserProfileByUsername", [username])
    except Exception as exc:
        msg = str(exc).lower()
        if "user not found" in msg:
            return None
        raise
    if isinstance(result, dict):
        return result
    return None


def _chain_invites() -> list[dict]:
    result = _security_agent_eval("ListEnrollmentInvites", [])
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    return []


def _normalized_invite_status(value: str) -> str:
    normalized = _norm_simple_text(value, 32, collapse=True).lower()
    if normalized in {"", "active", "pending"}:
        return "pending"
    return normalized


def _chain_invite_by_username(username: str) -> dict | None:
    wanted = str(username or "").strip().lower()
    if not wanted:
        return None
    for invite in _chain_invites():
        current = str(invite.get("username") or invite.get("Username") or "").strip().lower()
        if current == wanted:
            return invite
    return None


def _require_pending_invite(ticket: dict) -> dict:
    username = _validate_username(ticket.get("username", ""))
    invite_id = _norm_simple_text(ticket.get("invite_id", ""), 128, collapse=False)
    invite = _chain_invite_by_username(username)
    if not isinstance(invite, dict):
        raise ValueError("invite not found")
    if _normalized_invite_status(str(invite.get("status") or invite.get("Status") or "")) != "pending":
        raise ValueError("invite is not active")
    chain_invite_id = _norm_simple_text(invite.get("inviteID") or invite.get("inviteId") or "", 128, collapse=False)
    if chain_invite_id != invite_id:
        raise ValueError("invite mismatch")
    expires_at = str(invite.get("expiresAt") or invite.get("expires_at") or "")
    if expires_at and expires_at < _utc_now_iso():
        raise ValueError("invite expired")
    return invite


def _org_from_msp(msp_id: str) -> str:
    return "org2" if str(msp_id or "").strip() == "Org2MSP" else "org1"


def _fabric_ca_admin_context(org: str) -> tuple[dict, dict]:
    settings = _org_ca_settings(org)
    peer_org_dir = Path(_FABRIC_PATH) / "organizations" / "peerOrganizations" / settings["domain"]
    env = os.environ.copy()
    env["PATH"] = _FABRIC_BIN_DIR + (os.pathsep + env.get("PATH", "") if env.get("PATH") else "")
    env["FABRIC_CA_CLIENT_HOME"] = str(peer_org_dir) + os.sep
    return settings, env


def _identity_max_enrollments(*, username: str, role: str) -> str:
    normalized_username = _validate_username(username)
    normalized_role = _norm_simple_text(role, 64, collapse=True)
    if normalized_username == "SecurityService" and normalized_role == "SecurityService":
        return "-1"
    return "1"


def _fabric_ca_register_identity(*, username: str, enrollment_secret: str, role: str, department: str, org: str, max_enrollments: str | None = None):
    settings, env = _fabric_ca_admin_context(org)
    limit = str(max_enrollments or _identity_max_enrollments(username=username, role=role))
    register_cmd = [
        "fabric-ca-client",
        "register",
        "--caname",
        settings["ca_name"],
        "--id.name",
        username,
        "--id.secret",
        enrollment_secret,
        "--id.type",
        "client",
        "--id.maxenrollments",
        limit,
        "--id.attrs",
        f"department={department}:ecert,role={role}:ecert",
        "--tls.certfiles",
        settings["ca_cert"],
    ]
    try:
        _run_local_command(register_cmd, env=env, cwd=_FABRIC_PATH, timeout=120)
    except Exception as exc:
        msg = str(exc).lower()
        if "already registered" not in msg and "is already registered" not in msg:
            raise
        # Keep the Fabric CA secret aligned with the current invite/bootstrap
        # secret so activation uses the same credential that was issued.
        _fabric_ca_modify_identity_secret(
            username=username,
            enrollment_secret=enrollment_secret,
            role=role,
            department=department,
            org=org,
            max_enrollments=limit,
        )


def _fabric_ca_modify_identity_secret(*, username: str, enrollment_secret: str, role: str, department: str, org: str, max_enrollments: str | None = None):
    settings, env = _fabric_ca_admin_context(org)
    limit = str(max_enrollments or _identity_max_enrollments(username=username, role=role))
    modify_cmd = [
        "fabric-ca-client",
        "identity",
        "modify",
        username,
        "--caname",
        settings["ca_name"],
        "--secret",
        enrollment_secret,
        "--type",
        "client",
        "--maxenrollments",
        limit,
        "--attrs",
        f"department={department}:ecert,role={role}:ecert",
        "--tls.certfiles",
        settings["ca_cert"],
    ]
    _run_local_command(modify_cmd, env=env, cwd=_FABRIC_PATH, timeout=120)


def _fabric_ca_revoke_identity(*, username: str, org: str, reason: str = "unspecified"):
    """
    Revoke all enrollment certificates of `username` on the given CA.
    Unlike `identity remove`, this path does not require
    `cfg.identities.allowremove` to be true on the CA, and is the
    cryptographically meaningful operation when we want a user to lose
    access to Fabric.  Idempotent: treats 'no enrollment certificates'
    and 'identity not found' as success.
    """
    settings, env = _fabric_ca_admin_context(org)
    revoke_cmd = [
        "fabric-ca-client",
        "revoke",
        "--caname",
        settings["ca_name"],
        "--revoke.name",
        username,
        "--revoke.reason",
        reason or "unspecified",
        "--gencrl",
        "--tls.certfiles",
        settings["ca_cert"],
    ]
    try:
        _run_local_command(revoke_cmd, env=env, cwd=_FABRIC_PATH, timeout=120)
    except Exception as exc:
        msg = str(exc).lower()
        # Acceptable terminal states - the identity is either absent or
        # already revoked, both of which satisfy the caller's intent.
        acceptable = (
            "identity not found",
            "does not exist",
            "has no certificates",
            "no rows found",
            "certificate not found",
            "certificate already revoked",
            "already revoked",
        )
        if not any(tok in msg for tok in acceptable):
            raise


def _fabric_ca_disable_identity(*, username: str, org: str):
    """
    Set maxenrollments to 0 so `username` cannot enroll again, without
    removing the row (which CA refuses by default with Code 56).
    Used as a belt-and-braces step when we logically delete a pending
    user whose invite never activated.
    """
    settings, env = _fabric_ca_admin_context(org)
    modify_cmd = [
        "fabric-ca-client",
        "identity",
        "modify",
        username,
        "--caname",
        settings["ca_name"],
        "--maxenrollments",
        "0",
        "--tls.certfiles",
        settings["ca_cert"],
    ]
    try:
        _run_local_command(modify_cmd, env=env, cwd=_FABRIC_PATH, timeout=60)
    except Exception as exc:
        msg = str(exc).lower()
        if "not found" not in msg and "does not exist" not in msg:
            raise


def _fabric_ca_remove_identity(*, username: str, org: str):
    """
    Best-effort removal of the CA's record for `username`. Tries
    `identity remove` first; when the CA refuses with 'Code: 56 -
    Identity removal is disabled' (default fabric-ca configuration),
    falls back to `revoke + maxenrollments=0`, which is cryptographically
    equivalent for our purposes: the user can no longer enroll and any
    previously issued certificates are added to the CRL.
    """
    settings, env = _fabric_ca_admin_context(org)
    remove_cmd = [
        "fabric-ca-client",
        "identity",
        "remove",
        username,
        "--caname",
        settings["ca_name"],
        "--tls.certfiles",
        settings["ca_cert"],
    ]
    try:
        _run_local_command(remove_cmd, env=env, cwd=_FABRIC_PATH, timeout=120)
        return
    except Exception as exc:
        msg = str(exc).lower()
        if (
            "does not exist" in msg
            or "no rows found" in msg
            or "identity not found" in msg
        ):
            return
        if "code: 56" in msg or "identity removal is disabled" in msg:
            # CA has identities.allowremove=false. Fall back to the
            # cryptographic operation that actually matters.
            _fabric_ca_revoke_identity(username=username, org=org, reason="administrative")
            _fabric_ca_disable_identity(username=username, org=org)
            return
        raise


def _invite_token_key() -> bytes:
    seed = _INVITE_SIGNING_KEY or app.secret_key
    return str(seed).encode("utf-8")


def _issue_invite_token(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).rstrip(b"=")
    sig = hmac.new(_invite_token_key(), body, hashlib.sha256).digest()
    return body.decode("ascii") + "." + b64url_encode(sig)


def _verify_invite_token(token: str) -> dict:
    raw = str(token or "").strip()
    if "." not in raw:
        raise ValueError("invite token is invalid")
    body_b64, sig_b64 = raw.split(".", 1)
    expected_sig = hmac.new(_invite_token_key(), body_b64.encode("ascii"), hashlib.sha256).digest()
    actual_sig = b64url_decode(sig_b64)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("invite token signature mismatch")
    padded = body_b64 + ("=" * ((4 - len(body_b64) % 4) % 4))
    payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    if str(payload.get("exp", "")) < _utc_now_iso():
        raise ValueError("invite token expired")
    return payload


def _build_invite_token_payload(*, username: str, department: str, role: str, org: str, invite_id: str, secret: str, expires_at: str) -> dict:
    return {
        "username": username,
        "department": department,
        "role": role,
        "org": org,
        "invite_id": invite_id,
        "secret": secret,
        "exp": expires_at,
    }


def _issue_or_reissue_invite(*, username: str, department: str, role: str, org: str, actor: str, mode: str) -> dict:
    normalized_mode = "reissue" if str(mode or "").strip().lower() == "reissue" else "issue"
    username = _validate_username(username)
    role = _norm_simple_text(role, 64, collapse=True)
    department = _norm_simple_text(department, 128, collapse=True) or "IT Department"
    org = _norm_simple_text(org, 16, collapse=True).lower()
    if role not in _VALID_ROLES:
        raise ValueError("unsupported role")
    if _chain_profile_by_username(username):
        raise ValueError("username already activated")

    existing_invite = _chain_invite_by_username(username)
    if normalized_mode == "issue" and existing_invite:
        raise ValueError("pending user already exists; reissue or delete the existing invite")
    if normalized_mode == "reissue" and not existing_invite:
        raise ValueError("invite not found")

    enrollment_secret = secrets.token_urlsafe(18)
    invite_id = secrets.token_urlsafe(18)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=max(1, _INVITE_TTL_HOURS))).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if normalized_mode == "reissue":
        source = existing_invite or {}
        department = _norm_simple_text(source.get("department") or department, 128, collapse=True) or department
        role = _norm_simple_text(source.get("role") or role, 64, collapse=True) or role
        org = _norm_simple_text(source.get("org") or org, 16, collapse=True).lower() or org
        try:
            _fabric_ca_modify_identity_secret(
                username=username,
                enrollment_secret=enrollment_secret,
                role=role,
                department=department,
                org=org,
            )
        except Exception as exc:
            msg = str(exc).lower()
            if "does not exist" in msg or "no rows found" in msg or "identity not found" in msg:
                _fabric_ca_register_identity(
                    username=username,
                    enrollment_secret=enrollment_secret,
                    role=role,
                    department=department,
                    org=org,
                )
            else:
                raise
        _security_agent_submit("ReissueEnrollmentInvite", [username, invite_id, expires_at])
    else:
        _fabric_ca_register_identity(
            username=username,
            enrollment_secret=enrollment_secret,
            role=role,
            department=department,
            org=org,
        )
        _security_agent_submit("IssueEnrollmentInvite", [username, department, role, org, invite_id, expires_at])

    ticket = _issue_invite_token(
        _build_invite_token_payload(
            username=username,
            department=department,
            role=role,
            org=org,
            invite_id=invite_id,
            secret=enrollment_secret,
            expires_at=expires_at,
        )
    )
    _record_auth_event(
        "invite_reissued" if normalized_mode == "reissue" else "invite_created",
        username,
        actor=actor,
        details=f"org={org} role={role} invite_id={invite_id}",
    )
    return {
        "username": username,
        "org": org,
        "role": role,
        "department": department,
        "invite_token": ticket,
        "invite_id": invite_id,
        "expires_at": expires_at,
        "mode": normalized_mode,
    }


def _dn_value(name: x509.Name) -> str:
    oid_map = {
        "2.5.4.6": "C",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
        "2.5.4.3": "CN",
        "2.5.4.5": "SERIALNUMBER",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.9": "STREET",
        "2.5.4.17": "POSTALCODE",
    }
    parts: list[str] = []
    for rdn in reversed(name.rdns):
        attrs: list[str] = []
        for attr in rdn:
            key = oid_map.get(attr.oid.dotted_string, attr.oid.dotted_string)
            value = str(attr.value)
            escaped = []
            for idx, ch in enumerate(value):
                if (idx == 0 and (ch == " " or ch == "#")) or (idx == len(value) - 1 and ch == " "):
                    escaped.append("\\" + ch)
                elif ch in ',+"\\<>;':
                    escaped.append("\\" + ch)
                else:
                    escaped.append(ch)
            attrs.append(f"{key}={''.join(escaped)}")
        parts.append("+".join(attrs))
    return ",".join(parts)


def _fabric_client_id_from_cert(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    raw = f"x509::{_dn_value(cert.subject)}::{_dn_value(cert.issuer)}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _fabric_ca_enroll_csr(*, org: str, username: str, enrollment_secret: str, csr_pem: str) -> str:
    settings = _org_ca_settings(org)
    url = f"https://localhost:{settings['ca_port']}/enroll"
    payload = {
        "certificate_request": csr_pem,
        "caname": settings["ca_name"],
    }
    try:
        resp = requests.post(
            url,
            json=payload,
            auth=(username, enrollment_secret),
            verify=settings["ca_cert"],
            timeout=30,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"fabric ca enroll request failed: {exc}") from exc

    body = (resp.text or "").strip()
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}

    if resp.status_code >= 400 or not data.get("success", bool(data)):
        errors = data.get("errors") if isinstance(data, dict) else None
        raise RuntimeError(
            errors
            or body
            or f"fabric ca enroll failed with status {resp.status_code}"
        )

    result = data.get("result") or {}
    cert = result.get("Cert") or result.get("cert") or result.get("certificate")
    if isinstance(cert, dict):
        cert = cert.get("pem") or cert.get("cert") or cert.get("certificate") or cert.get("value")
    if isinstance(cert, list):
        cert = "\n".join(str(item or "") for item in cert if item)
    if isinstance(cert, str):
        normalized = cert.replace("\\r", "").replace("\\n", "\n").strip()
        if "BEGIN CERTIFICATE" not in normalized:
            try:
                decoded = base64.b64decode(normalized).decode("utf-8")
                if "BEGIN CERTIFICATE" in decoded:
                    normalized = decoded.strip()
            except Exception:
                pass
        cert = normalized
    if not cert:
        raise RuntimeError("fabric ca enroll did not return certificate")
    if "BEGIN CERTIFICATE" not in str(cert):
        raise RuntimeError(f"fabric ca enroll returned unexpected certificate payload: {result}")
    return str(cert)


def _security_bootstrap_needed() -> bool:
    try:
        profile = _chain_profile_by_username("SecurityService")
        if profile is None:
            return True
        credentials = _normalize_webauthn_credentials(
            profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or []
        )
        return not credentials
    except Exception as exc:
        app.logger.warning("failed to resolve SecurityService bootstrap status: %s", exc)
        return True


def _agent_offline_exec(mode: str, cert_pem: str, fn_or_bytes: str, extra: list[str]) -> dict:
    if not cert_pem:
        raise ValueError("fabric certificate is missing")
    cfg = _org_runtime_settings(_current_auth_user().get("org", "org1") if _current_auth_user() else "org1")
    env = os.environ.copy()
    env["PATH"] = _FABRIC_BIN_DIR + (os.pathsep + env.get("PATH", "") if env.get("PATH") else "")
    env.update(
        {
            "FABRIC_PATH": _FABRIC_PATH,
            "AGENT_ORG": cfg["org"],
            "AGENT_USER": _current_auth_user().get("username", "device-user") if _current_auth_user() else "device-user",
            "AGENT_MSPID": _current_auth_user().get("msp_id", cfg["msp_id"]) if _current_auth_user() else cfg["msp_id"],
            "AGENT_PEER_ENDPOINT": cfg["peer_endpoint"],
            "AGENT_PEER_HOST": cfg["peer_host"],
            "AGENT_CHANNEL": os.getenv("AGENT_CHANNEL", "mychannel"),
            "AGENT_CHAINCODE": os.getenv("AGENT_CHAINCODE", "securedata"),
        }
    )
    encoded_cert = base64.b64encode(cert_pem.encode("utf-8")).decode("ascii")
    cmd = [str(_AGENT_BIN_PATH), mode, encoded_cert, fn_or_bytes, *extra] if _AGENT_BIN_PATH.exists() else ["go", "run", ".", mode, encoded_cert, fn_or_bytes, *extra]
    cwd = None if _AGENT_BIN_PATH.exists() else str(_AGENT_WORKDIR)
    raw = _run_command(cmd, env=env, cwd=cwd, timeout=120)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("invalid offline agent response")
    return parsed


def _org_runtime_settings(org: str) -> dict:
    org_key = _norm_simple_text(org or "org1", 16, collapse=True).lower()
    if org_key == "org2":
        return {
            "org": "org2",
            "domain": "org2.example.com",
            "msp_id": "Org2MSP",
            "peer_endpoint": "localhost:9051",
            "peer_host": "peer0.org2.example.com",
        }
    return {
        "org": "org1",
        "domain": "org1.example.com",
        "msp_id": "Org1MSP",
        "peer_endpoint": "localhost:7051",
        "peer_host": "peer0.org1.example.com",
    }


def _agent_command(mode: str, fn: str, args: list[str]) -> tuple[list[str], str | None]:
    normalized = [str(arg) for arg in (args or [])]
    if _AGENT_BIN_PATH.exists():
        return [str(_AGENT_BIN_PATH), mode, fn, *normalized], None
    return ["go", "run", ".", mode, fn, *normalized], str(_AGENT_WORKDIR)


def _run_command(cmd: list[str], *, env: dict, cwd: str | None = None, timeout: int = 90) -> str:
    result = subprocess.run(cmd, env=env, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(err or "command failed")
    return (result.stdout or "").strip()


def _security_agent_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if _SECURITY_AGENT_TOKEN:
        headers["Authorization"] = f"Bearer {_SECURITY_AGENT_TOKEN}"
    return headers


def _security_agent_eval(function: str, args: list[str]):
    url = _SECURITY_AGENT_URL.rstrip("/") + "/eval"
    resp = requests.post(
        url,
        headers=_security_agent_headers(),
        json={"function": function, "args": [str(a) for a in (args or [])]},
        timeout=20,
    )
    data = resp.json()
    if not resp.ok or not data.get("ok"):
        raise RuntimeError(data.get("error") or f"security agent eval failed: {data}")
    return data.get("result")


_VALID_AGENT_ROLES = {"SecurityService", "MLService", "RiskService"}


def _agent_eval_as_role(role: str, function: str, args: list[str]):
    """
    Call the unified Go agent's /eval as a specific service identity
    by injecting the X-Agent-Role header. This is the server-side
    counterpart of the frontend's legacy `agentEvalAs("MLService", ...)`:
    it centralises AGENT_TOKEN auth and avoids the browser ever talking
    to the agent on a secondary port that may not exist in the unified
    deployment.
    """
    role = (role or "").strip()
    if role not in _VALID_AGENT_ROLES:
        raise ValueError(f"unknown agent role: {role}")
    headers = dict(_security_agent_headers())
    headers["X-Agent-Role"] = role
    url = _SECURITY_AGENT_URL.rstrip("/") + "/eval"
    resp = requests.post(
        url,
        headers=headers,
        json={"function": function, "args": [str(a) for a in (args or [])]},
        timeout=20,
    )
    try:
        data = resp.json()
    except Exception:
        data = {}
    if not resp.ok or not data.get("ok"):
        raise RuntimeError(data.get("error") or f"agent eval failed: HTTP {resp.status_code}")
    return data.get("result")


def _json_unauthorized():
    return jsonify({"ok": False, "error": "unauthorized"}), 401


def require_auth(view_func):
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        record = _current_server_session()
        if not record:
            return _json_unauthorized()
        if not _csrf_valid(record):
            return jsonify({"ok": False, "error": "csrf validation failed"}), 403
        return view_func(*args, **kwargs)

    return _wrapped


def require_security_session(view_func):
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        record = _current_server_session()
        if not record:
            return _json_unauthorized()
        if not _csrf_valid(record):
            return jsonify({"ok": False, "error": "csrf validation failed"}), 403
        user = _current_auth_user()
        if not user:
            return _json_unauthorized()
        if user.get("role") != "SecurityService":
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return view_func(*args, **kwargs)

    return _wrapped


atexit.register(_cleanup_all_server_sessions)


def _require_json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("invalid json body")
    return data


def _validate_username(username: str) -> str:
    username = _norm_simple_text(username, 64, collapse=False).strip()
    if not _USERNAME_RE.fullmatch(username):
        raise ValueError("username must start with a letter and contain only letters, digits, ., _, -")
    return username


def _resolve_fabric_ca_trust_bundle(org_dir: Path) -> str:
    """
    Return a file that can be used both for `requests(verify=...)` and for
    `fabric-ca-client --tls.certfiles`.

    The Fabric CA server only presents its leaf TLS certificate (`tls-cert.pem`)
    during the handshake. Python's `ssl` module needs the *issuer* in the
    trust store or verification fails with
    `unable to get local issuer certificate`. The default Fabric CA install
    uses the enrollment-CA root (`ca-cert.pem`) to sign its own TLS leaf, so
    that file is the correct trust anchor.

    We build a combined bundle (root + leaf) at runtime so the same file
    works for:
      * Python requests/ssl, which wants the root,
      * fabric-ca-client's Go TLS, which happily accepts either the root or
        the leaf itself,
      * future callers that may pin only the leaf (e.g. curl --cacert).

    The bundle is regenerated whenever its inputs change (mtime comparison).
    """
    ca_root = org_dir / "ca-cert.pem"
    tls_leaf = org_dir / "tls-cert.pem"
    inputs = [p for p in (ca_root, tls_leaf) if p.is_file()]
    if not inputs:
        # Nothing on disk - caller will get a meaningful error later.
        return str(tls_leaf)
    if len(inputs) == 1:
        return str(inputs[0])

    bundle = org_dir / ".securedata-ca-bundle.pem"
    try:
        newest = max(p.stat().st_mtime for p in inputs)
        if bundle.is_file() and bundle.stat().st_mtime >= newest and bundle.stat().st_size > 0:
            return str(bundle)
        parts = []
        for p in inputs:
            text = p.read_text(encoding="utf-8", errors="ignore").strip()
            if "BEGIN CERTIFICATE" in text:
                parts.append(text)
        if not parts:
            return str(inputs[0])
        bundle.write_text("\n".join(parts) + "\n", encoding="utf-8")
        return str(bundle)
    except OSError:
        # Read-only mount / permission error - fall back to the root cert,
        # which is what Python actually needs for chain verification.
        return str(ca_root if ca_root.is_file() else tls_leaf)


def _org_ca_settings(org: str) -> dict:
    normalized = _norm_simple_text(org or "org1", 16, collapse=True).lower()
    if normalized not in {"org1", "org2"}:
        raise ValueError("organization must be org1 or org2")
    base = Path(_FABRIC_PATH) / "organizations" / "fabric-ca"
    if normalized == "org2":
        org_dir = base / "org2"
        return {
            "org": "org2",
            "domain": "org2.example.com",
            "ca_name": "ca-org2",
            "ca_port": "8054",
            "ca_cert": _resolve_fabric_ca_trust_bundle(org_dir),
            "ca_dir": str(org_dir),
        }
    org_dir = base / "org1"
    return {
        "org": "org1",
        "domain": "org1.example.com",
        "ca_name": "ca-org1",
        "ca_port": "7054",
        "ca_cert": _resolve_fabric_ca_trust_bundle(org_dir),
        "ca_dir": str(org_dir),
    }


def _run_local_command(cmd: list[str], *, env: dict, cwd: str, timeout: int = 120):
    result = subprocess.run(cmd, env=env, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(err or "command failed")
    return (result.stdout or "").strip()
def _append_audit(rec: dict):
    try:
        item = dict(rec)
        _SERVER_AUDIT.append(item)
        _append_jsonl_audit("disp", item)
    except Exception:
        pass

@app.get("/health")
def health():
    ai_status = "active" if _ai_service_available else "disabled"
    return jsonify({"ok": True, "text": "ok", "ai": ai_status, "ai_service_url": AI_SERVICE_URL, "model_dir": MODEL_DIR}), 200


@app.get("/health/ipfs")
def health_ipfs():
    status = check_ipfs_health(timeout=3.0)
    http_status = 200 if status.get("ok") else 503
    return jsonify(status), http_status


@app.post("/ipfs/statuses")
@require_auth
def ipfs_statuses():
    try:
        data = _require_json_body()
        cids_raw = data.get("cids") or []
        if not isinstance(cids_raw, list):
            raise ValueError("cids must be a list")
        out = {}
        for raw in cids_raw[:200]:
            cid = _norm_simple_text(raw, 256, collapse=False)
            if not cid:
                continue
            status = _ipfs_status_snapshot(cid)
            needs_refresh = not status
            if status.get("last_checked_at"):
                try:
                    checked_at = parse_rfc3339_loose(status.get("last_checked_at"))
                    needs_refresh = (datetime.now(timezone.utc) - checked_at) > timedelta(seconds=IPFS_RECHECK_SECONDS)
                except Exception:
                    needs_refresh = True
            if needs_refresh:
                try:
                    status = ensure_ipfs_replication(cid, asset_ids=status.get("asset_ids") or [])
                except Exception as exc:
                    status = _merge_ipfs_status_record(
                        cid,
                        {
                            "last_checked_at": _utc_now_iso(),
                            "last_error": _norm_simple_text(str(exc), 512, collapse=True),
                        },
                    )
            out[cid] = status
        return jsonify(
            {
                "ok": True,
                "required_replicas": IPFS_MIN_REPLICAS,
                "target_replicas": IPFS_TARGET_REPLICAS,
                "statuses": out,
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/auth/session")
def auth_session():
    record = _refresh_server_session_identity()
    if not record:
        return jsonify({"ok": True, "authenticated": False, "session": None, "bootstrap_needed": _security_bootstrap_needed()}), 200
    return jsonify({"ok": True, "authenticated": True, "session": _current_auth_user(), "bootstrap_needed": _security_bootstrap_needed()}), 200


@app.get("/auth/bootstrap-status")
def auth_bootstrap_status():
    return jsonify({"ok": True, "bootstrap_needed": _security_bootstrap_needed()}), 200


@app.post("/auth/bootstrap-ticket")
def auth_bootstrap_ticket():
    try:
        if not _security_bootstrap_needed():
            raise ValueError("bootstrap already completed")
        mode = "reissue" if _chain_invite_by_username("SecurityService") else "issue"
        payload = _issue_or_reissue_invite(
            username="SecurityService",
            department="Security Office",
            role="SecurityService",
            org="org1",
            actor="SecurityService",
            mode=mode,
        )
        return jsonify(
            {
                "ok": True,
                "invite_token": payload["invite_token"],
                "bootstrap_needed": True,
                "reissued": mode == "reissue",
                "expires_at": payload["expires_at"],
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/login/options")
def auth_login_options():
    try:
        data = _require_json_body()
        username = _validate_username(data.get("username", ""))
        profile = _chain_profile_by_username(username)
        if not isinstance(profile, dict):
            raise ValueError("user not found")
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        if not credentials:
            raise ValueError("passkeys are not registered for this account")
        challenge = _new_challenge_record(kind="login", username=username)
        allow_credentials = [
            {
                "id": item["credentialID"],
                "type": "public-key",
                "transports": item.get("transports") or [],
            }
            for item in credentials
        ]
        return jsonify(
            {
                "ok": True,
                "challenge_id": challenge["id"],
                "publicKey": {
                    "challenge": challenge["challenge"],
                    "rpId": _WEBAUTHN_RP_ID,
                    "allowCredentials": allow_credentials,
                    "userVerification": "required",
                    "timeout": 60000,
                },
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/login/verify")
def auth_login_verify():
    try:
        data = _require_json_body()
        username = _validate_username(data.get("username", ""))
        challenge = _consume_challenge(str(data.get("challenge_id", "")), expected_kind="login", username=username)
        credential = data.get("credential") or {}
        profile = _chain_profile_by_username(username)
        if not isinstance(profile, dict):
            raise ValueError("user not found")
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        credential_id = _norm_simple_text(credential.get("id", ""), 256, collapse=False)
        stored = next((item for item in credentials if item.get("credentialID") == credential_id), None)
        if not stored:
            raise ValueError("credential not registered")
        verify_result = verify_authentication_response(
            credential=credential,
            expected_challenge_b64=challenge["challenge"],
            expected_origin=_WEBAUTHN_ORIGIN,
            expected_rp_id=_WEBAUTHN_RP_ID,
            stored_public_key_pem=stored["publicKeyPEM"],
            stored_sign_count=stored.get("signCount", 0),
        )
        stored["signCount"] = int(verify_result["sign_count"])
        stored["lastUsedAt"] = _utc_now_iso()
        user_handle = str(profile.get("webAuthnUserHandle") or profile.get("WebAuthnUserHandle") or "")
        _security_agent_submit("SyncWebAuthnCredentials", [username, user_handle, json.dumps(credentials, separators=(",", ":"))])
        payload = _session_payload_from_chain_profile(profile)
        if payload.get("status") == "blocked":
            raise ValueError("account is blocked")
        _set_session_from_payload(payload)
        _mark_session_webauthn_verified()
        _record_auth_event("login_success", username, actor=username, details="webauthn")
        return jsonify({"ok": True, "session": _current_auth_user()}), 200
    except Exception as exc:
        attempted_user = _norm_simple_text((request.get_json(silent=True) or {}).get("username", ""), 64, collapse=False)
        if attempted_user:
            _record_auth_event("login_failed", attempted_user, details=str(exc))
        _clear_authenticated_session()
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/reauth/options")
@require_auth
def auth_reauth_options():
    try:
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        profile = _chain_profile_by_username(username)
        if not isinstance(profile, dict):
            raise ValueError("user not found")
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        if not credentials:
            raise ValueError("passkeys are not registered for this account")
        challenge = _new_challenge_record(kind="reauth", username=username)
        return jsonify(
            {
                "ok": True,
                "challenge_id": challenge["id"],
                "publicKey": {
                    "challenge": challenge["challenge"],
                    "rpId": _WEBAUTHN_RP_ID,
                    "allowCredentials": [
                        {
                            "id": item["credentialID"],
                            "type": "public-key",
                            "transports": item.get("transports") or [],
                        }
                        for item in credentials
                    ],
                    "userVerification": "required",
                    "timeout": 60000,
                },
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/reauth/verify")
@require_auth
def auth_reauth_verify():
    try:
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        data = _require_json_body()
        challenge = _consume_challenge(str(data.get("challenge_id", "")), expected_kind="reauth", username=username)
        credential = data.get("credential") or {}
        profile = _chain_profile_by_username(username)
        if not isinstance(profile, dict):
            raise ValueError("user not found")
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        credential_id = _norm_simple_text(credential.get("id", ""), 256, collapse=False)
        stored = next((item for item in credentials if item.get("credentialID") == credential_id), None)
        if not stored:
            raise ValueError("credential not registered")
        verify_result = verify_authentication_response(
            credential=credential,
            expected_challenge_b64=challenge["challenge"],
            expected_origin=_WEBAUTHN_ORIGIN,
            expected_rp_id=_WEBAUTHN_RP_ID,
            stored_public_key_pem=stored["publicKeyPEM"],
            stored_sign_count=stored.get("signCount", 0),
        )
        stored["signCount"] = int(verify_result["sign_count"])
        stored["lastUsedAt"] = _utc_now_iso()
        user_handle = str(profile.get("webAuthnUserHandle") or profile.get("WebAuthnUserHandle") or "")
        _security_agent_submit("SyncWebAuthnCredentials", [username, user_handle, json.dumps(credentials, separators=(",", ":"))])
        _mark_session_webauthn_verified()
        _record_auth_event("reauth_success", username, actor=username)
        return jsonify({"ok": True, "session": _current_auth_user()}), 200
    except Exception as exc:
        user = _current_auth_user() or {}
        if user.get("username"):
            _record_auth_event("reauth_failed", user["username"], actor=user["username"], details=str(exc))
        return jsonify({"ok": False, "error": str(exc), "reauth_required": True}), 400


@app.get("/auth/passkeys")
@require_auth
def auth_list_passkeys():
    try:
        profile = _current_chain_profile()
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        return jsonify({"ok": True, "passkeys": credentials, "count": len(credentials)}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/passkeys/register/options")
@require_auth
def auth_passkey_register_options():
    try:
        _require_recent_webauthn_auth()
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        profile = _current_chain_profile()
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        user_handle = str(profile.get("webAuthnUserHandle") or profile.get("WebAuthnUserHandle") or "")
        if not user_handle:
            user_handle = b64url_encode(hashlib.sha256(username.encode("utf-8")).digest())
        challenge = _new_challenge_record(kind="passkey-register", username=username, extra={"user_handle": user_handle})
        return jsonify(
            {
                "ok": True,
                "challenge_id": challenge["id"],
                "publicKey": {
                    "challenge": challenge["challenge"],
                    "rp": {"name": "SecureData Archive", "id": _WEBAUTHN_RP_ID},
                    "user": {"id": user_handle, "name": username, "displayName": username},
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257},
                    ],
                    "timeout": 60000,
                    "attestation": "none",
                    "authenticatorSelection": {
                        "residentKey": "preferred",
                        "userVerification": "required",
                    },
                    "excludeCredentials": [
                        {
                            "id": item["credentialID"],
                            "type": "public-key",
                            "transports": item.get("transports") or [],
                        }
                        for item in credentials
                    ],
                },
            }
        ), 200
    except PermissionError as exc:
        return jsonify({"ok": False, "error": str(exc), "reauth_required": True}), 428
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/passkeys/register/finish")
@require_auth
def auth_passkey_register_finish():
    try:
        _require_recent_webauthn_auth()
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        data = _require_json_body()
        challenge = _consume_challenge(str(data.get("challenge_id", "")), expected_kind="passkey-register", username=username)
        registration = verify_registration_response(
            credential=data.get("credential") or {},
            expected_challenge_b64=challenge["challenge"],
            expected_origin=_WEBAUTHN_ORIGIN,
            expected_rp_id=_WEBAUTHN_RP_ID,
        )
        profile = _current_chain_profile()
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        if any(item.get("credentialID") == registration["credential_id"] for item in credentials):
            raise ValueError("credential already registered")
        credentials.append(
            {
                "credentialID": registration["credential_id"],
                "publicKeyPEM": registration["public_key_pem"],
                "signCount": int(registration["sign_count"]),
                "transports": registration.get("transports") or [],
                "aaguid": registration.get("aaguid", ""),
                "attestationFormat": registration.get("attestation_format", "none"),
                "label": _norm_simple_text(data.get("label", ""), 128, collapse=True),
                "rpID": _WEBAUTHN_RP_ID,
                "createdAt": _utc_now_iso(),
                "lastUsedAt": "",
            }
        )
        user_handle = str(challenge.get("user_handle") or profile.get("webAuthnUserHandle") or profile.get("WebAuthnUserHandle") or "")
        _security_agent_submit("SyncWebAuthnCredentials", [username, user_handle, json.dumps(credentials, separators=(",", ":"))])
        _mark_session_webauthn_verified()
        _record_auth_event("passkey_added", username, actor=username, details=_norm_simple_text(data.get("label", ""), 128, collapse=True))
        return jsonify({"ok": True, "passkeys": credentials, "count": len(credentials), "session": _current_auth_user()}), 200
    except PermissionError as exc:
        return jsonify({"ok": False, "error": str(exc), "reauth_required": True}), 428
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.delete("/auth/passkeys/<credential_id>")
@require_auth
def auth_passkey_delete(credential_id: str):
    try:
        _require_recent_webauthn_auth()
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        profile = _current_chain_profile()
        credentials = _normalize_webauthn_credentials(profile.get("webAuthnCredentials") or profile.get("WebAuthnCredentials") or [])
        wanted = _norm_simple_text(credential_id, 256, collapse=False)
        remaining = [item for item in credentials if item.get("credentialID") != wanted]
        if len(remaining) == len(credentials):
            raise ValueError("credential not found")
        if len(remaining) < 1:
            raise ValueError("cannot remove the last passkey; register a replacement first")
        user_handle = str(profile.get("webAuthnUserHandle") or profile.get("WebAuthnUserHandle") or "")
        _security_agent_submit("SyncWebAuthnCredentials", [username, user_handle, json.dumps(remaining, separators=(",", ":"))])
        _mark_session_webauthn_verified()
        _record_auth_event("passkey_removed", username, actor=username, details=wanted)
        return jsonify({"ok": True, "count": len(remaining), "session": _current_auth_user()}), 200
    except PermissionError as exc:
        return jsonify({"ok": False, "error": str(exc), "reauth_required": True}), 428
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/recovery/reissue-local-identities")
@require_auth
def auth_recovery_reissue_local_identities():
    try:
        _require_recent_webauthn_auth()
        user = _current_auth_user() or {}
        username = _validate_username(user.get("username", ""))
        profile = _current_chain_profile()
        recovery = profile.get("recoveryBundle") or profile.get("RecoveryBundle") or {}
        if bool(recovery.get("created")):
            return jsonify(
                {
                    "ok": False,
                    "error": "an existing recovery bundle is already recorded for this account",
                    "error_code": "RECOVERY_REISSUE_NOT_ALLOWED",
                }
            ), 409

        data = _require_json_body()
        content_public_key = str(data.get("content_public_key", "") or "").strip()
        if not content_public_key:
            raise ValueError("content_public_key is required")
        content_key_fingerprint = _norm_simple_text(data.get("content_key_fingerprint", ""), 256, collapse=False)
        fabric_csr_pem = str(data.get("fabric_csr_pem", "") or "").strip()
        if "BEGIN CERTIFICATE REQUEST" not in fabric_csr_pem:
            raise ValueError("fabric_csr_pem is invalid")

        user_id = str(profile.get("userID") or profile.get("userId") or user.get("client_id") or "").strip()
        if not user_id:
            raise ValueError("user profile is missing userID")

        blockers = _local_identity_reissue_blockers(user_id)
        if blockers["owned_asset_ids"] or blockers["shared_asset_ids"]:
            return jsonify(
                {
                    "ok": False,
                    "error": "automatic recovery repair is blocked because this account already owns files or has encrypted asset access bound to the old device key",
                    "error_code": "RECOVERY_REISSUE_BLOCKED_DATA_EXISTS",
                    "owned_assets": blockers["owned_asset_ids"],
                    "shared_assets": blockers["shared_asset_ids"],
                }
            ), 409

        org = _org_from_msp(str(profile.get("mspID") or profile.get("mspId") or user.get("msp_id") or "Org1MSP"))
        role = _norm_simple_text(profile.get("role") or user.get("role") or "Researcher", 64, collapse=True)
        department = _norm_simple_text(profile.get("department") or user.get("department") or "IT Department", 128, collapse=True)
        enrollment_secret = secrets.token_urlsafe(18)
        _fabric_ca_modify_identity_secret(
            username=username,
            enrollment_secret=enrollment_secret,
            role=role,
            department=department,
            org=org,
            max_enrollments="-1",
        )
        fabric_cert = _fabric_ca_enroll_csr(
            org=org,
            username=username,
            enrollment_secret=enrollment_secret,
            csr_pem=fabric_csr_pem,
        )
        reissued_user_id = _fabric_client_id_from_cert(fabric_cert)
        if reissued_user_id != user_id:
            raise ValueError("reissued certificate does not match the current user identity")

        _security_agent_submit(
            "ReissueActivatedUserLocalIdentities",
            [user_id, username, content_public_key, content_key_fingerprint, fabric_cert],
        )

        updated_profile = _chain_profile_by_username(username) or {}
        payload = _session_payload_from_chain_profile(
            updated_profile
            or {
                "username": username,
                "department": department,
                "role": role,
                "mspID": str(profile.get("mspID") or profile.get("mspId") or "Org1MSP"),
                "userID": user_id,
                "fabricCert": fabric_cert,
            }
        )
        _set_session_from_payload(payload)
        _record_auth_event("recovery_reissue_success", username, actor=username, details=f"org={org}")
        return jsonify(
            {
                "ok": True,
                "session": _current_auth_user(),
                "fabric_certificate": fabric_cert,
                "msp_id": payload.get("msp_id", str(profile.get("mspID") or profile.get("mspId") or "Org1MSP")),
                "client_id": user_id,
                "org": org,
                "content_public_key": content_public_key,
                "content_key_fingerprint": content_key_fingerprint,
            }
        ), 200
    except PermissionError as exc:
        return jsonify({"ok": False, "error": str(exc), "error_code": "RECOVERY_REISSUE_FAILED", "reauth_required": True}), 428
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc), "error_code": "RECOVERY_REISSUE_FAILED"}), 400
    except Exception as exc:
        app.logger.exception("recovery reissue failed")
        try:
            current_user = _current_auth_user() or {}
            attempted_username = _norm_simple_text(current_user.get("username", ""), 64, collapse=False)
            if attempted_username:
                _record_auth_event("recovery_reissue_failed", attempted_username, actor=attempted_username, details=str(exc))
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(exc), "error_code": "RECOVERY_REISSUE_FAILED"}), 400


@app.post("/auth/activate/options")
def auth_activate_options():
    try:
        data = _require_json_body()
        ticket = _verify_invite_token(data.get("invite_token", ""))
        _require_pending_invite(ticket)
        username = _validate_username(ticket.get("username", ""))
        user_handle = b64url_encode(hashlib.sha256(f"{username}:{ticket.get('invite_id', '')}".encode("utf-8")).digest())
        challenge = _new_challenge_record(kind="activation", username=username, extra={"invite_id": ticket.get("invite_id", ""), "ticket": ticket, "user_handle": user_handle})
        return jsonify(
            {
                "ok": True,
                "challenge_id": challenge["id"],
                "user": {
                    "username": username,
                    "department": ticket.get("department", ""),
                    "role": ticket.get("role", ""),
                    "org": ticket.get("org", "org1"),
                    "user_handle": user_handle,
                },
                "publicKey": {
                    "challenge": challenge["challenge"],
                    "rp": {"name": "SecureData Archive", "id": _WEBAUTHN_RP_ID},
                    "user": {
                        "id": user_handle,
                        "name": username,
                        "displayName": username,
                    },
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257},
                    ],
                    "timeout": 60000,
                    "attestation": "none",
                    "authenticatorSelection": {
                        "residentKey": "preferred",
                        "userVerification": "required",
                    },
                },
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/activate/finish")
def auth_activate_finish():
    try:
        data = _require_json_body()
        ticket = _verify_invite_token(data.get("invite_token", ""))
        _require_pending_invite(ticket)
        username = _validate_username(ticket.get("username", ""))
        challenge = _consume_challenge(str(data.get("challenge_id", "")), expected_kind="activation", username=username)
        registration = verify_registration_response(
            credential=data.get("credential") or {},
            expected_challenge_b64=challenge["challenge"],
            expected_origin=_WEBAUTHN_ORIGIN,
            expected_rp_id=_WEBAUTHN_RP_ID,
        )
        content_public_key = str(data.get("content_public_key", "") or "").strip()
        if not content_public_key:
            raise ValueError("content_public_key is required")
        content_key_fingerprint = _norm_simple_text(data.get("content_key_fingerprint", ""), 256, collapse=False)
        fabric_csr_pem = str(data.get("fabric_csr_pem", "") or "").strip()
        if "BEGIN CERTIFICATE REQUEST" not in fabric_csr_pem:
            raise ValueError("fabric_csr_pem is invalid")

        org = _norm_simple_text(ticket.get("org", "org1"), 16, collapse=True).lower()
        role = _norm_simple_text(ticket.get("role", "Researcher"), 64, collapse=True)
        department = _norm_simple_text(ticket.get("department", "IT Department"), 128, collapse=True)
        invite_id = _norm_simple_text(ticket.get("invite_id", ""), 128, collapse=False)
        enrollment_secret = str(ticket.get("secret") or "").strip()
        if not enrollment_secret:
            raise ValueError("invite secret is missing")

        _fabric_ca_register_identity(
            username=username,
            enrollment_secret=enrollment_secret,
            role=role,
            department=department,
            org=org,
        )
        fabric_cert = _fabric_ca_enroll_csr(
            org=org,
            username=username,
            enrollment_secret=enrollment_secret,
            csr_pem=fabric_csr_pem,
        )
        msp_id = _org_runtime_settings(org)["msp_id"]
        user_id = _fabric_client_id_from_cert(fabric_cert)
        cred_record = {
            "credentialID": registration["credential_id"],
            "publicKeyPEM": registration["public_key_pem"],
            "signCount": int(registration["sign_count"]),
            "transports": registration.get("transports") or [],
            "aaguid": registration.get("aaguid", ""),
            "attestationFormat": registration.get("attestation_format", "none"),
            "label": _norm_simple_text(data.get("webauthn_label", ""), 128, collapse=True),
            "rpID": _WEBAUTHN_RP_ID,
            "createdAt": _utc_now_iso(),
            "lastUsedAt": "",
        }
        user_handle = str(challenge.get("user_handle") or "")
        _security_agent_submit(
            "ActivateEnrollmentInvite",
            [
                user_id,
                username,
                msp_id,
                content_public_key,
                content_key_fingerprint,
                fabric_cert,
                user_handle,
                json.dumps([cred_record], separators=(",", ":")),
                invite_id,
            ],
        )
        profile = _chain_profile_by_username(username) or {}
        payload = _session_payload_from_chain_profile(profile or {
            "username": username,
            "department": department,
            "role": role,
            "mspID": msp_id,
            "userID": user_id,
            "fabricCert": fabric_cert,
        })
        _set_session_from_payload(payload)
        _record_auth_event("activation_success", username, actor=username, details=f"org={org}")
        return jsonify(
            {
                "ok": True,
                "session": _current_auth_user(),
                "fabric_certificate": fabric_cert,
                "msp_id": msp_id,
                "client_id": user_id,
                "org": org,
                "content_public_key": content_public_key,
                "content_key_fingerprint": content_key_fingerprint,
            }
        ), 200
    except Exception as exc:
        app.logger.exception("activation finish failed")
        attempted_user = ""
        try:
            body = request.get_json(silent=True) or {}
            if body.get("invite_token"):
                attempted_user = _norm_simple_text(_verify_invite_token(body.get("invite_token", "")).get("username", ""), 64, collapse=False)
        except Exception:
            attempted_user = ""
        if attempted_user:
            _record_auth_event("activation_failed", attempted_user, details=str(exc))
        _clear_authenticated_session()
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/logout")
def auth_logout():
    user = _current_auth_user()
    if user:
        _record_auth_event("logout", user["username"], actor=user["username"])
    _clear_authenticated_session()
    return jsonify({"ok": True}), 200


@app.post("/auth/change-password")
@require_auth
def auth_change_password():
    return jsonify({"ok": False, "error": "passwords are removed; use passkeys instead"}), 400


@app.get("/auth/users")
@require_security_session
def auth_users():
    try:
        profiles = _security_agent_eval("GetAllUserProfiles", [])
        invites = _chain_invites()
        by_username: dict[str, dict] = {}
        if isinstance(profiles, list):
            for item in profiles:
                if not isinstance(item, dict):
                    continue
                username = str(item.get("username") or item.get("Username") or "").strip()
                if not username:
                    continue
                stats = _auth_stats(username)
                recovery = item.get("recoveryBundle") or item.get("RecoveryBundle") or {}
                webauthn = item.get("webAuthnIdentity") or item.get("WebAuthnIdentity") or {}
                enc = item.get("dataEncryptionIdentity") or item.get("DataEncryptionIdentity") or {}
                fabric = item.get("fabricSigningIdentity") or item.get("FabricSigningIdentity") or {}
                by_username[username] = {
                    "username": username,
                    "display_name": username,
                    "role": str(item.get("role") or item.get("Role") or "Researcher"),
                    "department": str(item.get("department") or item.get("Department") or ""),
                    "msp_id": str(item.get("mspID") or item.get("mspId") or ""),
                    "user_id": str(item.get("userID") or item.get("userId") or ""),
                    "status": "blocked" if bool(item.get("isBlocked") or item.get("IsBlocked")) else "active",
                    "last_login": stats["last_login"],
                    "login_count": stats["login_count"],
                    "has_passkey": bool(item.get("webAuthnCredentials") or item.get("WebAuthnCredentials")),
                    "invite_status": "",
                    "invite_expires_at": "",
                    "recovery_bundle_required": bool(recovery.get("required")),
                    "recovery_bundle_created": bool(recovery.get("created")),
                    "recovery_bundle_created_at": str(recovery.get("createdAt") or ""),
                    "passkey_count": len(webauthn.get("credentials") or item.get("webAuthnCredentials") or []),
                    "has_encryption_identity": bool(enc.get("publicKey") or item.get("publicKey")),
                    "has_fabric_identity": bool(fabric.get("certificate") or item.get("fabricCert")),
                }
        for invite in invites:
            username = str(invite.get("username") or invite.get("Username") or "").strip()
            if not username:
                continue
            invite_status = _normalized_invite_status(str(invite.get("status") or invite.get("Status") or ""))
            row = by_username.get(username, {
                "username": username,
                "display_name": username,
                "role": str(invite.get("role") or "Researcher"),
                "department": str(invite.get("department") or ""),
                "msp_id": "",
                "user_id": str(invite.get("userID") or ""),
                "status": invite_status,
                "last_login": "",
                "login_count": 0,
                "has_passkey": False,
                "recovery_bundle_required": False,
                "recovery_bundle_created": False,
                "recovery_bundle_created_at": "",
                "passkey_count": 0,
                "has_encryption_identity": False,
                "has_fabric_identity": False,
            })
            row["invite_status"] = invite_status
            row["invite_expires_at"] = str(invite.get("expiresAt") or "")
            if row.get("status") == "pending" and invite_status == "activated":
                row["status"] = "active"
            by_username[username] = row
        result = list(by_username.values())
        result.sort(key=lambda item: (item.get("username") or "").lower())
        return jsonify({"ok": True, "users": result}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/auth/audit")
@require_security_session
def auth_audit():
    items = list(reversed(_AUTH_AUDIT)) if _AUTH_AUDIT else list(reversed(_tail_jsonl_audit("auth")))
    return jsonify({"ok": True, "items": items}), 200


@app.get("/audit/disp")
@require_security_session
def audit_disp():
    """Expose DISP sanitizer decisions from memory or the persistent JSONL log."""
    items = list(reversed(_SERVER_AUDIT)) if _SERVER_AUDIT else list(reversed(_tail_jsonl_audit("disp")))
    return jsonify({"ok": True, "items": items}), 200


@app.post("/auth/users")
@require_security_session
def auth_create_user():
    try:
        data = _require_json_body()
        username = _validate_username(data.get("username", ""))
        role = _norm_simple_text(data.get("role", "Researcher"), 64, collapse=True)
        department = _norm_simple_text(data.get("department", ""), 128, collapse=True) or "IT Department"
        org = _norm_simple_text(data.get("org", "org1"), 16, collapse=True).lower()
        created = _issue_or_reissue_invite(
            username=username,
            department=department,
            role=role,
            org=org,
            actor=_current_auth_user().get("username", "SecurityService"),
            mode="issue",
        )
        return jsonify(
            {
                "ok": True,
                "user": created,
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/users/<username>/reissue")
@require_security_session
def auth_reissue_user_invite(username: str):
    try:
        payload = _issue_or_reissue_invite(
            username=username,
            department="",
            role="Researcher",
            org="org1",
            actor=_current_auth_user().get("username", "SecurityService"),
            mode="reissue",
        )
        return jsonify({"ok": True, "user": payload}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/auth/users/<username>/revoke")
@require_security_session
def auth_revoke_user_invite(username: str):
    try:
        normalized_username = _validate_username(username)
        invite = _chain_invite_by_username(normalized_username)
        if not invite:
            raise ValueError("invite not found")
        org = _norm_simple_text(invite.get("org") or "org1", 16, collapse=True).lower()
        data = _require_json_body() if request.data else {}
        reason = _norm_simple_text((data or {}).get("reason", ""), 256, collapse=True)
        # Revoke is the cryptographic operation we actually want here.
        # 'identity remove' needs CA cfg.identities.allowremove=true and would
        # fail with Error Code 56 on default configurations.
        _fabric_ca_revoke_identity(
            username=normalized_username,
            org=org,
            reason=reason or "administrative",
        )
        _fabric_ca_disable_identity(username=normalized_username, org=org)
        _security_agent_submit("RevokeEnrollmentInvite", [normalized_username, reason])
        _record_auth_event(
            "invite_revoked",
            normalized_username,
            actor=_current_auth_user().get("username", "SecurityService"),
            details=reason,
        )
        return jsonify({"ok": True}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/agent/service-identity/<role>")
@require_security_session
def agent_service_identity(role: str):
    """
    Return the Fabric clientID seen by the unified Go agent under a
    specific service role (e.g. MLService).  The frontend uses this to
    discover the current MLService clientID for BindServiceIdentity,
    instead of talking to a second agent process on localhost:8091 -
    that port does not exist in the unified deployment and would
    surface to the browser as an opaque 'Failed to fetch'.
    """
    try:
        role_norm = _norm_simple_text(role or "", 32, collapse=True)
        if role_norm not in _VALID_AGENT_ROLES:
            raise ValueError(f"unknown role: {role_norm}")
        who = _agent_eval_as_role(role_norm, "WhoAmI", [])
        if isinstance(who, str):
            try:
                who = json.loads(who)
            except Exception:
                who = {"clientID": who}
        client_id = ""
        msp_id = ""
        if isinstance(who, dict):
            client_id = str(who.get("clientID") or who.get("clientId") or who.get("id") or "").strip()
            msp_id = str(who.get("mspID") or who.get("mspId") or "").strip()
        if not client_id:
            raise RuntimeError("agent did not return a clientID")
        return jsonify({"ok": True, "role": role_norm, "client_id": client_id, "msp_id": msp_id}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.delete("/auth/users/<username>")
@require_security_session
def auth_delete_pending_user(username: str):
    try:
        normalized_username = _validate_username(username)
        invite = _chain_invite_by_username(normalized_username)
        if not invite:
            raise ValueError("invite not found")
        org = _norm_simple_text(invite.get("org") or "org1", 16, collapse=True).lower()
        _fabric_ca_remove_identity(username=normalized_username, org=org)
        _security_agent_submit("DeletePendingUser", [normalized_username])
        _record_auth_event("pending_user_deleted", normalized_username, actor=_current_auth_user().get("username", "SecurityService"))
        return jsonify({"ok": True}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/fabric/eval")
@require_auth
def fabric_eval():
    try:
        data = _require_json_body()
        user = _current_auth_user() or {}
        profile = _current_chain_profile()
        flow_id = str(data.get("flow_id", "") or "").strip()
        if flow_id:
            flow = _get_offline_flow(flow_id)
            if flow.get("username") != user.get("username"):
                raise ValueError("fabric signing flow does not belong to current user")
            if flow.get("type") != "eval" or flow.get("stage") != "await-proposal-signature":
                raise ValueError("invalid fabric eval stage")
            signature_b64 = str(data.get("signature_b64", "") or "").strip()
            if not signature_b64:
                raise ValueError("signature_b64 is required")
            result = _agent_offline_exec(
                "offline-evaluate-signed",
                str(profile.get("fabricCert") or profile.get("FabricCert") or user.get("fabric_cert") or ""),
                str(flow.get("proposal_bytes_b64") or ""),
                [signature_b64],
            )
            _delete_offline_flow(flow_id)
            if "resultJSON" in result:
                return jsonify({"ok": True, "result": result["resultJSON"], "tx_id": result.get("transactionID", "")}), 200
            return jsonify({"ok": True, "result": result.get("ResultText", result.get("resultText", "")), "tx_id": result.get("transactionID", "")}), 200

        fn = _norm_simple_text(data.get("function", ""), 128, collapse=True)
        args = [str(a) for a in (data.get("args") or [])]
        if not fn:
            raise ValueError("function is required")
        prepared = _agent_offline_exec(
            "offline-prepare-eval",
            str(profile.get("fabricCert") or profile.get("FabricCert") or user.get("fabric_cert") or ""),
            fn,
            args,
        )
        flow_id = _store_offline_flow(
            {
                "type": "eval",
                "stage": "await-proposal-signature",
                "username": user.get("username", ""),
                "proposal_bytes_b64": prepared.get("proposalBytesB64", ""),
            }
        )
        return jsonify(
            {
                "ok": True,
                "needs_signature": True,
                "flow_id": flow_id,
                "stage": "proposal",
                "sign_input_b64": prepared.get("proposalSignB64", ""),
                "tx_id": prepared.get("transactionID", ""),
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/fabric/submit")
@require_auth
def fabric_submit():
    try:
        data = _require_json_body()
        user = _current_auth_user() or {}
        profile = _current_chain_profile()
        cert_pem = str(profile.get("fabricCert") or profile.get("FabricCert") or user.get("fabric_cert") or "")
        flow_id = str(data.get("flow_id", "") or "").strip()
        if flow_id:
            flow = _get_offline_flow(flow_id)
            if flow.get("username") != user.get("username"):
                raise ValueError("fabric signing flow does not belong to current user")
            if flow.get("type") != "submit":
                raise ValueError("invalid fabric submit flow")
            if flow.get("sensitive_webauthn"):
                _require_recent_webauthn_auth()
            if flow.get("stage") == "await-proposal-signature":
                signature_b64 = str(data.get("signature_b64", "") or "").strip()
                if not signature_b64:
                    raise ValueError("signature_b64 is required")
                endorsed = _agent_offline_exec(
                    "offline-endorse-signed",
                    cert_pem,
                    str(flow.get("proposal_bytes_b64") or ""),
                    [signature_b64],
                )
                _update_offline_flow(
                    flow_id,
                    {
                        "stage": "await-transaction-signature",
                        "transaction_bytes_b64": endorsed.get("transactionBytesB64", ""),
                        "tx_id": endorsed.get("transactionID", ""),
                    },
                )
                return jsonify(
                    {
                        "ok": True,
                        "needs_signature": True,
                        "flow_id": flow_id,
                        "stage": "transaction",
                        "sign_input_b64": endorsed.get("transactionSignB64", ""),
                        "tx_id": endorsed.get("transactionID", ""),
                        "preview_result": endorsed.get("resultJSON", endorsed.get("ResultText", endorsed.get("resultText", ""))),
                    }
                ), 200
            if flow.get("stage") == "await-transaction-signature":
                signature_b64 = str(data.get("signature_b64", "") or "").strip()
                if not signature_b64:
                    raise ValueError("signature_b64 is required")
                submitted = _agent_offline_exec(
                    "offline-submit-signed",
                    cert_pem,
                    str(flow.get("transaction_bytes_b64") or ""),
                    [signature_b64],
                )
                _delete_offline_flow(flow_id)
                if "resultJSON" in submitted:
                    result_json = submitted["resultJSON"]
                    if flow.get("function") == "RequestMyEncryptedKey":
                        status = str((result_json or {}).get("status") or (result_json or {}).get("Status") or "").upper()
                        args = list(flow.get("args") or [])
                        if status == "OK" and args:
                            _record_download_grant(str(args[0]))
                    return jsonify({"ok": True, "result": result_json, "tx_id": submitted.get("transactionID", "")}), 200
                return jsonify({"ok": True, "result": submitted.get("ResultText", submitted.get("resultText", "")), "tx_id": submitted.get("transactionID", "")}), 200
            raise ValueError("invalid fabric submit stage")

        fn = _norm_simple_text(data.get("function", ""), 128, collapse=True)
        args = [str(a) for a in (data.get("args") or [])]
        if not fn:
            raise ValueError("function is required")
        sensitive_webauthn = fn in {"MarkRecoveryBundleCreated"}
        if sensitive_webauthn:
            _require_recent_webauthn_auth()
        prepared = _agent_offline_exec("offline-prepare-eval", cert_pem, fn, args)
        flow_id = _store_offline_flow(
            {
                "type": "submit",
                "stage": "await-proposal-signature",
                "username": user.get("username", ""),
                "proposal_bytes_b64": prepared.get("proposalBytesB64", ""),
                "tx_id": prepared.get("transactionID", ""),
                "sensitive_webauthn": sensitive_webauthn,
                "function": fn,
                "args": args,
            }
        )
        return jsonify(
            {
                "ok": True,
                "needs_signature": True,
                "flow_id": flow_id,
                "stage": "proposal",
                "sign_input_b64": prepared.get("proposalSignB64", ""),
                "tx_id": prepared.get("transactionID", ""),
            }
        ), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/upload")
@require_auth
def upload_handler():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file"}), 400
    file = request.files["file"]

    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
    except Exception:
        size = 0

    ok, msg = validate_filename_policy(file.filename, size)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400

    try:
        file_bytes = file.read()
    except Exception:
        file_bytes = b""

    ok_blob, blob_msg = _validate_encrypted_blob(file_bytes)
    if not ok_blob:
        return jsonify({"status": "error", "message": blob_msg}), 400

    raw_meta = {
        "description": request.form.get("description", ""),
        "title": request.form.get("title", ""),
        "authors": request.form.get("authors", ""),
        "discipline": request.form.get("discipline", ""),
        "license": request.form.get("license", ""),
        "doi": request.form.get("doi", ""),
        "keywords": request.form.get("keywords", ""),
        "owner": request.form.get("owner", session.get("username", "")),
        "encryptedAesKey": request.form.get("encryptedAesKey", ""),
        "fileHash": request.form.get("fileHash", ""),
    }

    disp = sanitize_upload_metadata(raw_meta)
    req_id = disp.request_hash[:16]

    _append_audit(
        audit_record(
            req_id=req_id,
            result=disp,
            extra={
                "endpoint": "/upload",
                "remote": request.remote_addr,
                "filename": file.filename,
                "size": len(file_bytes),
            },
        )
    )

    if disp.decision == "reject":
        return jsonify({
            "status": "error",
            "message": "Input rejected by security policy",
            "disp_decision": disp.decision,
            "disp_score": disp.risk_score,
            "disp_flags": disp.flags,
            "disp_reasons": disp.reasons,
        }), 400

    title = disp.sanitized_payload["title"]
    authors = disp.sanitized_payload["authors"]
    discipline = disp.sanitized_payload["discipline"]
    keywords = disp.sanitized_payload["keywords"]
    desc = disp.sanitized_payload["description"]

    # Согласованный текст, как в обучении
    ai_text = build_ai_text(title=title, authors=authors, abstract=desc, keywords=keywords)

    predicted_label, confidence_pct = predict_category_and_confidence(ai_text)

    ai_trusted = (disp.decision == "allow")
    suspicious = not ai_trusted

    asset_id = f"asset_{disp.sanitized_payload['fileHash'][:8]}"
    envelope_aad = _content_envelope_aad(file_bytes)
    if envelope_aad:
        aad_file_hash = _norm_simple_text(envelope_aad.get("fileHash", ""), 128, collapse=False)
        aad_asset_id = _norm_simple_text(envelope_aad.get("assetId", ""), 128, collapse=True)
        if aad_file_hash and aad_file_hash.lower() != disp.sanitized_payload["fileHash"].lower():
            return jsonify({"status": "error", "message": "Encrypted payload AAD fileHash mismatch"}), 400
        if aad_asset_id and aad_asset_id != asset_id:
            return jsonify({"status": "error", "message": "Encrypted payload AAD assetId mismatch"}), 400
    try:
        replication = replicate_bytes_to_ipfs(file_bytes, filename=file.filename, asset_id=asset_id)
        cid = replication.get("cid") or ""
    except Exception as e:
        return jsonify({"status": "error", "message": f"IPFS replication failed: {str(e)}"}), 503
    if not _ipfs_storage_available(replication):
        return jsonify({
            "status": "error",
            "message": replication.get("last_error") or "IPFS replication quorum was not reached",
            "storage": replication,
        }), 503

    return jsonify(
        {
            "status": "success",
            "cid": cid,
            "asset_id": asset_id,
            "storage": replication,
            "ai_suggested_category": predicted_label,
            "ai_confidence": confidence_pct,
            "ai_trusted": ai_trusted,
            "ai_suspicious": suspicious,
            "initial_category": "Unverified",
            "disp_decision": disp.decision,
            "disp_score": disp.risk_score,
            "disp_flags": disp.flags,
            "disp_reasons": disp.reasons,
            "fileHash": disp.sanitized_payload["fileHash"],
            "owner": disp.sanitized_payload["owner"],
            "encryptedAesKey": disp.sanitized_payload["encryptedAesKey"],
            "description": desc,
            "title": title,
            "authors": authors,
            "discipline": discipline,
            "license": disp.sanitized_payload["license"],
            "doi": disp.sanitized_payload["doi"],
            "keywords": keywords,
            "note": "Encrypted payload was stored in IPFS. The UI should commit metadata through the session-backed /fabric API."
        }
    ), 200


@app.post("/download/asset/<asset_id>")
@require_auth
def download_encrypted_asset(asset_id: str):
    asset_id = _norm_simple_text(asset_id, 128, collapse=True)
    if not asset_id:
        return jsonify({"ok": False, "error": "asset_id is required"}), 400
    if not _has_recent_download_grant(asset_id):
        return jsonify({"ok": False, "error": "download requires a recent successful RequestMyEncryptedKey transaction"}), 403
    try:
        asset = _security_agent_eval("ReadAsset", [asset_id])
        cid = _norm_simple_text(
            (asset or {}).get("cidHash") or (asset or {}).get("CIDHash") or (asset or {}).get("cid") or (asset or {}).get("CID") or "",
            256,
            collapse=False,
        )
        if IPFS_STRICT_CID and not _looks_like_ipfs_cid(cid):
            return jsonify({"ok": False, "error": "asset CID is missing or invalid"}), 404
        data = cat_from_ipfs(cid)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return Response(data, status=200, mimetype="application/octet-stream")


@app.get("/download/<cid>")
@require_auth
def download_encrypted_file(cid: str):
    if os.getenv("ALLOW_DIRECT_CID_DOWNLOADS", "0") != "1":
        return jsonify({"ok": False, "error": "direct CID download is disabled; use /download/asset/<assetId>"}), 403
    try:
        data = cat_from_ipfs(cid)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return Response(data, status=200, mimetype="application/octet-stream")


@app.post("/ai_suggest")
@require_auth
def ai_suggest_handler():
    data = request.get_json(silent=True) or {}
    asset_id = _norm_simple_text(data.get("asset_id", ""), 128)
    suggested = _norm_simple_text(data.get("suggested_category", ""), 64)
    conf = data.get("confidence", None)

    if not asset_id or not suggested:
        return jsonify({"status": "error", "message": "Required fields missing"}), 400

    conf_val = _normalize_ai_confidence(conf if conf is not None else 0.0)
    if conf_val is None:
        conf_val = 0.0

    _append_audit({
        "ts": time.time(),
        "endpoint": "/ai_suggest",
        "asset_id": asset_id,
        "suggested": suggested,
        "confidence": conf_val,
    })

    if not _ai_suggestion_meets_threshold(suggested, conf_val):
        return jsonify({
            "status": "ignored",
            "message": "AI suggestion is not actionable enough to store on-chain",
            "suggested_category": suggested,
            "confidence": conf_val,
            "min_confidence": AUTO_SUGGEST_MIN_CONF,
        }), 200

    try:
        try:
            result = ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf_val:.2f}", "user-api"])
        except Exception:
            result = ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf_val:.2f}"])

        return jsonify({"status": "success", "agent_result": result}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"ML agent call failed: {e}"}), 502


@app.post("/ai_suggest_auto")
@require_auth
def ai_suggest_auto_handler():
    data = request.get_json(silent=True) or {}
    asset_id = _norm_simple_text(str(data.get("asset_id", "")), 128)
    if not asset_id:
        return jsonify({"status": "error", "message": "asset_id is required"}), 400

    # Short-circuit: if caller already has inference results (e.g. from /upload),
    # skip a second SciBERT pass and go straight to on-chain storage.
    precomp_suggested = _norm_simple_text(str(data.get("suggested_category", "")), 64)
    precomp_conf = data.get("confidence", None)
    if precomp_suggested and precomp_conf is not None:
        try:
            conf_val = _normalize_ai_confidence(precomp_conf)
            if conf_val is None:
                raise ValueError("confidence is invalid")
            actionable = _ai_suggestion_meets_threshold(precomp_suggested, conf_val)
            stored = False
            if actionable:
                try:
                    ml_submit("AddSuggestedCategory", [asset_id, precomp_suggested, f"{conf_val:.2f}"])
                    stored = True
                except Exception as e:
                    _append_audit({"error": f"ml_submit failed: {e}", "asset_id": asset_id})
            return jsonify({
                "status": "ok",
                "suggested_category": precomp_suggested,
                "confidence": conf_val,
                "min_confidence": AUTO_SUGGEST_MIN_CONF,
                "stored_on_chain": stored,
                "actionable": actionable,
            }), 200
        except (ValueError, TypeError):
            pass  # fall through to full inference below

    meta = data.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}

    disp_meta = sanitize_metadata_only({
        "title": meta.get("title", ""),
        "authors": meta.get("author", meta.get("authors", "")),
        "discipline": meta.get("department", meta.get("discipline", "")),
        "keywords": meta.get("keywords", ""),
        "description": meta.get("description", ""),
    })

    _append_audit(
        audit_record(
            req_id=disp_meta.request_hash[:16],
            result=disp_meta,
            extra={"endpoint": "/ai_suggest_auto", "asset_id": asset_id},
        )
    )

    if disp_meta.decision == "reject":
        return jsonify({"status": "error", "message": "Input rejected by security policy"}), 400

    features = {
        "title": disp_meta.sanitized_payload["title"],
        "author": disp_meta.sanitized_payload["authors"],
        "department": disp_meta.sanitized_payload["discipline"],
        "description": disp_meta.sanitized_payload["description"],
        "keywords": disp_meta.sanitized_payload["keywords"],
    }

    suggested, conf_val = predict_category_and_confidence(features)
    if conf_val is None:
        conf_val = 0.0

    stored = False
    actionable = _ai_suggestion_meets_threshold(str(suggested), float(conf_val))
    if actionable:
        try:
            ml_submit("AddSuggestedCategory", [asset_id, str(suggested), f"{float(conf_val):.2f}"])
            stored = True
        except Exception as e:
            _append_audit({"error": f"ml_submit failed: {e}", "asset_id": asset_id})

    return jsonify({
        "status": "ok",
        "suggested_category": str(suggested),
        "confidence": float(conf_val),
        "min_confidence": AUTO_SUGGEST_MIN_CONF,
        "stored_on_chain": stored,
        "actionable": actionable,
    }), 200

# -----------------------------
# Managed subprocesses (Fabric agent, AI service)
# -----------------------------
class _ManagedProcess:
    """Minimal subprocess supervisor: start, stream stdout, stop on exit."""

    def __init__(self, name: str, cmd: list[str], *, cwd: str | None = None, env: dict | None = None):
        self.name = name
        self.cmd = cmd
        self.cwd = cwd
        self.env = env
        self.proc: subprocess.Popen | None = None

    def start(self) -> bool:
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                env=self.env,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except Exception as exc:
            log.warning("Failed to auto-start %s: %s", self.name, exc)
            self.proc = None
            return False
        log.info("%s auto-started (pid=%d)", self.name, self.proc.pid)
        threading.Thread(target=self._stream, daemon=True).start()
        return True

    def _stream(self):
        stream = self.proc.stdout if self.proc else None
        if stream is None:
            return
        for line in stream:
            log.info("[%s] %s", self.name, line.decode("utf-8", errors="replace").rstrip())

    def stop(self, timeout: float = 5.0):
        if self.proc is None or self.proc.poll() is not None:
            return
        log.info("Stopping %s (pid=%d)...", self.name, self.proc.pid)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None


_MANAGED_PROCESSES: list[_ManagedProcess] = []


def _stop_managed_processes():
    for p in _MANAGED_PROCESSES:
        try:
            p.stop()
        except Exception:
            pass


atexit.register(_stop_managed_processes)


def _autostart_fabric_agent():
    """Start the unified Go Fabric agent as a subprocess if AGENT_AUTOSTART=1."""
    global _AGENT_PROCESS, _SECURITY_AGENT_TOKEN
    if not _AGENT_AUTOSTART:
        log.info("AGENT_AUTOSTART=0, skipping Go agent auto-start")
        return
    env = os.environ.copy()
    env["PATH"] = _FABRIC_BIN_DIR + (os.pathsep + env.get("PATH", "") if env.get("PATH") else "")
    env["FABRIC_PATH"] = _FABRIC_PATH
    # Auth is required by the Go agent by default. When backend auto-starts
    # the agent, we mint a token (if none is configured) and share it with
    # both sides so the handshake just works.
    auth_disabled = os.getenv("AGENT_DISABLE_AUTH", "").strip().lower() in {"1", "true"}
    if not auth_disabled and not _SECURITY_AGENT_TOKEN:
        _SECURITY_AGENT_TOKEN = secrets.token_urlsafe(32)
        os.environ["SECURITY_AGENT_TOKEN"] = _SECURITY_AGENT_TOKEN
        log.info("Generated a shared AGENT_TOKEN for backend <-> agent")
    if _SECURITY_AGENT_TOKEN:
        env["AGENT_TOKEN"] = _SECURITY_AGENT_TOKEN
    if _AGENT_BIN_PATH.exists():
        cmd = [str(_AGENT_BIN_PATH), "serve-unified"]
        cwd = None
    else:
        cmd = ["go", "run", ".", "serve-unified"]
        cwd = str(_AGENT_WORKDIR)
    p = _ManagedProcess("agent", cmd, cwd=cwd, env=env)
    if p.start():
        _AGENT_PROCESS = p.proc
        _MANAGED_PROCESSES.append(p)


def _autostart_ai_service():
    """Start the AI service as a subprocess if AI_SERVICE_AUTOSTART=1."""
    if os.getenv("AI_SERVICE_AUTOSTART", "0") != "1":
        return False
    ai_service_dir = _APP_ROOT / "ai_service"
    if not (ai_service_dir / "main.py").exists():
        log.warning("ai_service/main.py not found, skipping AI service auto-start")
        return False
    env = os.environ.copy()
    cmd = [
        "python", "-m", "uvicorn", "main:app",
        "--host", "127.0.0.1",
        "--port", os.getenv("AI_SERVICE_PORT", "8100"),
    ]
    p = _ManagedProcess("ai_service", cmd, cwd=str(ai_service_dir), env=env)
    if p.start():
        _MANAGED_PROCESSES.append(p)
        return True
    return False


def _probe_ai_service_in_background(ai_autostarted: bool):
    """Kick off AI health probing on startup. SciBERT load is slow when
    we auto-start the service, so we probe aggressively in that case."""
    if ai_autostarted:
        attempts = AI_HEALTH_MAX_ATTEMPTS
    else:
        attempts = int(os.getenv("AI_HEALTH_WARMUP_ATTEMPTS", "3"))

    def _worker():
        _check_ai_service(
            attempts=attempts,
            initial_delay=AI_HEALTH_INITIAL_DELAY,
            max_delay=AI_HEALTH_MAX_DELAY,
        )

    threading.Thread(target=_worker, daemon=True).start()


def _configure_logging():
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)


if __name__ == "__main__":
    _configure_logging()
    _autostart_fabric_agent()
    ai_autostarted = _autostart_ai_service()
    _probe_ai_service_in_background(ai_autostarted)
    start_ipfs_replication_monitor()
    start_auto_suggest_if_enabled()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5500"))
    debug = os.getenv("DEBUG", "0") == "1"
    log.info("Backend listening on http://%s:%d (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug, use_reloader=False)
