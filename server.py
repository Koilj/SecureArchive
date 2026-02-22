import os
import re
import time
import threading
import json
import pickle
import unicodedata
import requests
import numpy as np

# Настройка окружения TensorFlow
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")  # если есть GPU — убери или поставь нужный id
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import tensorflow as tf
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from transformers import AutoTokenizer, TFAutoModelForSequenceClassification

from utils import clean_text, format_model_input
from disp_sanitizer import sanitize_upload_metadata, sanitize_metadata_only, audit_record


# -----------------------------
# DISP policy knobs
# -----------------------------
_MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))  # 25MB
_AUDIT_LOG_PATH = os.getenv("DISP_AUDIT_LOG", "disp_audit.jsonl")

_SIMPLE_CONTROL = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_SIMPLE_ZW_BIDI = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
_SIMPLE_WS = re.compile(r"\s+")
_ASSET_ID_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")
_CATEGORY_RE = re.compile(r"^[a-zA-Z0-9 _\-\.]{1,64}$")

TARGET_CATEGORIES = {
    "cs.CV": "Computer Vision",
    "cs.LG": "Machine Learning",
    "cs.AI": "Artificial Intelligence",
    "cs.CL": "Computation and Language",
    "cs.CR": "Cryptography and Security",
    "cs.DC": "Distributed, Parallel, and Cluster Computing",
    "cs.SE": "Software Engineering",
    "cs.RO": "Robotics",
    "cs.CY": "Computers and Society",
    "cs.NI": "Networking and Internet Architecture",
    "cs.SI": "Social and Information Networks",
    "cs.IT": "Information Theory",
    "cs.DS": "Data Structures and Algorithms",
    "stat.ML": "Statistics - Machine Learning",
    "math.OC": "Optimization and Control",
    "math.PR": "Probability",
    "math.ST": "Statistics",
    "physics.comp-ph": "Computational Physics",
    "physics.data-an": "Data Analysis, Statistics and Probability",
    "quant-ph": "Quantum Physics",
    "q-bio.GN": "Genomics",
    "q-bio.NC": "Neuroscience",
    "q-bio.QM": "Quantitative Methods",
    "econ.EM": "Econometrics",
    "eess.IV": "Image and Video Processing",
    "eess.SP": "Signal Processing",
}


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


# -----------------------------
# Config
# -----------------------------
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001/api/v0/add")
IPFS_CAT_URL = os.getenv("IPFS_CAT_URL", "http://127.0.0.1:5001/api/v0/cat")

ML_AGENT_URL = os.getenv("ML_AGENT_URL", "http://127.0.0.1:8091")
ML_AGENT_TOKEN = os.getenv("ML_AGENT_TOKEN", "ml_token_please_change")

# ============================
# Auto-suggest daemon (polling)
# ============================
AUTO_SUGGEST = os.getenv("AUTO_SUGGEST", "0") == "1"
AUTO_SUGGEST_INTERVAL = float(os.getenv("AUTO_SUGGEST_INTERVAL", "10"))
AUTO_SUGGEST_MIN_CONF = float(os.getenv("AUTO_SUGGEST_MIN_CONF", "80.0"))

def _ml_headers():
    if not ML_AGENT_TOKEN:
        return {"Content-Type": "application/json"}
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ML_AGENT_TOKEN}",
    }

def ml_eval(function: str, args: list[str]):
    url = ML_AGENT_URL.rstrip("/") + "/eval"
    r = requests.post(url, headers=_ml_headers(), json={"function": function, "args": args}, timeout=10)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("error") or f"ml_eval failed: {data}")
    return data.get("result")

def ml_submit(function: str, args: list[str]):
    url = ML_AGENT_URL.rstrip("/") + "/submit"
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

def auto_suggest_once():
    try:
        assets = ml_eval("GetAllAssetsPublic", []) or []
    except Exception as e:
        print(f"AI_AUTO: GetAllAssetsPublic failed: {e}")
        return

    for a in assets:
        try:
            if not isinstance(a, dict) or not _should_suggest(a):
                continue

            asset_id_chain = a.get("assetID") or ""
            asset_id = _strip_asset_prefix(asset_id_chain)
            if not asset_id:
                continue

            meta = a.get("metadata") or {}
            payload = {
                "asset_id": asset_id,
                "metadata": {
                    "title": meta.get("title", "") if isinstance(meta, dict) else "",
                    "description": a.get("description", "") or "",
                    "author": (", ".join(meta.get("authors", [])) if isinstance(meta, dict) and isinstance(meta.get("authors"), list) else ""),
                    "department": (meta.get("discipline", "") if isinstance(meta, dict) else ""),
                    "keywords": (meta.get("keywords", []) if isinstance(meta, dict) else []),
                },
            }

            suggested, conf = predict_category_and_confidence(payload["metadata"])
            if not suggested or conf is None:
                continue
            if conf < AUTO_SUGGEST_MIN_CONF:
                print(f"AI_AUTO: skip {asset_id} conf={conf:.2f} < {AUTO_SUGGEST_MIN_CONF:.2f}")
                continue

            try:
                ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf:.2f}", "auto-ai"])
            except Exception:
                ml_submit("AddSuggestedCategory", [asset_id, suggested, f"{conf:.2f}"])

            print(f"AI_AUTO: suggested asset={asset_id} -> {suggested} conf={conf:.2f}")
        except Exception as e:
            print(f"AI_AUTO: failed on asset={a.get('assetID')}: {e}")

def auto_suggest_loop():
    time.sleep(0.5)
    print(f"AI_AUTO: enabled interval={AUTO_SUGGEST_INTERVAL}s min_conf={AUTO_SUGGEST_MIN_CONF}")
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
# AI MODEL (multilabel SciBERT) Setup
# -----------------------------
# ДОЛЖНО совпадать с обучением
MODEL_DIR = os.getenv("AI_MODEL_DIR", "scibert_multilabel_v3")
ENCODER_FILE = os.getenv("AI_ENCODER_FILE", os.path.join(MODEL_DIR, "multilabel_encoder.pickle"))
THRESHOLDS_FILE = os.getenv("AI_THRESHOLDS_FILE", os.path.join(MODEL_DIR, "thresholds.json"))

MAX_LEN = int(os.getenv("AI_MAX_LEN", "320"))  # совпадает с train (рекомендовано)

tokenizer = None
model = None
encoder = None
thresholds = {"type": "global", "global": 0.5}

def _load_thresholds():
    global thresholds
    try:
        if os.path.exists(THRESHOLDS_FILE):
            with open(THRESHOLDS_FILE, "r", encoding="utf-8") as f:
                thresholds = json.load(f)
            # sanity
            if thresholds.get("type") not in ("global", "per_class"):
                thresholds = {"type": "global", "global": 0.5}
        else:
            thresholds = {"type": "global", "global": 0.5}
    except Exception as e:
        print(f"⚠️ Could not load thresholds: {e}")
        thresholds = {"type": "global", "global": 0.5}

def _load_scibert_model(model_dir: str):
    print(f"🔄 Loading TFAutoModelForSequenceClassification from {model_dir}...")
    return TFAutoModelForSequenceClassification.from_pretrained(model_dir)

def _extract_logits(model_output):
    if hasattr(model_output, "logits"):
        return model_output.logits
    if isinstance(model_output, (tuple, list)) and model_output:
        return model_output[0]
    if isinstance(model_output, dict):
        if "logits" in model_output:
            return model_output["logits"]
    return model_output

def _sigmoid(x):
    # numpy sigmoid
    x = np.asarray(x, dtype=np.float32)
    return 1.0 / (1.0 + np.exp(-x))

def _apply_thresholds(probs_1d: np.ndarray):
    """
    probs_1d: shape [C]
    returns active_idx (np.ndarray of indices), used_thresholds
    """
    if thresholds.get("type") == "per_class":
        t = np.array(thresholds.get("per_class", []), dtype=np.float32)
        if t.shape[0] == probs_1d.shape[0]:
            active = np.where(probs_1d >= t)[0]
            return active, t
        # fallback
    t = float(thresholds.get("global", 0.5))
    active = np.where(probs_1d >= t)[0]
    return active, t

def build_ai_text(title: str, authors: str, abstract: str, keywords="") -> str:
    # Совпадает с prepare_data/utils.format_model_input
    return format_model_input(title=title, authors=authors, abstract=abstract, keywords=keywords)

def _features_to_text(x) -> str:
    """
    Поддержка:
    - str: уже текст
    - dict: ожидаем title/description/author/keywords
    """
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        title = x.get("title", "")
        abstract = x.get("description", "")
        authors = x.get("author", x.get("authors", ""))
        keywords = x.get("keywords", "")
        # keywords может быть list -> строка
        if isinstance(keywords, list):
            keywords = ", ".join([str(k) for k in keywords if str(k).strip()])
        return build_ai_text(str(title), str(authors), str(abstract), str(keywords))
    return str(x)

def predict_category_and_confidence(text_or_features, top_k: int = 0):
    """
    Multilabel inference.
    Возвращает:
      - suggested_label: str
      - confidence_pct: float | None
    Опционально: top_k>0 => ещё вернём список топ-K (label, conf)
    """
    if not (model and tokenizer and encoder):
        if top_k > 0:
            return "Unclassified", None, []
        return "Unclassified", None

    text = _features_to_text(text_or_features)
    text = clean_text(text)
    if not text.strip():
        if top_k > 0:
            return "Unclassified", None, []
        return "Unclassified", None

    try:
        inputs = tokenizer(
            text,
            return_tensors="tf",
            truncation=True,
            padding="max_length",
            max_length=MAX_LEN,
        )

        raw_output = model(dict(inputs), training=False)
        logits = _extract_logits(raw_output)
        logits = np.asarray(logits, dtype=np.float32)[0]  # [C]
        probs = _sigmoid(logits)  # [C], multilabel probabilities

        # выберем suggested как самый вероятный класс
        best_idx = int(np.argmax(probs))
        best_prob = float(probs[best_idx])

        # применим пороги (это влияет на "активные" метки; suggested всё равно берём max)
        active_idx, used_t = _apply_thresholds(probs)

        classes = list(getattr(encoder, "classes_", []))
        
        # Helper to map to full name
        def _to_full(c):
            return TARGET_CATEGORIES.get(c, c)

        raw_suggested = classes[best_idx] if best_idx < len(classes) else "Unclassified"
        suggested_label = _to_full(raw_suggested)
        confidence_pct = round(best_prob * 100.0, 2)

        if top_k > 0:
            # топ-K по вероятности
            k = min(int(top_k), len(probs))
            top_idx = np.argsort(-probs)[:k]
            top_list = []
            for i in top_idx:
                lab = classes[int(i)] if int(i) < len(classes) else f"class_{int(i)}"
                lab_full = _to_full(lab)
                top_list.append({"label": str(lab_full), "confidence": round(float(probs[int(i)]) * 100.0, 2)})
            return str(suggested_label), confidence_pct, top_list

        return str(suggested_label), confidence_pct

    except Exception as e:
        print(f"❌ AI Prediction Error: {e}")
        if top_k > 0:
            return "Error", 0.0, []
        return "Error", 0.0


# Load model artifacts
try:
    if os.path.exists(MODEL_DIR) and os.path.exists(ENCODER_FILE):
        print(f"🔄 Loading AI model from '{MODEL_DIR}'...")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, use_fast=True)
        model = _load_scibert_model(MODEL_DIR)
        with open(ENCODER_FILE, "rb") as f:
            encoder = pickle.load(f)
        _load_thresholds()
        print("✅ SciBERT multilabel loaded and ready!")
        print(f"🎚 Thresholds: {thresholds}")
    else:
        print(f"⚠️ Model or encoder not found: MODEL_DIR='{MODEL_DIR}', ENCODER_FILE='{ENCODER_FILE}'. AI disabled.")
        model = None
except Exception as e:
    print(f"❌ Critical model load error: {e}")
    model = None


# -----------------------------
# IPFS helpers
# -----------------------------
def upload_bytes_to_ipfs(file_bytes: bytes, filename: str = "payload.enc"):
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    resp = requests.post(IPFS_API_URL, files=files, params={"pin": "true"}, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"IPFS /add returned {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    cid = data.get("Hash")
    if not cid:
        raise RuntimeError(f"IPFS /add JSON has no Hash: {data}")
    return cid

def cat_from_ipfs(cid: str) -> bytes:
    resp = requests.post(IPFS_CAT_URL, params={"arg": cid}, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"IPFS /cat returned {resp.status_code}: {resp.text[:200]}")
    return resp.content


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
    if "::" not in s:
        return False, "Encrypted payload format invalid (missing ::)"
    iv_b64, ct_b64 = s.split("::", 1)
    if not iv_b64.strip() or not ct_b64.strip():
        return False, "Encrypted payload format invalid"
    return True, "OK"


# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = _MAX_UPLOAD_BYTES + (2 * 1024 * 1024)

def _append_audit(rec: dict):
    try:
        line = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

@app.get("/health")
def health():
    ai_status = "active" if model is not None else "disabled"
    return jsonify({"ok": True, "text": "ok", "ai": ai_status, "model_dir": MODEL_DIR}), 200


@app.post("/upload")
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
        "owner": request.form.get("owner", ""),
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

    try:
        cid = upload_bytes_to_ipfs(file_bytes, filename=file.filename)
    except Exception as e:
        return jsonify({"status": "error", "message": f"IPFS failed: {str(e)}"}), 500

    asset_id = f"asset_{disp.sanitized_payload['fileHash'][:8]}"

    return jsonify(
        {
            "status": "success",
            "cid": cid,
            "asset_id": asset_id,
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
            "note": "Server did NOT write to Fabric. Use local agent (127.0.0.1:8088)."
        }
    ), 200


@app.get("/download/<cid>")
def download_encrypted_file(cid: str):
    try:
        data = cat_from_ipfs(cid)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return Response(data, status=200, mimetype="application/octet-stream")


@app.post("/ai_suggest")
def ai_suggest_handler():
    data = request.get_json(silent=True) or {}
    asset_id = _norm_simple_text(data.get("asset_id", ""), 128)
    suggested = _norm_simple_text(data.get("suggested_category", ""), 64)
    conf = data.get("confidence", None)

    if not asset_id or not suggested:
        return jsonify({"status": "error", "message": "Required fields missing"}), 400

    try:
        conf_val = float(conf) if conf is not None else 0.0
    except Exception:
        conf_val = 0.0

    _append_audit({
        "ts": time.time(),
        "endpoint": "/ai_suggest",
        "asset_id": asset_id,
        "suggested": suggested,
        "confidence": conf_val,
    })

    try:
        try:
            resp = requests.post(
                ML_AGENT_URL.rstrip("/") + "/submit",
                headers=_ml_headers(),
                json={"function": "AddSuggestedCategory", "args": [asset_id, suggested, f"{conf_val:.2f}", "user-api"]},
                timeout=10,
            )
            j = resp.json()
            if not j.get("ok"):
                raise RuntimeError(j.get("error"))
        except Exception:
            resp = requests.post(
                ML_AGENT_URL.rstrip("/") + "/submit",
                headers=_ml_headers(),
                json={"function": "AddSuggestedCategory", "args": [asset_id, suggested, f"{conf_val:.2f}"]},
                timeout=10,
            )
            j = resp.json()

        if not j.get("ok"):
            return jsonify({"status": "error", "message": j.get("error", "ml agent error")}), 502
        return jsonify({"status": "success", "agent_result": j.get("result")}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"ML agent call failed: {e}"}), 502


@app.post("/ai_suggest_auto")
def ai_suggest_auto_handler():
    data = request.get_json(silent=True) or {}
    asset_id = _norm_simple_text(str(data.get("asset_id", "")), 128)
    if not asset_id:
        return jsonify({"status": "error", "message": "asset_id is required"}), 400

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
    try:
        ml_submit("AddSuggestedCategory", [asset_id, str(suggested), f"{float(conf_val):.2f}"])
        stored = True
    except Exception as e:
        _append_audit({"error": f"ml_submit failed: {e}", "asset_id": asset_id})

    return jsonify({
        "status": "ok",
        "suggested_category": str(suggested),
        "confidence": float(conf_val),
        "stored_on_chain": stored,
    }), 200


# -----------------------------
# Deprecated Endpoints
# -----------------------------
def moved_to_agent():
    return jsonify({"status": "error", "message": "Fabric operations moved to local agent on http://127.0.0.1:8088"}), 501

@app.route("/files", methods=["GET"])
def deprecated_files():
    return moved_to_agent()

@app.route("/metadata/<asset_id>", methods=["GET"])
def deprecated_metadata(asset_id):
    return moved_to_agent()

if __name__ == "__main__":
    start_auto_suggest_if_enabled()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5500"))
    debug = os.getenv("DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug, use_reloader=False)
