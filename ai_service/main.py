"""
AI Service — standalone FastAPI microservice for SciBERT multilabel classification.

Endpoints:
  POST /predict        — single prediction
  POST /predict/batch  — batch predictions
  GET  /health         — health check
"""

import os
import json
import pickle
import logging
from pathlib import Path
from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# TensorFlow setup — before importing TF
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import tensorflow as tf
from transformers import AutoTokenizer, TFAutoModelForSequenceClassification

# ---------------------
# Shared utilities (same as project root utils.py)
# ---------------------
import re

_WS_RE = re.compile(r"\s+")
_NONPRINT_RE = re.compile(r"[^\x20-\x7E\u00A0-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF\n\r\t]")


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = _NONPRINT_RE.sub("", text)
    text = _WS_RE.sub(" ", text).strip()
    return text


def format_model_input(title: str, authors: str, abstract: str, keywords: str = "") -> str:
    parts = [
        str(title or "").strip(),
        str(authors or "").strip(),
        str(keywords or "").strip(),
        str(abstract or "").strip(),
    ]
    parts = [p for p in parts if p]
    return " [SEP] ".join(parts)


# ---------------------
# Target categories map (single source of truth: ai_service/categories.json)
# ---------------------
_CATEGORIES_FILE = Path(__file__).resolve().parent / "categories.json"


def _load_target_categories() -> dict:
    try:
        with _CATEGORIES_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        logging.getLogger("ai_service").warning(
            "Could not load %s: %s", _CATEGORIES_FILE, exc
        )
    return {}


TARGET_CATEGORIES: dict[str, str] = _load_target_categories()

# ---------------------
# Configuration
# ---------------------
MODEL_DIR = os.getenv("AI_MODEL_DIR", str(Path(__file__).resolve().parent.parent / "scibert_multilabel_v3"))
ENCODER_FILE = os.getenv("AI_ENCODER_FILE", os.path.join(MODEL_DIR, "multilabel_encoder.pickle"))
THRESHOLDS_FILE = os.getenv("AI_THRESHOLDS_FILE", os.path.join(MODEL_DIR, "thresholds.json"))
MAX_LEN = int(os.getenv("AI_MAX_LEN", "320"))

logger = logging.getLogger("ai_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


# ---------------------
# Model state (module-level singleton)
# ---------------------
class ModelState:
    tokenizer = None
    model = None
    encoder = None
    thresholds: dict = {"type": "global", "global": 0.5}
    ready: bool = False


_state = ModelState()


def _load_thresholds() -> dict:
    try:
        if os.path.exists(THRESHOLDS_FILE):
            with open(THRESHOLDS_FILE, "r", encoding="utf-8") as f:
                t = json.load(f)
            if t.get("type") not in ("global", "per_class"):
                return {"type": "global", "global": 0.5}
            return t
    except Exception as e:
        logger.warning("Could not load thresholds: %s", e)
    return {"type": "global", "global": 0.5}


def _load_model():
    if not os.path.exists(MODEL_DIR) or not os.path.exists(ENCODER_FILE):
        logger.warning("Model or encoder not found: MODEL_DIR='%s', ENCODER_FILE='%s'. AI disabled.", MODEL_DIR, ENCODER_FILE)
        return

    logger.info("Loading AI model from '%s'...", MODEL_DIR)
    _state.tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, use_fast=True)
    _state.model = TFAutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    with open(ENCODER_FILE, "rb") as f:
        _state.encoder = pickle.load(f)
    _state.thresholds = _load_thresholds()
    _state.ready = True
    logger.info("SciBERT multilabel loaded and ready!")
    logger.info("Thresholds: %s", _state.thresholds)


# ---------------------
# Inference helpers
# ---------------------
def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x.astype(np.float32)))


def _extract_logits(model_output):
    if hasattr(model_output, "logits"):
        return model_output.logits
    if isinstance(model_output, (tuple, list)) and model_output:
        return model_output[0]
    if isinstance(model_output, dict) and "logits" in model_output:
        return model_output["logits"]
    return model_output


def _apply_thresholds(probs_1d: np.ndarray, thresholds: dict):
    if thresholds.get("type") == "per_class":
        t = np.array(thresholds.get("per_class", []), dtype=np.float32)
        if t.shape[0] == probs_1d.shape[0]:
            active = np.where(probs_1d >= t)[0]
            return active, t
    t = float(thresholds.get("global", 0.5))
    active = np.where(probs_1d >= t)[0]
    return active, t


def _threshold_for_index(index: int, thresholds: dict, probs_len: int) -> float:
    if thresholds.get("type") == "per_class":
        try:
            values = np.array(thresholds.get("per_class", []), dtype=np.float32)
            if values.shape[0] == probs_len:
                return float(values[index])
        except Exception:
            pass
    return float(thresholds.get("global", 0.5))


def _features_to_text(x) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        title = x.get("title", "")
        abstract = x.get("description", "")
        authors = x.get("author", x.get("authors", ""))
        keywords = x.get("keywords", "")
        if isinstance(keywords, list):
            keywords = ", ".join(str(k) for k in keywords if str(k).strip())
        return format_model_input(str(title), str(authors), str(abstract), str(keywords))
    return str(x)


def _to_full(c: str) -> str:
    return TARGET_CATEGORIES.get(c, c)


def predict(text_or_features, top_k: int = 0) -> dict:
    """
    Returns dict:
      suggested_label: str
      confidence: float | None
      top_k: list[dict] (if top_k > 0)
    """
    if not _state.ready:
        return {"suggested_label": "Unclassified", "confidence": None, "top_k": []}

    text = clean_text(_features_to_text(text_or_features))
    if not text.strip():
        return {"suggested_label": "Unclassified", "confidence": None, "top_k": []}

    try:
        inputs = _state.tokenizer(
            text,
            return_tensors="tf",
            truncation=True,
            padding="max_length",
            max_length=MAX_LEN,
        )
        raw_output = _state.model(dict(inputs), training=False)
        logits = np.asarray(_extract_logits(raw_output), dtype=np.float32)[0]
        probs = _sigmoid(logits)

        best_idx = int(np.argmax(probs))
        best_prob = float(probs[best_idx])

        classes = list(getattr(_state.encoder, "classes_", []))
        best_threshold = _threshold_for_index(best_idx, _state.thresholds, len(probs))
        if best_prob >= best_threshold:
            raw_suggested = classes[best_idx] if best_idx < len(classes) else "Unclassified"
            suggested_label = _to_full(raw_suggested)
        else:
            suggested_label = "Unclassified"
        confidence_pct = round(best_prob * 100.0, 2)

        top_list = []
        if top_k > 0:
            k = min(int(top_k), len(probs))
            top_idx = np.argsort(-probs)[:k]
            for i in top_idx:
                lab = classes[int(i)] if int(i) < len(classes) else f"class_{int(i)}"
                top_list.append({
                    "label": _to_full(lab),
                    "confidence": round(float(probs[int(i)]) * 100.0, 2),
                })

        return {
            "suggested_label": str(suggested_label),
            "confidence": confidence_pct,
            "top_k": top_list,
        }

    except Exception as e:
        logger.error("AI Prediction Error: %s", e)
        return {"suggested_label": "Error", "confidence": 0.0, "top_k": []}


# ---------------------
# Pydantic models
# ---------------------
class PredictRequest(BaseModel):
    text: str | None = None
    features: dict | None = None
    top_k: int = Field(default=0, ge=0, le=50)


class PredictResponse(BaseModel):
    ok: bool = True
    suggested_label: str
    confidence: float | None
    top_k: list[dict] = []


class BatchPredictRequest(BaseModel):
    items: list[PredictRequest]


class BatchPredictResponse(BaseModel):
    ok: bool = True
    results: list[PredictResponse]


class HealthResponse(BaseModel):
    ok: bool
    model_loaded: bool
    model_dir: str


# ---------------------
# FastAPI app
# ---------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()
    yield


app = FastAPI(title="AI Service", version="1.0.0", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        ok=_state.ready,
        model_loaded=_state.ready,
        model_dir=MODEL_DIR,
    )


@app.post("/predict", response_model=PredictResponse)
def predict_single(req: PredictRequest):
    input_data = req.text if req.text is not None else req.features
    if input_data is None:
        raise HTTPException(status_code=400, detail="provide 'text' or 'features'")
    result = predict(input_data, top_k=req.top_k)
    return PredictResponse(**result)


@app.post("/predict/batch", response_model=BatchPredictResponse)
def predict_batch(req: BatchPredictRequest):
    if len(req.items) > 100:
        raise HTTPException(status_code=400, detail="max 100 items per batch")
    results = []
    for item in req.items:
        input_data = item.text if item.text is not None else item.features
        if input_data is None:
            results.append(PredictResponse(
                suggested_label="Unclassified", confidence=None, top_k=[]
            ))
            continue
        r = predict(input_data, top_k=item.top_k)
        results.append(PredictResponse(**r))
    return BatchPredictResponse(results=results)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("AI_SERVICE_HOST", "127.0.0.1")
    port = int(os.getenv("AI_SERVICE_PORT", "8100"))
    uvicorn.run(app, host=host, port=port, log_level="info")
