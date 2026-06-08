"""Risk scoring, decisions, and output shaping policy."""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Iterable, List, Sequence, Tuple

from .constants import DISP_VERSION, FLAG_WEIGHTS, REVIEW_FLAGS


def score_from_flags(flags: Sequence[str]) -> int:
    return min(100, sum(FLAG_WEIGHTS.get(flag, 5) for flag in flags))


def decide(flags: Sequence[str], fatal_short_fields: bool) -> Tuple[str, List[str]]:
    if "FORMAT_INVALID" in flags or "JSON_PARSE_ERROR" in flags:
        return "reject", ["invalid format"]
    if fatal_short_fields and "XSS_SCRIPTISH" in flags:
        return "reject", ["active script/handler patterns detected"]
    if "DOS_LIKE" in flags:
        return "reject", ["payload looks like DoS attempt"]
    if "JSON_TOO_DEEP" in flags or "JSON_TOO_LARGE" in flags:
        return "reject", ["JSON complexity limits exceeded"]
    if any(flag in REVIEW_FLAGS for flag in flags):
        return "allow_with_review", ["requires manual review due to suspicious input signals"]
    return "allow", []


def ai_wrap(parts: Dict[str, str]) -> str:
    lines = ["BEGIN_USER_CONTENT"]
    for key in ("title", "authors", "discipline", "keywords", "description"):
        value = parts.get(key, "")
        if value:
            lines.append(f"{key}: {value}")
    lines.append("END_USER_CONTENT")
    return "\n".join(lines)


def request_hash(payload: Dict[str, str]) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8", errors="ignore")).hexdigest()


def current_version() -> str:
    return DISP_VERSION
