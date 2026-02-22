"""DISP-like Sanitizer (Defense-in-depth input sanitization pipeline).

This module is dependency-light (stdlib only) and provides a *structured* sanitizer
for user-controlled metadata and JSON payloads that will be used by:
  - UI rendering (XSS / HTML injection risk)
  - Backend JSON/APIs (schema/JSON injection risk)
  - AI classification (prompt-injection and abuse control)
  - Blockchain writes (immutability; strict limits)

Design goals:
  - Backend is the source of truth: UI must use sanitized outputs.
  - Deterministic results: same input + same rules => same output.
  - Auditability: return flags/score/decision/reasons and stable hashes.

NOTE: For blockchain writes we prefer *validation + reject* over silent mutation.
      For UI/AI we also produce safe representations.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import time
import unicodedata
from typing import Any, Dict, List, Tuple


# -----------------------------
# Policy knobs (tunable)
# -----------------------------

DEFAULT_LIMITS = {
    "max_title": 256,
    "max_authors": 256,
    "max_discipline": 128,
    "max_license": 128,
    "max_doi": 128,
    "max_keywords": 512,
    "max_description": 2000,
    "max_owner": 256,
    "max_encrypted_key": 4096,
    "max_asset_id": 128,
    "max_cid": 128,
    "max_file_hash": 128,
    "max_json_depth": 40,
    "max_json_keys": 2000,
    "max_json_total_chars": 200_000,
}


# -----------------------------
# Regex / detectors
# -----------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Zero-width + bidi control ranges we want to treat as suspicious.
_ZERO_WIDTH_BIDI = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]"
)

_WHITESPACE = re.compile(r"\s+")

_HTML_TAG_LIKE = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
_SCRIPTISH = re.compile(r"<\s*script\b|on\w+\s*=|javascript\s*:|data\s*:\s*text/html", re.I)

_PROMPT_INJECTION = re.compile(
    r"\b(ignore|disregard)\b.*\b(instruction|previous|system)\b|"
    r"\b(system\s+prompt|developer\s+message|jailbreak)\b|"
    r"\b(reveal|leak|exfiltrate)\b.*\b(secret|key|token|policy)\b",
    re.I | re.S,
)


_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.I)
_CID_ALLOWED = re.compile(r"^[a-zA-Z0-9]+$")
_ASSET_ID_ALLOWED = re.compile(r"^[a-zA-Z0-9_.\-]+$")
_CATEGORY_ALLOWED = re.compile(r"^[a-zA-Z0-9 _\-]{1,64}$")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _unicode_nfkc(s: str) -> str:
    try:
        return unicodedata.normalize("NFKC", s)
    except Exception:
        return s


def _collapse_ws(s: str) -> str:
    return _WHITESPACE.sub(" ", s).strip()


def _strip_control_and_bidi(s: str) -> Tuple[str, List[str]]:
    flags: List[str] = []
    if _CONTROL_CHARS.search(s):
        flags.append("CONTROL_CHARS")
        s = _CONTROL_CHARS.sub("", s)
    if _ZERO_WIDTH_BIDI.search(s):
        flags.append("ZERO_WIDTH_OR_BIDI")
        s = _ZERO_WIDTH_BIDI.sub("", s)
    return s, flags


def _script_groups(s: str) -> List[str]:
    """Very lightweight mixed-script heuristic.

    We bucket chars by unicode name prefix to detect obvious mixing
    (LATIN/CYRILLIC/GREEK/ARABIC/HEBREW/CJK/HANGUL/etc).
    """
    groups = set()
    for ch in s:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except Exception:
            continue
        # take the first token (e.g., 'LATIN', 'CYRILLIC')
        grp = name.split(" ", 1)[0]
        # treat common combining marks as neutral
        if grp in {"COMBINING", "MODIFIER"}:
            continue
        groups.add(grp)
        if len(groups) >= 3:
            break
    return sorted(groups)


def _has_mixed_scripts(s: str) -> bool:
    g = _script_groups(s)
    # Allow 0-1 group; flag when >=2 for identifiers-like fields.
    return len(g) >= 2


def _looks_dos_like(s: str) -> bool:
    # very long overall
    if len(s) > 20_000:
        return True
    # long run of same char
    if re.search(r"(.)\1{40,}", s):
        return True
    # extremely long token with no whitespace
    if re.search(r"\S{400,}", s):
        return True
    return False


def _detect_xss_like(s: str) -> List[str]:
    out: List[str] = []
    if _SCRIPTISH.search(s):
        out.append("XSS_SCRIPTISH")
    elif _HTML_TAG_LIKE.search(s):
        out.append("HTML_TAGS")
    return out


def _detect_prompt_injection(s: str) -> List[str]:
    return ["PROMPT_INJECTION"] if _PROMPT_INJECTION.search(s) else []


def _strict_json_loads_with_dupe_check(raw: str) -> Tuple[Any, List[str]]:
    flags: List[str] = []

    def hook(pairs: List[Tuple[str, Any]]):
        obj: Dict[str, Any] = {}
        seen = set()
        for k, v in pairs:
            if k in seen:
                flags.append("JSON_DUPLICATE_KEYS")
            seen.add(k)
            obj[k] = v
        return obj

    try:
        return json.loads(raw, object_pairs_hook=hook), flags
    except Exception:
        flags.append("JSON_PARSE_ERROR")
        return None, flags


def _json_complexity(obj: Any, depth: int = 0) -> Tuple[int, int, int]:
    """Return (max_depth, key_count, string_chars) for complexity limiting."""
    max_depth = depth
    key_count = 0
    string_chars = 0
    if isinstance(obj, dict):
        key_count += len(obj)
        for k, v in obj.items():
            string_chars += len(str(k))
            d2, k2, c2 = _json_complexity(v, depth + 1)
            max_depth = max(max_depth, d2)
            key_count += k2
            string_chars += c2
    elif isinstance(obj, list):
        for v in obj:
            d2, k2, c2 = _json_complexity(v, depth + 1)
            max_depth = max(max_depth, d2)
            key_count += k2
            string_chars += c2
    elif isinstance(obj, str):
        string_chars += len(obj)
    else:
        # numbers/bools/null: bounded
        pass
    return max_depth, key_count, string_chars


@dataclasses.dataclass
class DispResult:
    sanitized_payload: Dict[str, Any]
    ui_safe: Dict[str, str]
    ai_safe_text: str
    ledger_safe: Dict[str, Any]
    risk_score: int
    flags: List[str]
    decision: str
    reasons: List[str]
    request_hash: str
    version: str = "disp_v1"


def _score_from_flags(flags: List[str]) -> int:
    weights = {
        "CONTROL_CHARS": 15,
        "ZERO_WIDTH_OR_BIDI": 15,
        "MIXED_SCRIPTS": 10,
        "HTML_TAGS": 20,
        "XSS_SCRIPTISH": 60,
        "PROMPT_INJECTION": 25,
        "DOS_LIKE": 40,
        "JSON_PARSE_ERROR": 50,
        "JSON_DUPLICATE_KEYS": 25,
        "JSON_TOO_DEEP": 35,
        "JSON_TOO_LARGE": 35,
        "FORMAT_INVALID": 40,
        "TRUNCATED": 5,
    }
    s = 0
    for f in flags:
        s += weights.get(f, 5)
    return min(100, s)


def _decide(flags: List[str], field_fatal: bool) -> Tuple[str, List[str]]:
    reasons: List[str] = []

    # Hard rejects
    if "FORMAT_INVALID" in flags or "JSON_PARSE_ERROR" in flags:
        return "reject", ["invalid format"]
    if "XSS_SCRIPTISH" in flags and field_fatal:
        return "reject", ["active script/handler patterns detected"]
    if "DOS_LIKE" in flags:
        return "reject", ["payload looks like DoS attempt"]
    if "JSON_TOO_DEEP" in flags or "JSON_TOO_LARGE" in flags:
        return "reject", ["JSON complexity limits exceeded"]

    # Review-required
    review_flags = {
        "XSS_SCRIPTISH",
        "HTML_TAGS",
        "PROMPT_INJECTION",
        "ZERO_WIDTH_OR_BIDI",
        "CONTROL_CHARS",
        "MIXED_SCRIPTS",
        "JSON_DUPLICATE_KEYS",
        "TRUNCATED",
    }
    if any(f in review_flags for f in flags):
        reasons = ["requires manual review due to suspicious input signals"]
        return "allow_with_review", reasons

    return "allow", []


def _safe_for_ui_text(s: str) -> str:
    # UI must still escape at render; but we also normalize newlines.
    return s.replace("\r\n", "\n").replace("\r", "\n")


def _ai_wrap(title: str, authors: str, discipline: str, keywords: str, description: str) -> str:
    # Treat user text as DATA, not instructions.
    # The classifier in this project is classic ML, but we keep this for future LLM usage.
    parts = {
        "title": title,
        "authors": authors,
        "discipline": discipline,
        "keywords": keywords,
        "description": description,
    }
    lines = ["BEGIN_USER_CONTENT"]
    for k, v in parts.items():
        if v:
            lines.append(f"{k}: {v}")
    lines.append("END_USER_CONTENT")
    return "\n".join(lines)


def sanitize_upload_metadata(raw: Dict[str, Any], *, limits: Dict[str, int] | None = None) -> DispResult:
    lim = dict(DEFAULT_LIMITS)
    if limits:
        lim.update(limits)

    flags: List[str] = []

    def norm_field(val: Any, *, max_len: int, collapse: bool, mixed_script_sensitive: bool) -> str:
        s = "" if val is None else str(val)
        s = _unicode_nfkc(s)
        s, f2 = _strip_control_and_bidi(s)
        flags.extend(f2)
        if collapse:
            s = _collapse_ws(s)
        if len(s) > max_len:
            flags.append("TRUNCATED")
            s = s[:max_len]
        if mixed_script_sensitive and s and _has_mixed_scripts(s):
            flags.append("MIXED_SCRIPTS")
        if _looks_dos_like(s):
            flags.append("DOS_LIKE")
        return s

    # Field profiles
    title = norm_field(raw.get("title", ""), max_len=lim["max_title"], collapse=True, mixed_script_sensitive=True)
    authors = norm_field(raw.get("authors", ""), max_len=lim["max_authors"], collapse=True, mixed_script_sensitive=True)
    discipline = norm_field(raw.get("discipline", ""), max_len=lim["max_discipline"], collapse=True, mixed_script_sensitive=True)
    license_str = norm_field(raw.get("license", ""), max_len=lim["max_license"], collapse=True, mixed_script_sensitive=False)
    doi = norm_field(raw.get("doi", ""), max_len=lim["max_doi"], collapse=True, mixed_script_sensitive=False)
    keywords = norm_field(raw.get("keywords", ""), max_len=lim["max_keywords"], collapse=True, mixed_script_sensitive=False)

    # description can be multi-line, but we still normalize
    description_raw = "" if raw.get("description") is None else str(raw.get("description"))
    description_raw = _unicode_nfkc(description_raw)
    desc, f2 = _strip_control_and_bidi(description_raw)
    flags.extend(f2)
    # normalize newlines and trim
    desc = desc.replace("\r\n", "\n").replace("\r", "\n")
    desc = desc.strip()
    if len(desc) > lim["max_description"]:
        flags.append("TRUNCATED")
        desc = desc[: lim["max_description"]]
    if _looks_dos_like(desc):
        flags.append("DOS_LIKE")

    owner = norm_field(raw.get("owner", ""), max_len=lim["max_owner"], collapse=True, mixed_script_sensitive=False)
    encrypted_key = norm_field(raw.get("encryptedAesKey", ""), max_len=lim["max_encrypted_key"], collapse=True, mixed_script_sensitive=False)
    file_hash = norm_field(raw.get("fileHash", ""), max_len=lim["max_file_hash"], collapse=True, mixed_script_sensitive=False)

    # Validate formats that must be strict.
    if file_hash and not _HEX64.match(file_hash):
        flags.append("FORMAT_INVALID")
    if not encrypted_key:
        flags.append("FORMAT_INVALID")

    # Detect attacks per field
    # For identifier-like fields (title/authors/discipline/keywords) HTML/script is suspicious.
    flags.extend(_detect_xss_like(title))
    flags.extend(_detect_xss_like(authors))
    flags.extend(_detect_xss_like(discipline))
    flags.extend(_detect_xss_like(keywords))

    # Description may legitimately include angle brackets; still flag.
    flags.extend(_detect_xss_like(desc))

    # Prompt injection signals (most relevant in description/notes)
    flags.extend(_detect_prompt_injection(desc))

    # Build outputs
    sanitized_payload = {
        "title": title,
        "authors": authors,
        "discipline": discipline,
        "license": license_str,
        "doi": doi,
        "keywords": keywords,
        "description": desc,
        "owner": owner,
        "encryptedAesKey": encrypted_key,
        "fileHash": file_hash,
    }

    ui_safe = {k: _safe_for_ui_text(v) for k, v in sanitized_payload.items() if isinstance(v, str)}
    ai_safe_text = _ai_wrap(title, authors, discipline, keywords, desc)

    ledger_safe = {
        "title": title,
        "authors": authors,
        "discipline": discipline,
        "license": license_str,
        "doi": doi,
        "keywords": keywords,
        "description": desc,
        "fileHash": file_hash,
    }

    # Decision policy:
    # - treat XSS_SCRIPTISH in short fields as fatal
    short_field_fatal = any(
        f in flags for f in ("XSS_SCRIPTISH",)  # HTML_TAGS alone => review
    ) and any(
        _SCRIPTISH.search(x) for x in (title, authors, discipline, keywords)
    )

    decision, reasons = _decide(flags, field_fatal=short_field_fatal)
    risk_score = _score_from_flags(flags)
    req_hash = _sha256_hex(json.dumps(sanitized_payload, sort_keys=True, ensure_ascii=False))

    # De-duplicate flags (stable order)
    dedup_flags = []
    seen = set()
    for f in flags:
        if f not in seen:
            seen.add(f)
            dedup_flags.append(f)

    return DispResult(
        sanitized_payload=sanitized_payload,
        ui_safe=ui_safe,
        ai_safe_text=ai_safe_text,
        ledger_safe=ledger_safe,
        risk_score=risk_score,
        flags=dedup_flags,
        decision=decision,
        reasons=reasons,
        request_hash=req_hash,
    )


def sanitize_metadata_only(raw: Dict[str, Any], *, limits: Dict[str, int] | None = None) -> DispResult:
    """Sanitize *only* human metadata (no keys/hashes).

    Useful for AI-suggest endpoints or any place where keys/hashes are not present.
    """
    lim = dict(DEFAULT_LIMITS)
    if limits:
        lim.update(limits)

    flags: List[str] = []

    def norm_field(val: Any, *, max_len: int, collapse: bool, mixed_script_sensitive: bool) -> str:
        s = "" if val is None else str(val)
        s = _unicode_nfkc(s)
        s, f2 = _strip_control_and_bidi(s)
        flags.extend(f2)
        if collapse:
            s = _collapse_ws(s)
        if len(s) > max_len:
            flags.append("TRUNCATED")
            s = s[:max_len]
        if mixed_script_sensitive and s and _has_mixed_scripts(s):
            flags.append("MIXED_SCRIPTS")
        if _looks_dos_like(s):
            flags.append("DOS_LIKE")
        return s

    title = norm_field(raw.get("title", ""), max_len=lim["max_title"], collapse=True, mixed_script_sensitive=True)
    authors = norm_field(raw.get("authors", raw.get("author", "")), max_len=lim["max_authors"], collapse=True, mixed_script_sensitive=True)
    discipline = norm_field(raw.get("discipline", raw.get("department", "")), max_len=lim["max_discipline"], collapse=True, mixed_script_sensitive=True)
    keywords = raw.get("keywords", "")
    if isinstance(keywords, list):
        keywords = ", ".join([str(k) for k in keywords])
    keywords = norm_field(keywords, max_len=lim["max_keywords"], collapse=True, mixed_script_sensitive=False)

    description_raw = "" if raw.get("description") is None else str(raw.get("description"))
    description_raw = _unicode_nfkc(description_raw)
    desc, f2 = _strip_control_and_bidi(description_raw)
    flags.extend(f2)
    desc = desc.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(desc) > lim["max_description"]:
        flags.append("TRUNCATED")
        desc = desc[: lim["max_description"]]
    if _looks_dos_like(desc):
        flags.append("DOS_LIKE")

    flags.extend(_detect_xss_like(title))
    flags.extend(_detect_xss_like(authors))
    flags.extend(_detect_xss_like(discipline))
    flags.extend(_detect_xss_like(keywords))
    flags.extend(_detect_xss_like(desc))
    flags.extend(_detect_prompt_injection(desc))

    sanitized_payload = {
        "title": title,
        "authors": authors,
        "discipline": discipline,
        "keywords": keywords,
        "description": desc,
    }
    ui_safe = {k: _safe_for_ui_text(v) for k, v in sanitized_payload.items()}
    ai_safe_text = _ai_wrap(title, authors, discipline, keywords, desc)
    ledger_safe = dict(sanitized_payload)

    short_field_fatal = any(
        f in flags for f in ("XSS_SCRIPTISH",)
    ) and any(
        _SCRIPTISH.search(x) for x in (title, authors, discipline, keywords)
    )
    decision, reasons = _decide(flags, field_fatal=short_field_fatal)
    risk_score = _score_from_flags(flags)
    req_hash = _sha256_hex(json.dumps(sanitized_payload, sort_keys=True, ensure_ascii=False))

    dedup_flags = []
    seen = set()
    for f in flags:
        if f not in seen:
            seen.add(f)
            dedup_flags.append(f)

    return DispResult(
        sanitized_payload=sanitized_payload,
        ui_safe=ui_safe,
        ai_safe_text=ai_safe_text,
        ledger_safe=ledger_safe,
        risk_score=risk_score,
        flags=dedup_flags,
        decision=decision,
        reasons=reasons,
        request_hash=req_hash,
    )


def sanitize_json_payload(raw_json_text: str, *, limits: Dict[str, int] | None = None) -> Tuple[Any, List[str]]:
    """Strict JSON parse + basic complexity checks."""
    lim = dict(DEFAULT_LIMITS)
    if limits:
        lim.update(limits)

    obj, flags = _strict_json_loads_with_dupe_check(raw_json_text)
    if obj is None:
        return None, flags

    max_depth, key_count, string_chars = _json_complexity(obj, 0)
    if max_depth > lim["max_json_depth"]:
        flags.append("JSON_TOO_DEEP")
    if key_count > lim["max_json_keys"] or string_chars > lim["max_json_total_chars"]:
        flags.append("JSON_TOO_LARGE")
    return obj, flags


def audit_record(*, req_id: str, result: DispResult, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Create an audit-ready dict. Caller decides where to store it."""
    rec: Dict[str, Any] = {
        "ts": _now_iso(),
        "req_id": req_id,
        "disp_version": result.version,
        "decision": result.decision,
        "risk_score": result.risk_score,
        "flags": result.flags,
        "reasons": result.reasons,
        "request_hash": result.request_hash,
    }
    if extra:
        rec.update(extra)
    return rec
