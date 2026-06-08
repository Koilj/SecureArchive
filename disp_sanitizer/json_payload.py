"""Strict JSON parsing and complexity limiting."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .constants import DEFAULT_LIMITS


def sanitize_json_payload(raw_json_text: str, *, limits: Dict[str, int] | None = None) -> Tuple[Any, List[str]]:
    merged_limits = dict(DEFAULT_LIMITS)
    if limits:
        merged_limits.update(limits)

    obj, flags = _strict_json_loads_with_dupe_check(raw_json_text)
    if obj is None:
        return None, flags

    max_depth, key_count, string_chars = _json_complexity(obj, 0)
    if max_depth > merged_limits["max_json_depth"]:
        flags.append("JSON_TOO_DEEP")
    if key_count > merged_limits["max_json_keys"] or string_chars > merged_limits["max_json_total_chars"]:
        flags.append("JSON_TOO_LARGE")
    return obj, flags


def _strict_json_loads_with_dupe_check(raw: str) -> Tuple[Any, List[str]]:
    flags: List[str] = []

    def hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        seen = set()
        for key, value in pairs:
            if key in seen:
                flags.append("JSON_DUPLICATE_KEYS")
            seen.add(key)
            obj[key] = value
        return obj

    try:
        return json.loads(raw, object_pairs_hook=hook), flags
    except Exception:
        flags.append("JSON_PARSE_ERROR")
        return None, flags


def _json_complexity(obj: Any, depth: int = 0) -> Tuple[int, int, int]:
    max_depth = depth
    key_count = 0
    string_chars = 0
    if isinstance(obj, dict):
        key_count += len(obj)
        for key, value in obj.items():
            string_chars += len(str(key))
            depth2, keys2, chars2 = _json_complexity(value, depth + 1)
            max_depth = max(max_depth, depth2)
            key_count += keys2
            string_chars += chars2
    elif isinstance(obj, list):
        for value in obj:
            depth2, keys2, chars2 = _json_complexity(value, depth + 1)
            max_depth = max(max_depth, depth2)
            key_count += keys2
            string_chars += chars2
    elif isinstance(obj, str):
        string_chars += len(obj)
    return max_depth, key_count, string_chars
