"""Text normalization and low-level heuristics."""

from __future__ import annotations

import unicodedata
from typing import Iterable, List, Tuple

from .patterns import CONTROL_CHARS, WHITESPACE, ZERO_WIDTH_BIDI


def unicode_nfkc(value: str) -> str:
    try:
        return unicodedata.normalize("NFKC", value)
    except Exception:
        return value


def collapse_whitespace(value: str) -> str:
    return WHITESPACE.sub(" ", value).strip()


def normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def strip_control_and_bidi(value: str) -> Tuple[str, List[str]]:
    flags: List[str] = []
    if CONTROL_CHARS.search(value):
        flags.append("CONTROL_CHARS")
        value = CONTROL_CHARS.sub("", value)
    if ZERO_WIDTH_BIDI.search(value):
        flags.append("ZERO_WIDTH_OR_BIDI")
        value = ZERO_WIDTH_BIDI.sub("", value)
    return value, flags


def script_groups(value: str) -> List[str]:
    groups = set()
    for ch in value:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except Exception:
            continue
        group = name.split(" ", 1)[0]
        if group in {"COMBINING", "MODIFIER"}:
            continue
        groups.add(group)
        if len(groups) >= 3:
            break
    return sorted(groups)


def has_mixed_scripts(value: str) -> bool:
    return len(script_groups(value)) >= 2


def looks_dos_like(value: str) -> bool:
    if len(value) > 20_000:
        return True
    if any(len(run) > 40 for run in _same_char_runs(value)):
        return True
    return any(len(token) >= 400 for token in value.split())


def safe_for_ui_text(value: str) -> str:
    return normalize_newlines(value)


def stable_dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _same_char_runs(value: str) -> Iterable[str]:
    if not value:
        return []
    runs: List[str] = []
    start = 0
    for idx in range(1, len(value)):
        if value[idx] != value[idx - 1]:
            runs.append(value[start:idx])
            start = idx
    runs.append(value[start:])
    return runs
