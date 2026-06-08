"""Typed models used across the DISP sanitizer package."""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict, List, Tuple

from .constants import DISP_VERSION


@dataclasses.dataclass(frozen=True)
class FieldRule:
    name: str
    max_len_key: str
    aliases: Tuple[str, ...] = ()
    collapse_whitespace: bool = True
    normalize_newlines: bool = False
    mixed_script_sensitive: bool = False
    detect_xss: bool = True
    detect_prompt_injection: bool = False
    detect_dos_like: bool = True
    validator: str | None = None
    value_transform: Callable[[Any], Any] | None = None
    short_field_fatal: bool = False


@dataclasses.dataclass(frozen=True)
class FieldResult:
    name: str
    value: str
    flags: List[str]


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
    version: str = DISP_VERSION
    field_flags: Dict[str, List[str]] = dataclasses.field(default_factory=dict)
