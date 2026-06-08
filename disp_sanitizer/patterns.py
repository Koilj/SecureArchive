"""Compiled regex patterns used by detectors and validators."""

from __future__ import annotations

import re


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
ZERO_WIDTH_BIDI = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
WHITESPACE = re.compile(r"\s+")

HTML_TAG_LIKE = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
SCRIPTISH = re.compile(
    r"<\s*script\b|on\w+\s*=|javascript\s*:|data\s*:\s*text/html",
    re.I,
)
PROMPT_INJECTION = re.compile(
    r"\b(ignore|disregard)\b.*\b(instruction|previous|system)\b|"
    r"\b(system\s+prompt|developer\s+message|jailbreak)\b|"
    r"\b(reveal|leak|exfiltrate)\b.*\b(secret|key|token|policy)\b",
    re.I | re.S,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.I)
