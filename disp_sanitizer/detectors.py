"""Signal detectors for suspicious user-controlled text."""

from __future__ import annotations

from typing import List

from .patterns import HTML_TAG_LIKE, PROMPT_INJECTION, SCRIPTISH


def detect_xss_like(value: str) -> List[str]:
    if SCRIPTISH.search(value):
        return ["XSS_SCRIPTISH"]
    if HTML_TAG_LIKE.search(value):
        return ["HTML_TAGS"]
    return []


def detect_prompt_injection(value: str) -> List[str]:
    return ["PROMPT_INJECTION"] if PROMPT_INJECTION.search(value) else []


def contains_active_script_pattern(value: str) -> bool:
    return bool(SCRIPTISH.search(value))
