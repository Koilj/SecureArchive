"""Static policy configuration for DISP sanitization."""

from __future__ import annotations


DISP_VERSION = "disp_v2"

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

FLAG_WEIGHTS = {
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

REVIEW_FLAGS = {
    "XSS_SCRIPTISH",
    "HTML_TAGS",
    "PROMPT_INJECTION",
    "ZERO_WIDTH_OR_BIDI",
    "CONTROL_CHARS",
    "MIXED_SCRIPTS",
    "JSON_DUPLICATE_KEYS",
    "TRUNCATED",
}
