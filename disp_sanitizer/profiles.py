"""Field profiles for different DISP sanitization flows."""

from __future__ import annotations

from typing import Any, Sequence

from .models import FieldRule


def _join_keywords(value: Any) -> Any:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return value


UPLOAD_RULES: Sequence[FieldRule] = (
    FieldRule("title", "max_title", mixed_script_sensitive=True, short_field_fatal=True),
    FieldRule("authors", "max_authors", mixed_script_sensitive=True, short_field_fatal=True),
    FieldRule("discipline", "max_discipline", mixed_script_sensitive=True, short_field_fatal=True),
    FieldRule("license", "max_license", detect_xss=False),
    FieldRule("doi", "max_doi", detect_xss=False),
    FieldRule("keywords", "max_keywords", short_field_fatal=True),
    FieldRule(
        "description",
        "max_description",
        collapse_whitespace=False,
        normalize_newlines=True,
        detect_prompt_injection=True,
    ),
    FieldRule("owner", "max_owner", detect_xss=False),
    FieldRule(
        "encryptedAesKey",
        "max_encrypted_key",
        detect_xss=False,
        detect_dos_like=False,
        validator="non_empty",
    ),
    FieldRule("fileHash", "max_file_hash", detect_xss=False, detect_dos_like=False, validator="hex64"),
)

METADATA_RULES: Sequence[FieldRule] = (
    FieldRule("title", "max_title", mixed_script_sensitive=True, short_field_fatal=True),
    FieldRule(
        "authors",
        "max_authors",
        aliases=("author",),
        mixed_script_sensitive=True,
        short_field_fatal=True,
    ),
    FieldRule(
        "discipline",
        "max_discipline",
        aliases=("department",),
        mixed_script_sensitive=True,
        short_field_fatal=True,
    ),
    FieldRule("keywords", "max_keywords", short_field_fatal=True, value_transform=_join_keywords),
    FieldRule(
        "description",
        "max_description",
        collapse_whitespace=False,
        normalize_newlines=True,
        detect_prompt_injection=True,
    ),
)
