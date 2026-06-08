from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .constants import DEFAULT_LIMITS
from .detectors import contains_active_script_pattern, detect_prompt_injection, detect_xss_like
from .models import DispResult, FieldResult, FieldRule
from .policy import ai_wrap, current_version, decide, request_hash, score_from_flags
from .profiles import METADATA_RULES, UPLOAD_RULES
from .text import (
    collapse_whitespace,
    has_mixed_scripts,
    looks_dos_like,
    normalize_newlines,
    safe_for_ui_text,
    stable_dedupe,
    strip_control_and_bidi,
    unicode_nfkc,
)
from .validators import validate_named


def sanitize_upload_metadata(raw: Dict[str, Any], *, limits: Dict[str, int] | None = None) -> DispResult:
    merged_limits = _merge_limits(limits)
    field_results = _sanitize_fields(raw, UPLOAD_RULES, merged_limits)
    ledger_keys = ("title", "authors", "discipline", "license", "doi", "keywords", "description", "fileHash")
    return _build_result(field_results, ledger_keys=ledger_keys)


def sanitize_metadata_only(raw: Dict[str, Any], *, limits: Dict[str, int] | None = None) -> DispResult:
    merged_limits = _merge_limits(limits)
    field_results = _sanitize_fields(raw, METADATA_RULES, merged_limits)
    ledger_keys = tuple(result.name for result in field_results)
    return _build_result(field_results, ledger_keys=ledger_keys)


def _sanitize_fields(raw: Dict[str, Any], rules: Sequence[FieldRule], limits: Dict[str, int]) -> List[FieldResult]:
    results: List[FieldResult] = []
    for rule in rules:
        raw_value = _resolve_raw_value(raw, rule)
        results.append(_sanitize_field(rule, raw_value, limits[rule.max_len_key]))
    return results


def _sanitize_field(rule: FieldRule, raw_value: Any, max_len: int) -> FieldResult:
    if rule.value_transform is not None:
        raw_value = rule.value_transform(raw_value)

    value = "" if raw_value is None else str(raw_value)
    value = unicode_nfkc(value)
    value, flags = strip_control_and_bidi(value)

    if rule.normalize_newlines:
        value = normalize_newlines(value).strip()
    elif rule.collapse_whitespace:
        value = collapse_whitespace(value)

    if len(value) > max_len:
        flags.append("TRUNCATED")
        value = value[:max_len]

    if rule.mixed_script_sensitive and value and has_mixed_scripts(value):
        flags.append("MIXED_SCRIPTS")
    if rule.detect_dos_like and looks_dos_like(value):
        flags.append("DOS_LIKE")
    if rule.detect_xss:
        flags.extend(detect_xss_like(value))
    if rule.detect_prompt_injection:
        flags.extend(detect_prompt_injection(value))
    if not validate_named(rule.validator, value):
        flags.append("FORMAT_INVALID")

    return FieldResult(name=rule.name, value=value, flags=flags)


def _build_result(field_results: Sequence[FieldResult], *, ledger_keys: Iterable[str]) -> DispResult:
    sanitized_payload = {result.name: result.value for result in field_results}
    field_flags = {result.name: stable_dedupe(result.flags) for result in field_results if result.flags}
    combined_flags = stable_dedupe(
        flag
        for result in field_results
        for flag in result.flags
    )

    fatal_short_fields = any(
        rule.short_field_fatal
        and contains_active_script_pattern(sanitized_payload.get(rule.name, ""))
        for rule in _rules_by_name(field_results)
    )
    decision, reasons = decide(combined_flags, fatal_short_fields=fatal_short_fields)

    return DispResult(
        sanitized_payload=sanitized_payload,
        ui_safe={key: safe_for_ui_text(value) for key, value in sanitized_payload.items()},
        ai_safe_text=ai_wrap(sanitized_payload),
        ledger_safe={key: sanitized_payload[key] for key in ledger_keys},
        risk_score=score_from_flags(combined_flags),
        flags=combined_flags,
        decision=decision,
        reasons=reasons,
        request_hash=request_hash(sanitized_payload),
        version=current_version(),
        field_flags=field_flags,
    )


def _rules_by_name(field_results: Sequence[FieldResult]) -> Sequence[FieldRule]:
    names = {result.name for result in field_results}
    catalog = {rule.name: rule for rule in (*UPLOAD_RULES, *METADATA_RULES)}
    return [catalog[name] for name in names if name in catalog]


def _resolve_raw_value(raw: Dict[str, Any], rule: FieldRule) -> Any:
    for candidate in (rule.name, *rule.aliases):
        if candidate in raw:
            return raw.get(candidate)
    return ""


def _merge_limits(overrides: Dict[str, int] | None) -> Dict[str, int]:
    merged = dict(DEFAULT_LIMITS)
    if overrides:
        merged.update(overrides)
    return merged
