"""Audit helpers for DISP sanitizer results."""

from __future__ import annotations

import time
from typing import Any, Dict

from .models import DispResult


def audit_record(*, req_id: str, result: DispResult, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    record: Dict[str, Any] = {
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
        record.update(extra)
    return record


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
