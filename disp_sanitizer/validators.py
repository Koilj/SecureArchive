"""Format validators for strict DISP fields."""

from __future__ import annotations

from .patterns import HEX64


def validate_named(name: str | None, value: str) -> bool:
    if name is None:
        return True
    if name == "hex64":
        return bool(value) and bool(HEX64.match(value))
    if name == "non_empty":
        return bool(value)
    raise ValueError(f"Unknown validator: {name}")
