from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from tfstride.providers.coercion import dedupe_strings, unknown_block_at


def first_unknown_block(value: Any) -> Any:
    if value is True or isinstance(value, Mapping):
        return value
    return unknown_block_at(value, 0)


def unknown_block_at_index(value: Any, index: int, *, mapping_applies_to_any_index: bool = False) -> Any:
    if value is True:
        return value
    if isinstance(value, Mapping):
        return value if mapping_applies_to_any_index or index == 0 else None
    return unknown_block_at(value, index)


def block_value(block: Any, key: str) -> Any:
    if isinstance(block, Mapping):
        return block.get(key)
    if block is True:
        return True
    return None


# Re-export for downstream consumers.
dedupe = dedupe_strings


def uncertainty_evidence(uncertainties: Iterable[str], field_markers: tuple[str, ...]) -> list[str]:
    return [uncertainty for uncertainty in uncertainties if any(marker in uncertainty for marker in field_markers)]
