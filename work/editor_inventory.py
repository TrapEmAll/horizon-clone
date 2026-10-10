"""Aggregate title-editor coverage observed by REA.

This module intentionally exposes counts and capability status, not proprietary
member labels or inferred package layouts.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EditorInventory:
    name: str
    observed_type_count: int
    implementation_status: str


_INVENTORY = (
    EditorInventory("Skyrim", 3, "catalog-only"),
    EditorInventory("Gears of War 3", 1, "catalog-only"),
    EditorInventory("Halo general classes", 103, "catalog-only"),
)


def observed_editor_inventory() -> tuple[EditorInventory, ...]:
    return _INVENTORY


def inventory_summary() -> dict[str, object]:
    return {
        "managed_type_count": 7693,
        "editors": [
            {
                "name": item.name,
                "observed_type_count": item.observed_type_count,
                "implementation_status": item.implementation_status,
            }
            for item in _INVENTORY
        ],
    }

