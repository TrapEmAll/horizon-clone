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


@dataclass(frozen=True)
class Capability:
    name: str
    status: str
    evidence: str
    entry_points: tuple[str, ...]


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


_CAPABILITIES = (
    Capability("STFS inspection", "implemented", "STFS container parsing and file-table evidence", ("inspect", "list_stfs_entries")),
    Capability("STFS extraction", "implemented", "STFS file-table and block traversal", ("extract_stfs", "read_stfs_entry")),
    Capability("STFS hash verification", "implemented", "three-level STFS hash-tree implementation", ("verify_stfs_hashes", "rehash_stfs_hashes")),
    Capability("STFS metadata and thumbnails", "implemented", "observed STFS metadata fields and bounded thumbnail regions", ("mutate_stfs_metadata", "mutate_stfs_thumbnails")),
    Capability("STFS file management", "implemented", "observed file-table mutation substrate", ("repack_stfs_entries", "add_stfs_directory", "move_stfs_entry", "rename_stfs_entry")),
    Capability("XDBF/GPD inspection", "implemented", "observed XDBF entry and namespace-5/achievement payloads", ("parse_xdbf", "list_embedded_xdbf", "list_embedded_achievements")),
    Capability("XDBF/GPD mutation", "implemented", "bounded XDBF repacking and observed achievement edits", ("repack_xdbf_entries", "mutate_xdbf_text", "mutate_xdbf_achievement")),
    Capability("ProfileData contract", "metadata-only", "REA observed six-field Horizon.ProfileData surface; Account serialization unresolved", ("ProfileData",)),
    Capability("Account serialization", "unresolved", "supplied Account payload is opaque and REA exposed no serializer, offsets, or replay", ("mutate_stfs_entry_same_size",)),
    Capability("Skyrim/Gears/Halo title editors", "catalog-only", "REA observed type and member names without authenticated field layouts or behavioral replay", ("observed_editor_inventory", "halo_general_class_types")),
    Capability("Console signing", "provider-boundary", "public signature metadata observed; private signing material and console validity unavailable", ("sign_with_provider",)),
)


def capability_report() -> dict[str, object]:
    """Return an explicit, evidence-qualified implementation ledger."""
    return {
        "managed_type_count": 7693,
        "managed_method_count": 37401,
        "capabilities": [
            {
                "name": item.name,
                "status": item.status,
                "evidence": item.evidence,
                "entry_points": list(item.entry_points),
            }
            for item in _CAPABILITIES
        ],
    }

