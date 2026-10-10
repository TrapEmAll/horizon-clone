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
    EditorInventory("Dragon Ball Xenoverse", 1, "catalog-only"),
    EditorInventory("Code Veronica X", 1, "catalog-only"),
    EditorInventory("Devil May Cry", 1, "catalog-only"),
    EditorInventory("Ninja Gaiden 3", 2, "catalog-only"),
    EditorInventory("State of Decay", 1, "catalog-only"),
    EditorInventory("Castle Crashers", 1, "catalog-only"),
    EditorInventory("Saints Row", 3, "catalog-only"),
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
    Capability("Account serialization", "unresolved", "supplied Account payload is opaque; REA exposed no managed Account type, serializer, field offsets, or Account-specific call edge", ("mutate_stfs_entry_same_size",)),
    Capability("Skyrim/Gears/Halo title editors", "catalog-only", "REA observed type and member names without authenticated field layouts or behavioral replay", ("observed_editor_inventory", "halo_general_class_types")),
    Capability("Embedded UI/resource surface", "observed-only", "REA observed 205 embedded managed resource payloads; feature ownership, rendering behavior, and signed-resource semantics unresolved", ("observed_resource_surface", "--resource-surface")),
    Capability("Native save/runtime boundaries", "provider-boundary", "REA observed class3 save crypto, LZO, device I/O, and DNG/HVM imports; signatures are modeled but protocols remain unresolved", ("native_surface_report", "NativeSaveBinding", "LzoBinding", "NativeRuntimeBinding")),
    Capability("Device exploration surface", "provider-boundary", "REA observed device thumbnail properties and an i8 DeviceSize property; device protocols unresolved", ("device_surface_report", "DeviceBinding")),
    Capability("DNG/HVM runtime adapter", "provider-boundary", "REA recovered CheckRuntime, RunHVM, and GetUserString declarations; native argument semantics unresolved", ("NativeRuntimeBinding",)),
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


def catalog_report(name: str) -> dict[str, object]:
    """Return one REA-observed catalog without claiming binary layouts."""
    if name == "shared":
        from .horizon_catalog import observed_catalogs

        return {item.name: list(item.members) for item in observed_catalogs()}
    if name == "skyrim":
        from .skyrim_catalog import observed_skyrim_enum_summary, observed_skyrim_enums

        report = {item.name: list(item.members) for item in observed_skyrim_enums()}
        report["summary"] = observed_skyrim_enum_summary()
        return report
    if name == "gears":
        from .gears_catalog import gears_entry_id_summary, gears_of_war_3_entry_ids

        return {"EntryID": list(gears_of_war_3_entry_ids()), "summary": gears_entry_id_summary()}
    if name == "halo":
        from .halo_catalog import halo_general_class_field_counts, halo_general_class_method_summary, halo_general_class_property_names, halo_general_class_types

        return {
            "types": list(halo_general_class_types()),
            "field_counts": halo_general_class_field_counts(),
            "method_summary": halo_general_class_method_summary(),
            "property_names": list(halo_general_class_property_names()),
        }
    if name == "legacy":
        from .legacy_catalog import legacy_catalog_report

        return legacy_catalog_report()
    if name == "global":
        from .global_catalog import global_catalog_report

        return global_catalog_report()
    raise KeyError(f"unknown catalog: {name}")

