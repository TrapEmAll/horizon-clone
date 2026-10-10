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
    Capability("Desktop atomic artifact writes", "implemented", "same-directory replacement for GUI mutations and exports", ("_atomic_write_bytes", "_atomic_write_text")),
    Capability("Desktop metadata editor dispatch", "implemented", "GUI inspection and separate-output editing for registry-supported explicit artifacts", ("open_editor_artifact", "edit_editor_artifact")),
    Capability("XDBF/GPD inspection", "implemented", "observed XDBF entries, payload digests, namespace-5 strings, achievement payloads, and profile aggregates", ("parse_xdbf", "xdbf_payload_surface", "list_embedded_xdbf", "list_embedded_achievements", "summarize_profile_achievements", "--editor-inspect")),
    Capability("XDBF/GPD mutation", "implemented", "bounded XDBF repacking and observed achievement edits", ("repack_xdbf_entries", "mutate_xdbf_text", "mutate_xdbf_achievement")),
    Capability("Managed surface editor dispatch", "implemented", "Read-only editor-registry dispatch for exported REA managed-members evidence", ("ManagedSurfaceEditor", "EditorRegistry")),
    Capability("Opaque Account editor dispatch", "implemented", "Deterministic Account payload inspection and same-size replacement without schema inference", ("AccountEditor", "EditorRegistry")),
    Capability("ProfileData contract", "metadata-only", "REA observed six-field Horizon.ProfileData surface; Account serialization unresolved", ("ProfileData",)),
    Capability("ProfileData metadata editor dispatch", "metadata-only", "Typed editor for the authenticated six-field ProfileData envelope; Account serialization remains unresolved", ("ProfileDataEditor", "--editor-edit-values")),
    Capability("Account serialization", "unresolved", "supplied Account payload is opaque; REA exposed no managed Account type, serializer, field offsets, or Account-specific call edge", ("mutate_stfs_entry_same_size",)),
    Capability("Account crypto provider bridge", "provider-boundary", "Connects opaque Account payloads to the authenticated class3 save signatures while preserving unresolved encryption status/length semantics", ("AccountCodec", "encrypt_raw", "NativeSaveBinding", "PowerShellNativeSaveProvider")),
    Capability("Skyrim enum catalogs", "metadata-only", "REA-managed Constant rows authenticate named enum values; save layouts and editor behavior remain unresolved", ("enum_member_values", "resolve_skyrim_enum_member", "validate_skyrim_enum_values")),
    Capability("Gears/Halo title editors", "catalog-only", "REA observed type and member names without authenticated field layouts or behavioral replay", ("observed_editor_inventory", "halo_general_class_types")),
    Capability("Halo typed metadata validation", "metadata-only", "Validates values against the authenticated REA field-type slice without assigning save offsets", ("validate_halo_metadata_values",)),
    Capability("Halo metadata editor dispatch", "metadata-only", "Validates and edits explicit Halo metadata JSON envelopes without binary serialization", ("HaloMetadataEditor",)),
    Capability("Gears EntryID validation", "metadata-only", "Resolves and validates all 1,139 authenticated EntryID Constant values without save-offset inference", ("resolve_gears_entry_id", "validate_gears_entry_ids")),
    Capability("Authenticated Constant catalog dispatch", "metadata-only", "Unified registry dispatch for validated Skyrim, Gears, shared, and global Constant envelopes", ("ConstantCatalogEditor",)),
    Capability("Legacy catalog editor dispatch", "metadata-only", "Validates REA-observed legacy editor member names and signed-32-bit values without inventing enum assignments or save offsets", ("LegacyCatalogEditor", "EditorRegistry")),
    Capability("Managed editor surface export", "observed-only", "Exports filtered types, fields, and methods from a retained REA managed-members bundle without loading the assembly", ("managed_surface_report", "--managed-surface")),
    Capability("Joined managed editor schemas", "observed-only", "Joins every observed type with its fields and methods without inferring save offsets", ("managed_schema_report", "--managed-schema")),
    Capability("Managed field-access evidence", "observed-only", "Exports REA field-access anchors for matched managed editor types without inferring binary offsets", ("--schema-field-accesses",)),
    Capability("Managed schema registry dispatch", "observed-only", "Routes explicit .managed-schema.json evidence through the clean-room editor registry", ("ManagedSchemaEditor", "EditorRegistry")),
    Capability("Anti-analysis evidence report", "observed-only", "Reports REA-observed managed anti-analysis markers without executing or bypassing the target", ("anti_analysis_report", "--anti-analysis")),
    Capability("Embedded UI/resource surface", "observed-only", "REA observed 205 embedded managed resource payloads; feature ownership, rendering behavior, and signed-resource semantics unresolved", ("observed_resource_surface", "resource_surface_report", "verify_managed_resource_payloads", "--resource-surface", "--resource-bundle", "--verify-resources")),
    Capability("Native save/runtime boundaries", "provider-boundary", "REA observed class3 save crypto, LZO, device I/O, and DNG/HVM imports; explicit x86 adapters require caller-supplied providers and keys", ("native_surface_report", "native_export_contract_report", "NativeSaveBinding", "CtypesNativeSaveProvider", "PowerShellNativeSaveProvider", "LzoBinding", "NativeRuntimeBinding")),
    Capability("Complete managed P/Invoke inventory", "observed-only", "Reports all 54 REA-authenticated managed native declarations without executing them", ("managed_native_import_report", "--native-import-bundle")),
    Capability("LZO codec provider bridge", "provider-boundary", "Validated high-level wrapper plus explicit x86 path-bound adapters over the four observed LZO imports", ("LzoCodec", "LzoBinding", "CtypesLzoProvider", "PowerShellLzoProvider")),
    Capability("Device exploration surface", "provider-boundary", "REA observed device thumbnail properties and an i8 DeviceSize property; device protocols unresolved", ("device_surface_report", "DeviceBinding")),
    Capability("Host volume inventory", "implemented", "Read-only Windows logical-volume identity and capacity inventory", ("device_inventory_report", "--device-inventory")),
    Capability("DNG/HVM runtime adapter", "provider-boundary", "REA recovered CheckRuntime, RunHVM, and GetUserString declarations; native argument semantics unresolved", ("NativeRuntimeBinding",)),
    Capability("Console signing", "provider-boundary", "public signature metadata observed; explicit caller-bounded RSA verification is available, but package layout and console validity remain unresolved", ("sign_with_provider", "verify_detached_signature", "verify_embedded_signature_region", "--verify-embedded-signature")),
    Capability("CON public-key extraction", "implemented", "Extracts the public RSA modulus and exponent from an observed CON certificate", ("extract_stfs_public_key", "--public-key")),
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
        from .horizon_catalog import catalog_member_values, observed_catalogs

        return {
            **{item.name: list(item.members) for item in observed_catalogs()},
            "values": {
                item.name: dict(catalog_member_values(item.name))
                for item in observed_catalogs()
                if item.values_observed
            },
        }
    if name == "skyrim":
        from .skyrim_catalog import enum_member_values, observed_skyrim_enum_summary, observed_skyrim_enums

        report = {item.name: list(item.members) for item in observed_skyrim_enums()}
        report["summary"] = observed_skyrim_enum_summary()
        report["values"] = {
            item.name: dict(enum_member_values(item.name)) for item in observed_skyrim_enums()
        }
        return report
    if name == "gears":
        from .gears_catalog import gears_entry_id_summary, gears_entry_id_values, gears_of_war_3_entry_ids

        return {"EntryID": list(gears_of_war_3_entry_ids()), "values": gears_entry_id_values(), "summary": gears_entry_id_summary()}
    if name == "halo":
        from .halo_catalog import halo_general_class_field_counts, halo_general_class_field_types, halo_general_class_method_summary, halo_general_class_property_names, halo_general_class_types

        return {
            "types": list(halo_general_class_types()),
            "field_counts": halo_general_class_field_counts(),
            "field_types": halo_general_class_field_types(),
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

