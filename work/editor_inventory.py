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
    Capability("Canonical FATX content path", "implemented", "Profile filename and Content path derived from authenticated STFS creator/profile, title ID, and content type fields", ("stfs_magic_filename", "stfs_fatx_device_path", "--fatx-path")),
    Capability("STFS file management", "implemented", "observed file-table mutation substrate", ("repack_stfs_entries", "add_stfs_directory", "move_stfs_entry", "rename_stfs_entry")),
    Capability("Desktop atomic artifact writes", "implemented", "same-directory replacement for GUI mutations and exports", ("_atomic_write_bytes", "_atomic_write_text")),
    Capability("Desktop metadata editor dispatch", "implemented", "GUI inspection, separate-output editing, authenticated resource export, detached development signing, and CON signature verification for explicit artifacts", ("open_editor_artifact", "edit_editor_artifact", "extract_managed_resources", "sign_loaded_bytes", "sign_con_package", "verify_con_signature")),
    Capability("XDBF/GPD/FIT inspection", "implemented", "observed XDBF entries across GPD and profile FIT payloads, payload digests, namespace-5 strings, achievement payloads, and profile aggregates", ("parse_xdbf", "xdbf_payload_surface", "list_embedded_xdbf", "list_embedded_achievements", "summarize_profile_achievements", "--editor-inspect")),
    Capability("XDBF/GPD mutation", "implemented", "bounded XDBF repacking, observed achievement edits, raw achievement-flag masks, and exact profile-wide namespace-5 text replacement", ("repack_xdbf_entries", "mutate_xdbf_text", "mutate_xdbf_achievement", "mutate_xdbf_achievement_flags", "mutate_profile_achievement_flags", "mutate_profile_xdbf_text", "--achievement-flags-or", "--achievement-flags-and-not", "--profile-achievement-flags-or", "--profile-achievement-flags-and-not", "--profile-xdbf-text")),
    Capability("Managed surface editor dispatch", "implemented", "Read-only editor-registry dispatch for exported REA managed-members evidence", ("ManagedSurfaceEditor", "EditorRegistry")),
    Capability("Opaque Account editor dispatch", "implemented", "Deterministic Account payload inspection and same-size replacement without schema inference", ("AccountEditor", "EditorRegistry")),
    Capability("ProfileData contract", "metadata-only", "REA observed six-field Horizon.ProfileData surface; Account serialization unresolved", ("ProfileData",)),
    Capability("ProfileData metadata editor dispatch", "metadata-only", "Typed editor for the authenticated six-field ProfileData envelope; Account serialization remains unresolved", ("ProfileDataEditor", "--editor-edit-values")),
    Capability("Account serialization", "unresolved", "supplied Account payload is opaque; REA exposed no managed Account type, serializer, field offsets, or Account-specific call edge", ("mutate_stfs_entry_same_size",)),
    Capability("Historical Account body codec", "historical-reference", "Unlicense historical XProfile reference matches the supplied 404-byte Account boundary; this does not replace REA evidence for Horizon's serializer or prove console validity", ("AccountRecord", "unobfuscate_account", "obfuscate_account", "historical_account_report", "mutate_historical_account", "--historical-account-inspect", "--historical-account-edit")),
    Capability("Account crypto provider bridge", "provider-boundary", "Connects opaque Account payloads to authenticated class3 signatures and caller-owned nonpersistent key providers, including explicit CLI decrypt/encrypt through an x86 bridge, while preserving caller-resolved output lengths", ("AccountCodec", "AccountKeyProvider", "CommandAccountKeyProvider", "decrypt_account_entry", "encrypt_account_payload", "decrypt_with_key_provider", "encrypt_with_key_provider", "encrypt_raw", "NativeSaveBinding", "PowerShellNativeSaveProvider")),
    Capability("Skyrim enum catalogs", "metadata-only", "REA-managed Constant rows authenticate named enum values; save layouts and editor behavior remain unresolved", ("enum_member_values", "resolve_skyrim_enum_member", "validate_skyrim_enum_values")),
    Capability("Gears/Halo title editors", "catalog-only", "REA observed type and member names without authenticated field layouts or behavioral replay", ("observed_editor_inventory", "halo_general_class_types")),
    Capability("Halo typed metadata validation", "metadata-only", "Validates 489 decoded fields across 92 named classes from REA without assigning save offsets", ("validate_halo_metadata_values",)),
    Capability("Halo metadata editor dispatch", "metadata-only", "Validates and edits explicit Halo metadata JSON envelopes without binary serialization", ("HaloMetadataEditor",)),
    Capability("Gears EntryID validation", "metadata-only", "Resolves and validates all 1,139 authenticated EntryID Constant values without save-offset inference", ("resolve_gears_entry_id", "validate_gears_entry_ids")),
    Capability("Authenticated Constant catalog dispatch", "metadata-only", "Unified registry dispatch for validated Skyrim, Gears, shared, and global Constant envelopes", ("ConstantCatalogEditor",)),
    Capability("Legacy catalog editor dispatch", "metadata-only", "Validates REA-observed legacy editor member names and signed-32-bit values without inventing enum assignments or save offsets", ("LegacyCatalogEditor", "EditorRegistry")),
    Capability("Managed editor surface export", "observed-only", "Exports filtered types, fields, and methods from a retained REA managed-members bundle without loading the assembly", ("managed_surface_report", "--managed-surface")),
    Capability("Managed assembly reference inventory", "observed-only", "Exports authenticated declared assembly references and versions from a retained REA artifact bundle without loading dependencies", ("managed_reference_report", "--managed-references")),
    Capability("Managed artifact provenance", "observed-only", "Reports authenticated PE/CLI identity, assembly metadata, dependency/resource counts, and partial-coverage diagnostics", ("managed_artifact_report", "--managed-artifact")),
    Capability("Managed assembly reference inventory", "observed-only", "Exports authenticated declared assembly references and versions from a retained REA artifact bundle without loading dependencies", ("managed_reference_report", "--managed-references")),
    Capability("Managed editor-family inventory", "observed-only", "Groups authenticated managed types into queryable Horizon.PackageEditors families without inferring registration or save layouts", ("managed_editor_family_report", "--managed-editor-families")),
    Capability("Named title namespace inventory", "observed-only", "Separates stable non-obfuscated managed namespaces for follow-on title-editor reconstruction", ("managed_named_namespace_report", "--managed-named-namespaces")),
    Capability("Guarded managed-method inventory", "observed-only", "Reports authenticated methods with throw/no-return opcode evidence without executing or bypassing them", ("managed_guarded_methods_report", "--managed-guarded-methods")),
    Capability("Managed body-fidelity audit", "observed-only", "Measures duplicate retained method-body hashes and offsets so guard stubs are not mistaken for serializer implementations", ("managed_body_fidelity_report", "--managed-body-fidelity")),
    Capability("Joined managed editor schemas", "observed-only", "Joins every observed type with its fields and methods without inferring save offsets", ("managed_schema_report", "--managed-schema")),
    Capability("Managed field-access evidence", "observed-only", "Exports REA field-access anchors for matched managed editor types without inferring binary offsets", ("--schema-field-accesses",)),
    Capability("Managed I/O contract evidence", "observed-only", "Projects authenticated Read/Write/Load/Save CIL signatures, anchors, field accesses, and call targets without inferring save layouts", ("managed_io_contract_report", "--managed-io-contract")),
    Capability("Managed schema registry dispatch", "observed-only", "Routes explicit .managed-schema.json evidence through the clean-room editor registry", ("ManagedSchemaEditor", "EditorRegistry")),
    Capability("Anti-analysis evidence report", "observed-only", "Reports REA-observed managed anti-analysis markers in CLI and desktop workflows without executing or bypassing the target", ("anti_analysis_report", "--anti-analysis", "show_anti_analysis")),
    Capability("Embedded UI/resource surface", "observed-only", "REA observed 205 embedded managed resource payloads; uniquely hash-verified extraction, conservative magic classification, and safe image dimensions are available, while feature ownership, rendering behavior, and signed-resource semantics remain unresolved", ("observed_resource_surface", "resource_surface_report", "verify_managed_resource_payloads", "extract_managed_resource_payloads", "classify_resource_payload", "resource_payload_metadata", "--resource-surface", "--resource-bundle", "--verify-resources", "--extract-resources")),
    Capability(".NET resource index inspection", "implemented", "Parses standard .resources name/type indexes and authenticated byte spans without deserializing values", ("parse_dotnet_resources", "--dotnet-resource-index")),
    Capability("Native save/runtime boundaries", "provider-boundary", "REA observed class3 save crypto, LZO, device I/O, and DNG/HVM imports; explicit x86 adapters require caller-supplied providers and keys", ("native_surface_report", "native_export_contract_report", "native_installation_report", "--native-installation", "NativeSaveBinding", "CtypesNativeSaveProvider", "PowerShellNativeSaveProvider", "LzoBinding", "NativeRuntimeBinding")),
    Capability("Complete managed P/Invoke inventory", "observed-only", "Reports all 54 REA-authenticated managed native declarations without executing them", ("managed_native_import_report", "--native-import-bundle")),
    Capability("LZO codec provider bridge", "provider-boundary", "Validated high-level wrapper plus explicit x86 path-bound adapters over the four observed LZO imports, including a verified lzo2a round trip with 256 KiB work memory", ("LzoCodec", "LzoBinding", "CtypesLzoProvider", "PowerShellLzoProvider")),
    Capability("Device exploration surface", "provider-boundary", "REA observed device properties plus CreateFile/DeviceIoControl declarations; explicit read-only Windows handles and raw IOCTL forwarding are available through the library and CLI, while FATX command semantics remain unresolved", ("device_surface_report", "DeviceBinding", "DeviceIoBinding", "WindowsDeviceIoProvider", "device_ioctl_report", "--device-ioctl")),
    Capability("Host volume inventory", "implemented", "Read-only Windows logical-volume identity, capacity, and bounded directory listing in CLI and desktop workflows", ("device_inventory_report", "enumerate_host_device_entries", "--device-inventory", "--device-list", "show_device_inventory")),
    Capability("DNG/HVM runtime adapter", "provider-boundary", "REA recovered x86 and x64 CheckRuntime/GetUserString declarations plus RunHVM; explicit path-bound PowerShell bridges preserve raw return values while native argument semantics remain unresolved", ("NativeRuntimeBinding", "PowerShellNativeRuntimeProvider", "check_runtime64", "get_user_string64")),
    Capability("Console signing", "provider-boundary", "observed CON-layout XeCrypt SHA-1 package signing is available for an explicit matching RSA private key, including post-mutation output signing; authorized key ownership and console policy remain unresolved", ("sign_stfs_console_package", "sign_with_provider", "sign_detached_signature", "verify_detached_signature", "verify_embedded_signature_region", "verify_xecrypt_sha1_pkcs1v15", "verify_stfs_console_signature", "--sign-stfs-package", "--sign-written-package", "--sign-detached-signature", "--sign-written-output", "--verify-embedded-signature", "--verify-stfs-signature")),
    Capability("CON public-key extraction", "implemented", "Extracts the public RSA modulus and exponent from an observed CON certificate", ("extract_stfs_public_key", "--public-key")),
    Capability("STFS signature mutation audit", "implemented", "Compares stored signature regions and changed non-signature bytes without claiming console validity", ("stfs_signature_mutation_report", "--signature-compare")),
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

