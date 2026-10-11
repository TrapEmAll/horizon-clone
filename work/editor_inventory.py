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


def rea_feature_ledger() -> dict[str, object]:
    """Return the compact REA ledger used to gate reconstruction work."""

    return {
        "source": "REA shipped-artifact evidence",
        "artifact": "Horizon.exe",
        "evidence": {
            "managed_artifact": "ev_30551abd91b6a09fbc26f7b8264d514c62e4df84ea6ded235f2ae27aa669e2fa",
            "managed_members": "ev_6514c14f1e6b41b3396b80e944e73751ef34bbcaf65a549262065abbb3ec9301",
            "native_boundaries": "ev_0db9f22f86a797ce3601eafde37782d66fcb67ae376c1661933b53cb786a3728",
            "horizon_native": "ev_89e4fc748456e53f0a366f862127d64187af35bf99c73ee9fb91a43837d54631",
        },
        "observed": {
            "managed_types": 7693,
            "managed_methods": 37401,
            "managed_pinvoke_declarations": 54,
            "profile_data_fields": [
                {"name": "FromDevice", "type": "bool"},
                {"name": "XUID", "type": "u8"},
                {"name": "Gamertag", "type": "string"},
                {"name": "Gamerpicture", "type": "u1[]"},
                {"name": "ProfileId", "type": "u8"},
                {"name": "Favorite", "type": "bool"},
            ],
            "horizon_native_exports": ["CheckRuntime", "DNG_Runtime", "GetUserString", "RunHVM"],
        },
        "unresolved": [
            "Account type and Horizon Account serializer were not present in authenticated managed evidence",
            "Title-specific save offsets and serializers were not established by static evidence",
            "Native DNG/HVM argument semantics and device protocol values remain unresolved",
            "Retail console-authoritative signing and key-vault ownership remain unresolved",
            "Windows runtime GUI capture is unavailable in the current REA provider environment",
        ],
    }


_CAPABILITIES = (
    Capability("STFS inspection", "implemented", "STFS container parsing and file-table evidence, including preserved raw entry flags", ("inspect", "list_stfs_entries")),
    Capability("STFS extraction", "implemented", "STFS file-table and block traversal", ("extract_stfs", "read_stfs_entry")),
    Capability("STFS hash verification", "implemented", "three-level STFS hash-tree implementation", ("verify_stfs_hashes", "rehash_stfs_hashes")),
    Capability("STFS metadata and thumbnails", "implemented", "observed STFS metadata fields and bounded thumbnail regions", ("mutate_stfs_metadata", "mutate_stfs_thumbnails")),
    Capability("Profile asset surface", "implemented", "Recognizes supplied profile tile/theme/PEC/WLE/FIT/avatar entries, validates tile PNG dimensions, and rehashes explicit replacements while leaving opaque formats uninterpreted", ("profile_asset_report", "mutate_profile_assets", "--profile-assets", "--profile-asset")),
    Capability("Canonical FATX content path", "implemented", "Profile filename and Content path derived from authenticated STFS creator/profile, title ID, and content type fields", ("stfs_magic_filename", "stfs_fatx_device_path", "--fatx-path")),
    Capability("STFS file management", "implemented", "observed file-table mutation substrate, including explicit recursive directory removal", ("repack_stfs_entries", "add_stfs_directory", "move_stfs_entry", "rename_stfs_entry", "--remove-tree")),
    Capability("Desktop atomic artifact writes", "implemented", "same-directory replacement for GUI mutations and exports, including explicit selected-entry in-place replacement, capacity-aware repack, file and recursive-directory removal, rename, and move", ("_atomic_write_bytes", "_atomic_write_text", "replace_selected_in_place", "repack_selected_in_place", "remove_file_in_place", "remove_tree", "remove_tree_in_place", "rename_file_in_place", "move_entry_in_place")),
    Capability("Desktop metadata editor dispatch", "implemented", "GUI inspection, separate-output editing, authenticated resource export, profile asset inspection and validated tile/achievement-image replacement, profile-wide linked achievement-image replacement, managed feature/property/I/O evidence, detached development signing, post-mutation CON signing, LIVE/PIRS signing and signature verification, and historical Account actions", ("open_editor_artifact", "edit_editor_artifact", "extract_managed_resources", "show_profile_assets", "replace_profile_tile", "replace_achievement_image", "replace_profile_achievement_image", "show_managed_feature_surface", "show_managed_property_contracts", "show_managed_io_contracts", "sign_loaded_bytes", "sign_con_package", "sign_written_package", "sign_con_package_with_key_vault", "sign_written_package_with_key_vault", "verify_con_signature", "verify_remote_signature", "sign_remote_package_with_key_vault", "inspect_historical_account", "edit_historical_account")),
    Capability("XDBF/GPD/FIT inspection", "implemented", "observed XDBF entries across GPD and profile FIT payloads, payload digests, namespace-5 strings, achievement payloads, and profile aggregates", ("parse_xdbf", "xdbf_payload_surface", "list_embedded_xdbf", "list_embedded_achievements", "summarize_profile_achievements", "--editor-inspect")),
    Capability("XDBF/GPD mutation", "implemented", "bounded XDBF repacking, observed achievement edits and linked PNG replacement, profile-wide linked PNG replacement, raw achievement-flag masks, and exact profile-wide namespace-5 text replacement", ("repack_xdbf_entries", "mutate_xdbf_text", "mutate_xdbf_achievement", "mutate_xdbf_achievement_image", "mutate_profile_achievement_images", "mutate_xdbf_achievement_flags", "mutate_profile_achievement_flags", "mutate_profile_xdbf_text", "--achievement-image", "--profile-achievement-image", "--achievement-flags-or", "--achievement-flags-and-not", "--profile-achievement-flags-or", "--profile-achievement-flags-and-not", "--profile-xdbf-text")),
    Capability("Managed surface editor dispatch", "implemented", "Read-only editor-registry dispatch for exported REA managed-members evidence", ("ManagedSurfaceEditor", "EditorRegistry")),
    Capability("Opaque Account editor dispatch", "implemented", "Deterministic Account payload inspection and same-size replacement without schema inference", ("AccountEditor", "EditorRegistry")),
    Capability("ProfileData contract", "metadata-only", "REA observed six-field Horizon.ProfileData surface; Account serialization unresolved", ("ProfileData",)),
    Capability("ProfileData metadata editor dispatch", "metadata-only", "Typed editor for the authenticated six-field ProfileData envelope; Account serialization remains unresolved", ("ProfileDataEditor", "--editor-edit-values")),
    Capability("Account serialization", "unresolved", "supplied Account payload is opaque; REA exposed no managed Account type, serializer, field offsets, or Account-specific call edge", ("mutate_stfs_entry_same_size",)),
    Capability("Historical Account body codec", "historical-reference", "Unlicense historical XProfile reference matches the supplied 404-byte Account boundary; this does not replace REA evidence for Horizon's serializer or prove console validity", ("AccountRecord", "unobfuscate_account", "obfuscate_account", "historical_account_report", "mutate_historical_account", "--historical-account-inspect", "--historical-account-edit")),
    Capability("Account crypto provider bridge", "provider-boundary", "Connects opaque Account payloads to authenticated class3 signatures and caller-owned nonpersistent key providers, including historical-reference inspect/edit and explicit CLI decrypt/encrypt through an x86 bridge, while preserving caller-resolved output lengths", ("AccountCodec", "AccountKeyProvider", "CommandAccountKeyProvider", "historical_account_report_with_key_provider", "mutate_historical_account_with_key_provider", "decrypt_account_entry", "encrypt_account_payload", "decrypt_with_key_provider", "encrypt_with_key_provider", "encrypt_raw", "NativeSaveBinding", "PowerShellNativeSaveProvider", "--historical-account-key-helper")),
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
    Capability("Managed feature-surface inventory", "observed-only", "Classifies literal profile, achievement, storage, serialization, UI, and security terms in authenticated managed names to prioritize clean-room reconstruction without claiming runtime reachability", ("managed_feature_surface_report", "--managed-feature-surface")),
    Capability("Managed accessor-contract inventory", "observed-only", "Joins authenticated get_/set_ method pairs into derived read/write contracts while preserving method-body evidence and refusing offset or serializer inference", ("managed_property_contract_report", "--managed-property-contract")),
    Capability("Named title namespace inventory", "observed-only", "Separates stable non-obfuscated managed namespaces for follow-on title-editor reconstruction", ("managed_named_namespace_report", "--managed-named-namespaces")),
    Capability("REA reconstruction ledger", "observed-only", "Preserves exact evidence identities, observed managed/native boundaries, and explicit unresolved parity questions", ("rea_feature_ledger", "--rea-feature-ledger")),
    Capability("Guarded managed-method inventory", "observed-only", "Reports authenticated methods with throw/no-return opcode evidence without executing or bypassing them", ("managed_guarded_methods_report", "--managed-guarded-methods")),
    Capability("Managed body-fidelity audit", "observed-only", "Measures duplicate retained method-body hashes and offsets so guard stubs are not mistaken for serializer implementations", ("managed_body_fidelity_report", "--managed-body-fidelity")),
    Capability("Joined managed editor schemas", "observed-only", "Joins every observed type with its fields and methods without inferring save offsets", ("managed_schema_report", "--managed-schema")),
    Capability("Managed field-access evidence", "observed-only", "Exports REA field-access anchors for matched managed editor types without inferring binary offsets", ("--schema-field-accesses",)),
    Capability("Managed I/O contract evidence", "observed-only", "Projects authenticated Read/Write/Load/Save CIL signatures, role counts, anchors, field accesses, call targets, and title-family counts without inferring save layouts", ("managed_io_contract_report", "--managed-io-contract")),
    Capability("Managed schema registry dispatch", "observed-only", "Routes explicit .managed-schema.json evidence through the clean-room editor registry", ("ManagedSchemaEditor", "EditorRegistry")),
    Capability("Anti-analysis evidence report", "observed-only", "Reports REA-observed managed anti-analysis markers in CLI and desktop workflows without executing or bypassing the target", ("anti_analysis_report", "--anti-analysis", "show_anti_analysis")),
    Capability("Embedded UI/resource surface", "observed-only", "REA observed 205 embedded managed resource payloads; uniquely hash-verified extraction, conservative magic classification, and safe image dimensions are available, while feature ownership, rendering behavior, and signed-resource semantics remain unresolved", ("observed_resource_surface", "resource_surface_report", "verify_managed_resource_payloads", "extract_managed_resource_payloads", "classify_resource_payload", "resource_payload_metadata", "--resource-surface", "--resource-bundle", "--verify-resources", "--extract-resources")),
    Capability(".NET resource index inspection", "implemented", "Parses standard .resources name/type indexes and authenticated byte spans without deserializing values", ("parse_dotnet_resources", "--dotnet-resource-index")),
    Capability("Native save/runtime boundaries", "provider-boundary", "REA observed class3 save crypto, LZO, device I/O, and DNG/HVM imports; artifact-hash-bound export contracts now include deterministic PE ordinal/RVA/file-offset metadata, explicit x86 adapters require caller-supplied providers and keys, and the supplied Horizon.dll has controlled CheckRuntime/RunHVM/GetUserString probe observations", ("native_surface_report", "native_export_contract_report", "native_installation_report", "pe_export_table", "--native-installation", "NativeSaveBinding", "CtypesNativeSaveProvider", "PowerShellNativeSaveProvider", "LzoBinding", "NativeRuntimeBinding")),
    Capability("Complete managed P/Invoke inventory", "observed-only", "Reports all 54 REA-authenticated managed native declarations without executing them", ("managed_native_import_report", "--native-import-bundle")),
    Capability("LZO codec provider bridge", "provider-boundary", "Validated high-level wrapper plus explicit x86 path-bound adapters over the four observed LZO imports, including a verified lzo2a round trip with 256 KiB work memory", ("LzoCodec", "LzoBinding", "CtypesLzoProvider", "PowerShellLzoProvider")),
    Capability("LZO operation surface", "provider-boundary", "Exposes explicit REA-observed LZO version, compression, and decompression operations with caller-selected x86 providers in CLI and desktop workflows", ("native_lzo_operation_report", "--lzo-operation", "lzo_operation")),
    Capability("Device exploration surface", "provider-boundary", "REA observed device properties plus CreateFile/DeviceIoControl declarations; explicit caller-selected read-only or read/write Windows handles and raw IOCTL forwarding are available through the library, CLI, and desktop action, while FATX command semantics remain unresolved", ("device_surface_report", "DeviceBinding", "DeviceIoBinding", "WindowsDeviceIoProvider", "device_ioctl_report", "--device-ioctl", "--device-ioctl-write-access")),
    Capability("Host volume inventory", "implemented", "Read-only Windows logical-volume identity, capacity, and bounded directory listing in CLI and desktop workflows", ("device_inventory_report", "enumerate_host_device_entries", "--device-inventory", "--device-list", "show_device_inventory")),
    Capability("DNG/HVM runtime adapter", "provider-boundary", "REA recovered x86 and x64 CheckRuntime/GetUserString declarations plus RunHVM; supplied x86 Horizon.dll probes returned CheckRuntime=true, RunHVM=0, and stable zero/nonzero behavior for bounded GetUserString selector probes through the explicit PowerShell bridge, while native argument semantics remain unresolved", ("NativeRuntimeBinding", "PowerShellNativeRuntimeProvider", "native_runtime_operation_report", "--native-runtime-operation", "check_runtime", "run_hvm", "get_user_string", "check_runtime64", "get_user_string64")),
    Capability("Console and remote package signing", "provider-boundary", "Observed CON XeCrypt signing plus caller-key LIVE/PIRS verification and provider-backed development signing are available; authorized key ownership and retail console policy remain unresolved", ("sign_stfs_console_package", "sign_stfs_console_package_with_provider", "sign_stfs_remote_package_with_provider", "verify_stfs_console_signature", "verify_stfs_remote_signature", "sign_with_provider", "sign_detached_signature", "verify_detached_signature", "verify_embedded_signature_region", "verify_xecrypt_sha1_pkcs1v15", "--sign-stfs-package", "--sign-stfs-remote-package", "--sign-written-package", "--sign-detached-signature", "--sign-written-output", "--verify-embedded-signature", "--verify-stfs-signature", "--verify-stfs-remote-signature")),
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

