import hashlib
import json
import dataclasses
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock
from pathlib import Path

from work.horizon_clone import (
    inspect,
    _json_report,
    list_stfs_entries,
    list_embedded_xdbf,
    summarize_embedded_xdbf,
    list_embedded_achievements,
    list_embedded_achievement_image_links,
    extract_embedded_achievement_images,
    summarize_profile_achievements,
    rename_stfs_entry,
    add_stfs_directory,
    move_stfs_entry,
    mutate_stfs_entry_same_size,
    mutate_stfs_metadata,
    mutate_profile_assets,
    profile_asset_report,
    mutate_stfs_thumbnails,
    mutate_xdbf_achievement,
    mutate_xdbf_achievement_flags,
    mutate_profile_achievement_flags,
    mutate_profile_achievement_images,
    mutate_profile_xdbf_text,
    mutate_xdbf_text,
    repack_xdbf_entries,
    repack_stfs_entries,
    rehash_stfs_hashes,
    mutate_xdbf_entry_same_size,
    _atomic_replace_bytes,
    validate_stfs_mutation,
    profile_data_report,
    editor_inspect_report,
    editor_edit_values,
    verify_detached_signature,
    verify_embedded_signature_region,
    read_public_key_json,
    block_offset,
    parse_stfs_header,
    parse_stfs_security_metadata,
    extract_stfs_public_key,
    stfs_signature_region_report,
    stfs_signature_mutation_report,
    verify_stfs_console_signature,
    stfs_console_validation_report,
    verify_stfs_remote_signature,
    sign_stfs_remote_package_with_provider,
    sign_stfs_console_package,
    sign_stfs_console_package_with_provider,
    stfs_content_type_name,
    stfs_magic_filename,
    stfs_fatx_device_path,
    device_ioctl_report,
    read_private_key_json,
    sign_detached_signature,
    sign_detached_bytes,
    parse_stfs_thumbnails,
    parse_xdbf,
    filetime_to_utc,
    utc_to_filetime,
    xdbf_payload_surface,
    xdbf_achievement_image_links,
    xdbf_achievement_image_payload,
    mutate_xdbf_achievement_image,
    mutate_profile_achievement_images,
    historical_account_report,
    historical_account_report_with_key_provider,
    mutate_historical_account,
    mutate_historical_account_with_key_provider,
    read_stfs_entry,
    verify_stfs_hashes,
    native_runtime_operation_report,
    native_lzo_operation_report,
)
from work.signing import (
    CommandSha1SigningProvider,
    DetachedSignature,
    RsaPrivateKey,
    LocalRsaSha1Signer,
    RsaPublicKey,
    SignedRegion,
    sign_region,
    sign_with_provider,
    verify_region,
    verify_sha1_pkcs1v15,
    verify_sha256_pkcs1v15,
    verify_xecrypt_sha1_pkcs1v15,
)
from work.profile_model import ProfileData
from work.editors import AccountEditor, ConstantCatalogEditor, EditorContext, EditorRegistry, HaloMetadataEditor, LegacyCatalogEditor, ManagedSchemaEditor, ManagedSurfaceEditor, ProfileDataEditor, XdbfEditor, default_registry
from work.skyrim_catalog import enum_member_names, enum_member_values, observed_skyrim_enum_summary, observed_skyrim_enums, resolve_skyrim_enum_member, validate_skyrim_enum_values
from work.horizon_catalog import catalog_member_names, observed_catalogs
from work.gears_catalog import gears_entry_id_summary, gears_entry_id_values, gears_of_war_3_entry_ids, resolve_gears_entry_id, validate_gears_entry_ids
from work.halo_catalog import halo_general_class_field_counts, halo_general_class_field_types, halo_general_class_method_summary, halo_general_class_property_names, halo_general_class_types, validate_halo_metadata_values
from work.resource_inventory import classify_resource_payload, extract_managed_resource_payloads, observed_resource_surface, parse_dotnet_resources, resource_payload_metadata, resource_surface_report, verify_managed_resource_payloads
from work.observed_members import observed_fields, observed_profile_data_fields, observed_profile_data_methods
from work.editor_inventory import capability_report, catalog_report, inventory_summary, observed_editor_inventory, rea_feature_ledger
from work.anti_analysis import anti_analysis_report, native_anti_analysis_report
from work.legacy_catalog import legacy_catalog_report, legacy_field_names, observed_legacy_catalogs
from work.global_catalog import global_catalog_report, observed_global_types
from work.native_surface import managed_native_import_report, native_export_contract_report, native_import_table_report, native_installation_report, native_surface_report, observed_native_imports, observed_native_callers
from work.device_surface import device_surface_report, observed_device_members
from work.device_binding import DeviceBinding, DeviceIoBinding, DeviceProviderUnavailable, WindowsDeviceIoProvider
from work.device_inventory import device_inventory_report, enumerate_host_device_entries
from work.native_runtime import NativeRuntimeBinding, NativeRuntimeUnavailable, PowerShellNativeRuntimeProvider
from work.native_save import CtypesNativeSaveProvider, NativeSaveBinding, NativeSaveUnavailable, PowerShellNativeSaveProvider, UInt32Ref
from work.account_codec import AccountCodec, AccountKeyProviderUnavailable, CommandAccountKeyProvider
from work.account_format import (
    AccountRecord,
    obfuscate_account,
    unobfuscate_account,
)
from work.native_compression import CtypesLzoProvider, Int32Ref, LzoBinding, LzoUnavailable, PowerShellLzoProvider
from work.native_loader import compatible_pe_architecture, pe_export_names, pe_export_table, pe_import_table
from work.lzo_codec import LzoCodec
from work.horizon_app import HorizonApp, _atomic_write_bytes, _atomic_write_text
from work.managed_surface import managed_artifact_report, managed_body_fidelity_report, managed_editor_family_report, managed_feature_surface_report, managed_guarded_methods_report, managed_io_contract_report, managed_named_namespace_report, managed_property_contract_report, managed_reference_report, managed_schema_report, managed_surface_report


def supplied_fixture():
    value = os.environ.get("HORIZON_PROFILE_FIXTURE")
    return Path(value) if value else None


def historical_account_key(test_case):
    value = os.environ.get("HORIZON_HISTORICAL_ACCOUNT_KEY_HEX")
    if not value:
        test_case.skipTest("historical Account key is not supplied")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        test_case.fail(f"HORIZON_HISTORICAL_ACCOUNT_KEY_HEX is not hexadecimal: {exc}")


class ContainerInspectionTests(unittest.TestCase):
    def test_historical_account_codec_round_trips_supplied_account(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "Account")
        encrypted = read_stfs_entry(original, entry, header)
        production_key = historical_account_key(self)
        plain = unobfuscate_account(encrypted, production_key)
        record = AccountRecord.from_bytes(plain)

        self.assertEqual(len(encrypted), 404)
        self.assertEqual(len(plain), 380)
        self.assertEqual(record.reserved, 0x20000001)
        self.assertEqual(record.live_flags, 0)
        self.assertTrue(record.xbox_live_enabled)
        self.assertFalse(record.recovering)
        self.assertFalse(record.password_protected)
        self.assertEqual(record.membership_type, 6)
        self.assertEqual(record.membership_name, "gold")
        self.assertEqual(record.online_country_code, 0x67)
        self.assertEqual(record.online_country_name, "US")
        self.assertEqual(record.online_language_code, 1)
        self.assertEqual(record.online_language_name, "en")
        self.assertEqual(record.to_bytes(), plain)
        self.assertEqual(
            unobfuscate_account(
                obfuscate_account(plain, production_key, confounder=b"\x00" * 8),
                production_key,
            ),
            plain,
        )

        tampered = bytearray(encrypted)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            unobfuscate_account(bytes(tampered), production_key)

    def test_historical_account_report_exposes_authenticated_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        report = historical_account_report(path, historical_account_key(self))
        self.assertEqual(report["operation"], "historical-account-inspect")
        self.assertEqual(report["encrypted_bytes"], 404)
        self.assertEqual(report["plaintext_bytes"], 380)
        self.assertEqual(report["record"]["gamertag"], "Trap Em All")
        self.assertEqual(report["record"]["membership_type"], 6)
        self.assertEqual(report["record"]["membership_name"], "gold")
        self.assertEqual(report["record"]["online_country_code"], 0x67)
        self.assertEqual(report["record"]["online_country_name"], "US")
        self.assertEqual(len(report["record"]["online_key_hex"]), 32)

    def test_historical_account_provider_path_uses_caller_owned_key(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        key = historical_account_key(self)

        class Provider:
            def __init__(self):
                self.operations = []

            def get_account_key(self, operation, payload_sha256):
                self.operations.append((operation, payload_sha256))
                return key

        provider = Provider()
        report = historical_account_report_with_key_provider(path, provider)
        self.assertEqual(report["record"]["gamertag"], "Trap Em All")
        self.assertEqual(provider.operations[0][0], "decrypt")
        edited = mutate_historical_account_with_key_provider(path.read_bytes(), provider, {"gamertag": "Vault User"})
        self.assertEqual(verify_stfs_hashes(edited, header=parse_stfs_header(edited))["failures"], [])
        self.assertEqual([operation for operation, _digest in provider.operations[-2:]], ["decrypt", "encrypt"])
        self.assertNotEqual(provider.operations[-2][1], provider.operations[-1][1])

    def test_historical_account_mutation_rehashes_container(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        key = historical_account_key(self)
        edited = mutate_historical_account(original, key, {"gamertag": "Clone Test"})
        edited_header = parse_stfs_header(edited)
        report = historical_account_report(path, key)
        self.assertEqual(verify_stfs_hashes(edited, header=edited_header)["failures"], [])
        entry = next(item for item in list_stfs_entries(edited, edited_header) if item.path == "Account")
        plaintext = unobfuscate_account(read_stfs_entry(edited, entry, edited_header), key)
        self.assertEqual(AccountRecord.from_bytes(plaintext).gamertag, "Clone Test")
        self.assertEqual(report["encrypted_bytes"], entry.size)

    def test_historical_account_mutates_derived_flag_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        key = historical_account_key(self)
        edited = mutate_historical_account(
            path.read_bytes(),
            key,
            {"membership_type": 3, "online_country_code": 0x10, "xbox_live_enabled": False},
        )
        header = parse_stfs_header(edited)
        entry = next(item for item in list_stfs_entries(edited, header) if item.path == "Account")
        record = AccountRecord.from_bytes(unobfuscate_account(read_stfs_entry(edited, entry, header), key))
        self.assertEqual(record.membership_type, 3)
        self.assertEqual(record.online_country_code, 0x10)
        self.assertFalse(record.xbox_live_enabled)

    def test_historical_account_mutates_named_flag_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        key = historical_account_key(self)
        edited = mutate_historical_account(
            path.read_bytes(),
            key,
            {"membership_name": "silver", "online_country_name": "CA", "online_language_name": "fr"},
        )
        header = parse_stfs_header(edited)
        entry = next(item for item in list_stfs_entries(edited, header) if item.path == "Account")
        record = AccountRecord.from_bytes(unobfuscate_account(read_stfs_entry(edited, entry, header), key))
        self.assertEqual(record.membership_name, "silver")
        self.assertEqual(record.online_country_name, "CA")
        self.assertEqual(record.online_language_name, "fr")

    fixture_dir = Path(__file__).parent / ".tmp"

    def test_desktop_atomic_writes_replace_and_clean_temporary_files(self):
        self.fixture_dir.mkdir(exist_ok=True)
        binary = self.fixture_dir / "atomic.bin"
        text = self.fixture_dir / "atomic.json"
        try:
            _atomic_write_bytes(binary, b"new-bytes")
            _atomic_write_text(text, "{\"ok\": true}\n")
            self.assertEqual(binary.read_bytes(), b"new-bytes")
            self.assertEqual(text.read_text(encoding="utf-8"), "{\"ok\": true}\n")
            self.assertFalse((self.fixture_dir / "atomic.bin.horizon-tmp").exists())
            self.assertFalse((self.fixture_dir / "atomic.json.horizon-tmp").exists())
        finally:
            binary.unlink(missing_ok=True)
            text.unlink(missing_ok=True)

    def test_cli_atomic_replace_cleans_temporary_file(self):
        self.fixture_dir.mkdir(exist_ok=True)
        target = self.fixture_dir / "cli-atomic.bin"
        try:
            _atomic_replace_bytes(target, b"atomic")
            self.assertEqual(target.read_bytes(), b"atomic")
            self.assertFalse(Path(str(target) + ".horizon-tmp").exists())
        finally:
            target.unlink(missing_ok=True)

    def test_stfs_mutation_integrity_is_verified_before_cli_write(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        self.assertEqual(verify_stfs_hashes(original, header=parse_stfs_header(original))["failures"], [])
        validate_stfs_mutation(original)
        corrupted = bytearray(original)
        account = list_stfs_entries(original, parse_stfs_header(original))[0]
        data_offset = block_offset(account.first_block, parse_stfs_header(original).header_size, parse_stfs_header(original).block_separation)
        corrupted[data_offset] ^= 0x01
        with self.assertRaises(ValueError):
            validate_stfs_mutation(bytes(corrupted))

    def test_desktop_exposes_bulk_gpd_summary_export(self):
        self.assertTrue(hasattr(HorizonApp, "export_gpd_summary"))
        self.assertTrue(hasattr(HorizonApp, "export_profile_summary"))
        self.assertTrue(hasattr(HorizonApp, "export_title_catalog"))
        self.assertTrue(hasattr(HorizonApp, "extract_managed_resources"))
        self.assertTrue(hasattr(HorizonApp, "sign_loaded_bytes"))
        self.assertTrue(hasattr(HorizonApp, "sign_con_package"))
        self.assertTrue(hasattr(HorizonApp, "sign_con_package_with_key_vault"))
        self.assertTrue(hasattr(HorizonApp, "sign_written_package"))
        self.assertTrue(hasattr(HorizonApp, "sign_written_package_with_key_vault"))
        self.assertTrue(hasattr(HorizonApp, "verify_con_signature"))
        self.assertTrue(hasattr(HorizonApp, "verify_remote_signature"))
        self.assertTrue(hasattr(HorizonApp, "sign_remote_package_with_key_vault"))
        self.assertTrue(hasattr(HorizonApp, "show_anti_analysis"))
        self.assertTrue(hasattr(HorizonApp, "show_native_anti_analysis"))
        self.assertTrue(hasattr(HorizonApp, "show_profile_assets"))
        self.assertTrue(hasattr(HorizonApp, "replace_profile_tile"))
        self.assertTrue(hasattr(HorizonApp, "show_managed_feature_surface"))
        self.assertTrue(hasattr(HorizonApp, "show_managed_property_contracts"))
        self.assertTrue(hasattr(HorizonApp, "show_managed_io_contracts"))
        self.assertTrue(hasattr(HorizonApp, "show_device_inventory"))
        self.assertTrue(hasattr(HorizonApp, "show_device_directory"))
        self.assertTrue(hasattr(HorizonApp, "device_ioctl"))
        self.assertTrue(hasattr(HorizonApp, "runtime_export"))
        self.assertTrue(hasattr(HorizonApp, "lzo_operation"))
        self.assertTrue(hasattr(HorizonApp, "show_native_installation"))
        self.assertTrue(hasattr(HorizonApp, "replace_selected_in_place"))
        self.assertTrue(hasattr(HorizonApp, "repack_selected_in_place"))
        self.assertTrue(hasattr(HorizonApp, "remove_file_in_place"))
        self.assertTrue(hasattr(HorizonApp, "remove_tree"))
        self.assertTrue(hasattr(HorizonApp, "remove_tree_in_place"))
        self.assertTrue(hasattr(HorizonApp, "rename_file_in_place"))
        self.assertTrue(hasattr(HorizonApp, "move_entry_in_place"))
        self.assertTrue(hasattr(HorizonApp, "decrypt_account"))
        self.assertTrue(hasattr(HorizonApp, "encrypt_account"))
        self.assertTrue(hasattr(HorizonApp, "inspect_historical_account"))
        self.assertTrue(hasattr(HorizonApp, "edit_historical_account"))
        self.assertTrue(hasattr(HorizonApp, "export_xdbf_surface"))
        self.assertTrue(hasattr(HorizonApp, "export_achievement_image"))
        self.assertTrue(hasattr(HorizonApp, "replace_achievement_image"))
        self.assertTrue(hasattr(HorizonApp, "replace_profile_achievement_image"))
        self.assertTrue(hasattr(HorizonApp, "export_achievement_links"))
        self.assertTrue(hasattr(HorizonApp, "extract_achievement_images"))
        self.assertTrue(hasattr(HorizonApp, "show_selected"))

    def test_rea_feature_ledger_preserves_observed_boundaries(self):
        ledger = rea_feature_ledger()
        self.assertEqual(ledger["observed"]["managed_types"], 7693)
        self.assertEqual(len(ledger["observed"]["profile_data_fields"]), 6)
        self.assertIn("Account type and Horizon Account serializer", " ".join(ledger["unresolved"]))

    def test_device_inventory_is_read_only_and_explicitly_bounded(self):
        report = device_inventory_report()
        self.assertIn(report["status"], {"host-visible-read-only", "unsupported-host"})
        self.assertEqual(len(report["volumes"]), len({item["root"] for item in report["volumes"]}))
        self.assertTrue(any("FATX" in item for item in report["limitations"]))

    def test_host_device_listing_is_bounded_and_read_only(self):
        root = self.fixture_dir.resolve()
        entries = enumerate_host_device_entries(root)
        self.assertEqual(tuple(item.name for item in entries), tuple(sorted((item.name for item in root.iterdir()), key=str.casefold)))
        self.assertTrue(all(not item.relative_path.startswith("../") for item in entries))
        with self.assertRaises(ValueError):
            enumerate_host_device_entries(root, "..")

    def test_device_ioctl_report_closes_explicit_provider_session(self):
        class FakeProvider:
            def __init__(self):
                self.calls = []

            def open_read_only(self, device_path):
                self.calls.append(("open", device_path))
                return 41

            def device_io_control(self, handle, control_code, input_data, output_capacity):
                self.calls.append(("ioctl", handle, control_code, input_data, output_capacity))
                return b"\x10\x20"

            def close(self, handle):
                self.calls.append(("close", handle))

        provider = FakeProvider()
        report = device_ioctl_report("\\\\.\\PhysicalDrive-test", 0x70000, b"\x01\x02", 16, provider=provider)
        self.assertEqual(report["output_hex"], "1020")
        self.assertEqual(report["status"], "provider-bound-read-only-handle")
        self.assertEqual(provider.calls, [
            ("open", "\\\\.\\PhysicalDrive-test"),
            ("ioctl", 41, 0x70000, b"\x01\x02", 16),
            ("close", 41),
        ])

    def test_device_ioctl_report_explicitly_selects_read_write_handle(self):
        class FakeProvider:
            def __init__(self):
                self.calls = []

            def open_read_only(self, device_path):
                self.calls.append(("read-only", device_path))
                return 40

            def open_read_write(self, device_path):
                self.calls.append(("read-write", device_path))
                return 42

            def device_io_control(self, handle, control_code, input_data, output_capacity):
                self.calls.append(("ioctl", handle, control_code, input_data, output_capacity))
                return b"ok"

            def close(self, handle):
                self.calls.append(("close", handle))

        provider = FakeProvider()
        report = device_ioctl_report(
            "\\\\.\\PhysicalDrive-test", 0x70001, b"write", 2,
            provider=provider, write_access=True,
        )
        self.assertEqual(report["status"], "provider-bound-read-write-handle")
        self.assertEqual(provider.calls, [
            ("read-write", "\\\\.\\PhysicalDrive-test"),
            ("ioctl", 42, 0x70001, b"write", 2),
            ("close", 42),
        ])
        with self.assertRaises(TypeError):
            device_ioctl_report("device", 1, write_access=1, provider=provider)

    def test_reports_selected_managed_surface_from_exported_evidence(self):
        bundle = self.fixture_dir / "managed-surface.json"
        bundle.parent.mkdir(exist_ok=True)
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_test",
                "normalized_result": {
                    "artifact": {"sha256": "abc", "path": "Horizon.exe"},
                    "identity_scope": {"requires_artifact_sha256": "abc"},
                    "types": [{"full_name": "Horizon.PackageEditors.Skyrim.Save", "field_list": {"count": 2}, "method_list": {"count": 3}}],
                    "fields": [{"declaring_type": "Horizon.PackageEditors.Skyrim.Save", "name": "Gold", "token": "0x04000001", "signature": {"field_type": "System.Int32"}}],
                    "methods": [{"declaring_type": "Horizon.PackageEditors.Skyrim.Save", "name": "Save", "token": "0x06000001", "signature": {"return_type": "System.Void"}}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_surface_report(bundle, r"Skyrim|Gold")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"], {"types": 1, "fields": 1, "methods": 1})
        self.assertEqual(report["methods"][0]["name"], "Save")

    def test_reports_declared_managed_assembly_references(self):
        bundle = self.fixture_dir / "managed-artifact.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_artifact",
                "evidence_id": "ev_artifact",
                "normalized_result": {
                    "artifact": {"sha256": "abc", "path": "Horizon.exe"},
                    "assembly": {"name": "Horizon", "version": "2.9.0.0"},
                    "references": [
                        {"name": "System", "version": "2.0.0.0", "public_key_or_token": {"token": "b77a"}, "token": "0x23000001"},
                        {"name": "System.Data.SQLite", "version": "1.0.65.0", "public_key_or_token": {"token": "db93"}, "token": "0x23000002"},
                    ],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_reference_report(bundle, "SQLite")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"], {"matched": 1, "total": 2})
        self.assertEqual(report["references"][0]["name"], "System.Data.SQLite")

    def test_reports_managed_artifact_identity_and_partial_coverage(self):
        bundle = self.fixture_dir / "managed-artifact-provenance.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_artifact",
                "evidence_id": "ev_artifact_provenance",
                "normalized_result": {
                    "artifact": {"sha256": "abc", "path": "Horizon.exe"},
                    "pe": {"architecture": "x86"},
                    "classification": {"status": "managed", "implementation": "cil"},
                    "assembly": {"name": "Horizon", "version": "2.9.0.0"},
                    "metadata": {"status": "partial", "version": "v2.0.50727", "stream_names": ["#~"], "table_row_counts": {"TypeDef": 1}},
                    "coverage": {"state": "partial", "issues": [{"code": "invalid-row"}]},
                    "references": [{"name": "System"}],
                    "resources": [{"name": "ui.resources"}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_artifact_report(bundle)
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["assembly"]["version"], "2.9.0.0")
        self.assertEqual(report["metadata"]["status"], "partial")
        self.assertEqual(report["counts"], {"references": 1, "resources": 1})

    def test_joins_managed_editor_schema_by_type(self):
        bundle = self.fixture_dir / "schema-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_schema",
                "normalized_result": {
                    "types": [{"full_name": "Demo.Editor", "token": "0x02000001"}],
                    "fields": [{"declaring_type": "Demo.Editor", "name": "Value", "token": "0x04000001", "signature": {"field_type": "i4"}}],
                    "methods": [{"declaring_type": "Demo.Editor", "name": "Save", "token": "0x06000001", "signature": {"return_type": "void"}, "body": {"status": "present", "opcode_counts": {"ret": 1}}}],
                    "field_accesses": [{"method": "Save", "method_token": "0x06000001", "field_name": "Value", "field_token": "0x04000001", "opcode": "stfld"}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_schema_report(bundle, "Demo\\.Editor", include_bodies=True, method_pattern="Save", include_field_accesses=True)
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["matched_types"], 1)
        self.assertEqual(report["counts"]["matched_fields"], 1)
        self.assertEqual(report["types"][0]["methods"][0]["name"], "Save")
        self.assertEqual(report["types"][0]["methods"][0]["body"]["status"], "present")
        self.assertEqual(report["method_pattern"], "Save")
        self.assertEqual(report["field_accesses"][0]["opcode"], "stfld")

    def test_reports_managed_io_contract_anchors(self):
        bundle = self.fixture_dir / "io-contract-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_io",
                "normalized_result": {
                    "types": [{"full_name": "Demo.Editor"}],
                    "methods": [{"declaring_type": "Demo.Editor", "name": "Save", "token": "0x06000001", "signature": {"return_type": "void"}, "body": {"status": "present", "anchors": [{"opcode": "stfld"}]}}],
                    "field_accesses": [{"method_token": "0x06000001", "field_name": "Value", "field_token": "0x04000001", "opcode": "stfld"}],
                    "call_edges": [{"caller_token": "0x06000001", "opcode": "call", "target_kind": "method-def", "target_name": "Write", "target_token": "0x06000002"}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_io_contract_report(bundle, "Demo\\.Editor", "^Save$")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["matched_methods"], 1)
        self.assertEqual(report["role_counts"], {"save": 1})
        self.assertEqual(report["methods"][0]["role"], "save")
        self.assertEqual(report["methods"][0]["implementation_readiness"], "observed-body")
        self.assertEqual(report["implementation_readiness_counts"], {"observed-body": 1})
        self.assertEqual(report["title_implementation_readiness_counts"], {})
        self.assertEqual(report["title_serializer_status"], "body-unavailable")
        self.assertEqual(report["methods"][0]["field_accesses"][0]["field_name"], "Value")
        self.assertEqual(report["methods"][0]["call_targets"][0]["target_name"], "Write")
        self.assertEqual(report["family_counts"], [])

    def test_classifies_retained_throw_only_io_stubs(self):
        bundle = self.fixture_dir / "io-stub-contract-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_io_stub",
                "normalized_result": {
                    "types": [{"full_name": "Horizon.PackageEditors.Skyrim.Save"}],
                    "methods": [{
                        "declaring_type": "Horizon.PackageEditors.Skyrim.Save",
                        "name": "Write",
                        "token": "0x06000001",
                        "body": {"status": "present", "opcode_counts": {"ldstr": 1, "newobj": 1, "throw": 1}},
                    }],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_io_contract_report(bundle, "Skyrim", "^Write$")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["methods"][0]["implementation_readiness"], "throw-only-stub")
        self.assertEqual(report["implementation_readiness_counts"], {"throw-only-stub": 1})
        self.assertEqual(report["title_implementation_readiness_counts"], {"throw-only-stub": 1})
        self.assertEqual(report["title_serializer_status"], "throw-only-stub-only")

    def test_groups_title_editor_io_contracts_by_family(self):
        bundle = self.fixture_dir / "title-io-contract-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_title_io",
                "normalized_result": {
                    "types": [
                        {"full_name": "Horizon.PackageEditors.Skyrim.Save"},
                        {"full_name": "Horizon.PackageEditors.Skyrim.Inventory"},
                        {"full_name": "Horizon.PackageEditors.Halo__General_Classes_.Variant"},
                    ],
                    "methods": [
                        {"declaring_type": "Horizon.PackageEditors.Skyrim.Save", "name": "Save", "token": "0x06000001"},
                        {"declaring_type": "Horizon.PackageEditors.Halo__General_Classes_.Variant", "name": "Write", "token": "0x06000002"},
                    ],
                    "field_accesses": [],
                    "call_edges": [],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_io_contract_report(bundle, r"^Horizon\.PackageEditors\.(Skyrim|Halo__General_Classes_)")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(
            report["family_counts"],
            [
                {"family": "Horizon.PackageEditors.Halo__General_Classes_", "types": 1, "methods": 1, "implementation_readiness": {"body-unavailable": 1}, "serializer_status": "body-unavailable"},
                {"family": "Horizon.PackageEditors.Skyrim", "types": 2, "methods": 1, "implementation_readiness": {"body-unavailable": 1}, "serializer_status": "body-unavailable"},
            ],
        )
        self.assertEqual(report["role_counts"], {"save": 1, "write": 1})

    def test_groups_managed_types_into_observed_editor_families(self):
        bundle = self.fixture_dir / "family-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_family",
                "normalized_result": {
                    "types": [
                        {"full_name": "Horizon.PackageEditors.Skyrim.Save"},
                        {"full_name": "Horizon.PackageEditors.Skyrim.Inventory"},
                        {"full_name": "A.obfuscated"},
                    ],
                    "fields": [{"declaring_type": "Horizon.PackageEditors.Skyrim.Save"}],
                    "methods": [{"declaring_type": "Horizon.PackageEditors.Skyrim.Save"}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_editor_family_report(bundle, "Horizon\\.PackageEditors")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["matched_types"], 2)
        self.assertEqual(report["families"][0]["family"], "Horizon.PackageEditors.Skyrim")
        self.assertEqual(report["families"][0]["field_count"], 1)
        self.assertEqual(report["families"][0]["method_count"], 1)

    def test_summarizes_named_managed_namespaces(self):
        bundle = self.fixture_dir / "namespace-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_namespace",
                "normalized_result": {
                    "types": [{"full_name": "StateofDecay.Save"}, {"full_name": "A.obfuscated"}, {"full_name": "<Module>"}],
                    "fields": [{"declaring_type": "StateofDecay.Save"}],
                    "methods": [{"declaring_type": "StateofDecay.Save"}],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_named_namespace_report(bundle)
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["matched_types"], 1)
        self.assertEqual(report["namespaces"][0]["namespace"], "StateofDecay")
        self.assertEqual(report["namespaces"][0]["field_count"], 1)
        self.assertEqual(report["namespaces"][0]["method_count"], 1)

    def test_classifies_observed_managed_feature_surface_without_claiming_behavior(self):
        bundle = self.fixture_dir / "feature-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_feature",
                "normalized_result": {
                    "types": [
                        {"full_name": "Horizon.ProfileData"},
                        {"full_name": "Horizon.PackageEditors.Halo.AchievementEditor"},
                    ],
                    "methods": [
                        {"declaring_type": "Horizon.ProfileData", "name": "get_Gamertag"},
                        {"declaring_type": "Horizon.PackageEditors.Halo.AchievementEditor", "name": "Save"},
                    ],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_feature_surface_report(bundle)
        finally:
            bundle.unlink(missing_ok=True)
        features = {item["feature"]: item for item in report["features"]}
        self.assertEqual(report["counts"]["selected_types"], 2)
        self.assertIn("profile-and-social", features)
        self.assertIn("achievement-and-score", features)
        self.assertIn("save-and-serialization", features)
        self.assertIn("literal-name classifications", report["limitations"][0])

    def test_joins_managed_accessor_contracts_without_inventing_offsets(self):
        bundle = self.fixture_dir / "property-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_property",
                "normalized_result": {
                    "types": [{"full_name": "Demo.Editor"}],
                    "methods": [
                        {"declaring_type": "Demo.Editor", "name": "get_Value", "token": "0x06000001", "signature": {"return_type": "i4"}, "body": {"status": "present", "opcode_counts": {"ret": 1}}},
                        {"declaring_type": "Demo.Editor", "name": "set_Value", "token": "0x06000002", "signature": {"parameter_types": ["i4"]}, "body": {"status": "present", "opcode_counts": {"ret": 1}}},
                    ],
                    "call_edges": [],
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_property_contract_report(bundle, "Demo\\.Editor", "Value", include_bodies=True)
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["property_contracts"], 1)
        self.assertEqual(report["properties"][0]["access"], "read-write")
        self.assertEqual(report["properties"][0]["get"]["body"]["status"], "present")
        self.assertIn("backing fields", report["limitations"][1])

    def test_reports_throw_observed_managed_methods(self):
        bundle = self.fixture_dir / "guarded-bundle.json"
        bundle.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_members",
                "evidence_id": "ev_guarded",
                "normalized_result": {
                    "methods": [
                        {"declaring_type": "Demo.Reader", "name": "Read", "token": "0x06000001", "signature": {}, "body": {"status": "present", "instruction_count": 3, "opcode_counts": {"ldstr": 1, "newobj": 1, "throw": 1}, "il_sha256": "abc"}},
                        {"declaring_type": "Demo.Reader", "name": "Write", "token": "0x06000002", "signature": {}, "body": {"status": "present", "instruction_count": 1, "opcode_counts": {"ret": 1}}},
                    ]
                },
            }]
        }), encoding="utf-8")
        try:
            report = managed_guarded_methods_report(bundle, "Demo\\.Reader")
        finally:
            bundle.unlink(missing_ok=True)
        self.assertEqual(report["counts"]["guarded_methods"], 1)
        self.assertEqual(report["methods"][0]["status"], "throw-observed-no-return")

    def test_recognizes_con_and_extracts_utf16(self):
        payload = b"CON " + b"\x00" * 12 + "Achievement One".encode("utf-16-le") + b"\x00\x00"
        self.fixture_dir.mkdir(exist_ok=True)
        path = self.fixture_dir / "sample-con"
        path.write_bytes(payload)
        try:
            report = inspect(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertTrue(report.is_container)
        self.assertEqual(report.package_kind, "Xbox 360 content container")
        self.assertEqual(report.sha256, hashlib.sha256(payload).hexdigest())
        self.assertIn("Achievement One", {item.value for item in report.utf16_strings})

    def test_parses_every_gpd_in_supplied_profile_fixture(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        gpd_entries = [
            entry for entry in list_stfs_entries(data, header)
            if not entry.is_directory and entry.name.casefold().endswith(".gpd")
        ]
        self.assertEqual(len(gpd_entries), 67)
        for entry in gpd_entries:
            self.assertTrue(parse_xdbf(read_stfs_entry(data, entry, header)))

    def test_exercises_same_size_xdbf_mutation_for_every_fixture_gpd(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        gpd_entries = [
            entry for entry in list_stfs_entries(data, header)
            if not entry.is_directory and entry.name.casefold().endswith(".gpd")
        ]
        for entry in gpd_entries:
            gpd = read_stfs_entry(data, entry, header)
            xdbf_entries = parse_xdbf(gpd)
            candidate = next((item for item in xdbf_entries if item.length), None)
            self.assertIsNotNone(candidate, entry.name)
            replacement = b"\x00" * candidate.length
            mutated = mutate_xdbf_entry_same_size(gpd, candidate, replacement)
            self.assertEqual(len(mutated), len(gpd))
            self.assertEqual(len(parse_xdbf(mutated)), len(xdbf_entries))

    def test_exercises_same_size_xdbf_mutation_for_profile_fit(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        fit = next(entry for entry in list_stfs_entries(data, header) if entry.name == "FFFE07D1.fit")
        payload = read_stfs_entry(data, fit, header)
        entries = parse_xdbf(payload)
        replacement = bytes(value ^ 0x5A for value in payload)
        mutated = mutate_xdbf_entry_same_size(payload, entries[0], replacement[entries[0].data_offset:entries[0].data_offset + entries[0].length])
        self.assertEqual(len(mutated), len(payload))
        self.assertEqual(len(parse_xdbf(mutated)), len(entries))

    def test_rehashes_full_stfs_after_same_size_account_replacement(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        account = next(entry for entry in list_stfs_entries(data, header) if entry.name.casefold() == "account")
        replacement = bytes(value ^ 0xA5 for value in read_stfs_entry(data, account, header))
        mutated = mutate_stfs_entry_same_size(data, account, replacement, header)
        self.assertEqual(read_stfs_entry(mutated, account, header), replacement)
        verification = verify_stfs_hashes(mutated, header=header)
        self.assertEqual(verification["failures"], [])
        self.assertEqual(verification["hash_table_failures"], [])
        self.assertTrue(verification["header_hash_matches"])
        self.assertTrue(verification["top_hash_matches"])

    def test_validates_achievement_mutation_for_every_fixture_achievement(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        count = 0
        for entry in list_stfs_entries(data, header):
            if entry.is_directory or not entry.name.casefold().endswith(".gpd"):
                continue
            gpd = read_stfs_entry(data, entry, header)
            for achievement in parse_xdbf(gpd):
                if achievement.achievement is None:
                    continue
                edited = mutate_xdbf_achievement(
                    gpd,
                    achievement.index,
                    achievement_id=achievement.achievement["achievement_id"],
                    image_id=achievement.achievement["image_id"],
                    gamerscore=achievement.achievement["gamerscore"],
                    flags=achievement.achievement["flags"],
                )
                self.assertEqual(len(parse_xdbf(edited)), len(parse_xdbf(gpd)))
                count += 1
        self.assertEqual(count, 2339)

    def test_unknown_magic_is_not_reported_as_container(self):
        self.fixture_dir.mkdir(exist_ok=True)
        path = self.fixture_dir / "sample-unknown"
        path.write_bytes(b"NOPE\x00\x01")
        try:
            report = inspect(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertFalse(report.is_container)
        self.assertEqual(report.package_kind, "Unknown container")

    def test_recognizes_all_stfs_magic_variants_as_containers(self):
        for magic, package_kind in ((b"LIVE", "Xbox 360 LIVE container"), (b"PIRS", "Xbox 360 PIRS container")):
            self.fixture_dir.mkdir(exist_ok=True)
            path = self.fixture_dir / f"sample-{magic.decode('ascii').lower()}"
            path.write_bytes(magic + b"\x00" * 12)
            try:
                report = inspect(path)
            finally:
                path.unlink(missing_ok=True)
            self.assertTrue(report.is_container)
            self.assertEqual(report.package_kind, package_kind)

    def test_parses_xdbf_string_entry(self):
        payload = "Dashboard".encode("utf-16-be") + b"\x00\x00"
        table_length, free_length = 1, 1
        data_base = 0x18 + table_length * 0x12 + free_length * 8
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 2 + b"\x00\x00\x00\x01" * 2
        entry = (5).to_bytes(2, "big") + (0x8000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        data = header + entry + b"\x00" * 8 + payload + b"\x00" * 100

        parsed = parse_xdbf(data)

        self.assertEqual(data_base, 50)
        self.assertEqual(parsed[0].namespace, 5)
        self.assertEqual(parsed[0].text, "Dashboard")
        mutated = mutate_xdbf_entry_same_size(
            data, parsed[0], "Settings!".encode("utf-16-be") + b"\x00\x00"
        )
        self.assertEqual(parse_xdbf(mutated)[0].text, "Settings!")

        longer = "Longer Dashboard".encode("utf-16-be") + b"\x00\x00"
        repacked = repack_xdbf_entries(data, {0: longer})
        self.assertEqual(parse_xdbf(repacked)[0].text, "Longer Dashboard")

        text_mutated = mutate_xdbf_text(data, 0, "Preferences")
        self.assertEqual(parse_xdbf(text_mutated)[0].text, "Preferences")

        removed = repack_xdbf_entries(data, {}, remove=(0,))
        self.assertEqual(parse_xdbf(removed), ())

        with self.assertRaises(ValueError):
            mutate_xdbf_entry_same_size(data, parsed[0], b"short")

        surface = xdbf_payload_surface(data)
        self.assertEqual(surface[0]["kind"], "text")
        self.assertEqual(surface[0]["length"], len(payload))
        self.assertEqual(len(surface[0]["sha256"]), 64)
        self.assertEqual(surface[0]["metadata"]["kind"], "binary")

    def test_reports_conservative_xdbf_png_metadata(self):
        payload = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (64).to_bytes(4, "big") + (32).to_bytes(4, "big") + b"\x08\x06\x00\x00\x00"
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 4
        entry = (2).to_bytes(2, "big") + (1).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        data = header + entry + b"\x00" * 8 + payload
        surface = xdbf_payload_surface(data)
        self.assertEqual(surface[0]["kind"], "opaque")
        self.assertEqual(surface[0]["metadata"], {"kind": "png", "bytes": len(payload), "width": 64, "height": 32})

    def test_links_achievement_image_ids_to_same_file_png_entries(self):
        image = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"\x08\x06\x00\x00\x00"
        achievement = bytearray(0x1c)
        achievement[4:8] = (7).to_bytes(4, "big")
        achievement[8:12] = (99).to_bytes(4, "big")
        header = b"XDBF" + b"\x00\x01\x00\x00" + (b"\x00\x00\x00\x02" + b"\x00\x00\x00\x02" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x01")
        first = (1).to_bytes(2, "big") + (7).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(achievement).to_bytes(4, "big")
        second = (2).to_bytes(2, "big") + (99).to_bytes(8, "big") + len(achievement).to_bytes(4, "big") + len(image).to_bytes(4, "big")
        data = header + first + second + b"\x00" * 8 + bytes(achievement) + image
        links = xdbf_achievement_image_links(data)
        self.assertEqual(links[0]["status"], "linked")
        self.assertEqual(links[0]["image_id"], 99)
        self.assertEqual(links[0]["image_metadata"]["kind"], "png")
        self.assertEqual(xdbf_achievement_image_payload(data, 0), image)
        self.assertEqual(mutate_xdbf_achievement_image(data, 0, image), data)
        with self.assertRaises(ValueError):
            mutate_xdbf_achievement_image(data, 0, b"not-a-png")
        with self.assertRaises(ValueError):
            xdbf_achievement_image_payload(data, 1)

    def test_adds_xdbf_entry_with_explicit_namespace_and_id(self):
        payload = "Dashboard".encode("utf-16-be") + b"\x00\x00"
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x01"
        entry = (5).to_bytes(2, "big") + (0x8000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        data = header + entry + b"\x00" * 8 + payload + b"\x00" * 100
        expanded = bytearray(data)
        expanded[8:12] = (2).to_bytes(4, "big")
        expanded[42:42] = b"\x00" * 0x12

        added = repack_xdbf_entries(
            bytes(expanded), {}, additions={(5, 0x9000): "Added".encode("utf-16-be") + b"\x00\x00"}
        )
        parsed = parse_xdbf(added)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[1].namespace, 5)
        self.assertEqual(parsed[1].entry_id, 0x9000)
        self.assertEqual(parsed[1].text, "Added")

    def test_cli_adds_xdbf_entry_with_explicit_identity(self):
        payload = "Dashboard".encode("utf-16-be") + b"\x00\x00"
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 4
        entry = (5).to_bytes(2, "big") + (0x8000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        expanded = bytearray(header + entry + b"\x00" * 8 + payload + b"\x00" * 100)
        expanded[8:12] = (2).to_bytes(4, "big")
        expanded[42:42] = b"\x00" * 0x12
        directory = self.fixture_dir / "cli-xdbf-add"
        directory.mkdir(parents=True, exist_ok=True)
        source_path = directory / "input.gpd"
        addition_path = directory / "addition.bin"
        output_path = directory / "output.gpd"
        try:
            source_path.write_bytes(bytes(expanded))
            addition_path.write_bytes("Added".encode("utf-16-be") + b"\x00\x00")
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "work.horizon_clone",
                    str(source_path),
                    "--xdbf-add-namespace",
                    "5",
                    "--xdbf-add-id",
                    "0x9000",
                    "--xdbf-add-source",
                    str(addition_path),
                    "--write",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            parsed = parse_xdbf(output_path.read_bytes())
            self.assertEqual(parsed[1].entry_id, 0x9000)
            self.assertEqual(parsed[1].text, "Added")
        finally:
            source_path.unlink(missing_ok=True)
            addition_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_lists_standalone_xdbf_entries(self):
        payload = "Dashboard".encode("utf-16-be") + b"\x00\x00"
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 4
        entry = (5).to_bytes(2, "big") + (0x8000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        directory = self.fixture_dir / "cli-xdbf-list"
        directory.mkdir(parents=True, exist_ok=True)
        source_path = directory / "input.gpd"
        try:
            source_path.write_bytes(header + entry + b"\x00" * 8 + payload + b"\x00" * 20)
            result = subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", str(source_path), "--list"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("ns=    5 id=0x8000", result.stdout)
            self.assertIn("Dashboard", result.stdout)
        finally:
            source_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_mutates_xdbf_achievement_fields(self):
        name = "Old".encode("utf-16-be") + b"\x00\x00"
        payload = bytearray(0x1C + len(name))
        payload[4:8] = (10).to_bytes(4, "big")
        payload[8:12] = (20).to_bytes(4, "big")
        payload[12:16] = (5).to_bytes(4, "big", signed=True)
        payload[16:18] = (1).to_bytes(2, "big")
        payload[0x1C:] = name
        header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 2 + b"\x00\x00\x00\x01" * 2
        entry = (1).to_bytes(2, "big") + (0x9000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(payload).to_bytes(4, "big")
        data = header + entry + b"\x00" * 8 + payload

        mutated = mutate_xdbf_achievement(data, 0, gamerscore=100, flags=7, name="New")
        achievement = parse_xdbf(mutated)[0].achievement
        self.assertEqual(achievement["gamerscore"], 100)
        self.assertEqual(achievement["flags"], 7)
        self.assertEqual(achievement["name"], "New")

        editor = XdbfEditor()
        edited = editor.edit_achievement(data, 0, gamerscore=125, name="API")
        self.assertEqual(parse_xdbf(edited)[0].achievement["gamerscore"], 125)
        self.assertEqual(parse_xdbf(edited)[0].achievement["name"], "API")

        text_payload = "Dashboard".encode("utf-16-be") + b"\x00\x00"
        text_header = b"XDBF" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x01" * 4
        text_entry = (5).to_bytes(2, "big") + (0x8000).to_bytes(8, "big") + (0).to_bytes(4, "big") + len(text_payload).to_bytes(4, "big")
        text_data = text_header + text_entry + b"\x00" * 8 + text_payload + b"\x00" * 100
        text_edited = editor.edit_text(text_data, 0, "Settings")
        self.assertEqual(parse_xdbf(text_edited)[0].text, "Settings")

    def test_mutates_and_rehashes_supplied_profile_fixture(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "Account")
        replacement = b"\x00" * entry.size

        mutated = mutate_stfs_entry_same_size(original, entry, replacement, header)

        self.assertEqual(read_stfs_entry(mutated, entry, header), replacement)
        result = verify_stfs_hashes(mutated, entry, header)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["hash_table_failures"], [])
        self.assertTrue(result["header_hash_matches"])
        self.assertTrue(result["top_hash_matches"])
        self.assertFalse(result["signature_checked"])

    def test_preserves_raw_stfs_entry_flags_in_file_table_model(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        entries = list_stfs_entries(path.read_bytes(), parse_stfs_header(path.read_bytes()))
        account = next(item for item in entries if item.path == "Account")
        cache = next(item for item in entries if item.path == "cache")
        self.assertEqual(account.raw_flags & 0xC0, 0x40 if account.consecutive else 0)
        self.assertEqual(bool(cache.raw_flags & 0x80), cache.is_directory)
        self.assertEqual(bool(cache.raw_flags & 0x40), cache.consecutive)

    def test_renames_stfs_entry_and_rehashes(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = rename_stfs_entry(original, "cache/ph.dat", "ph2.dat", header)
        renamed_header = parse_stfs_header(mutated)
        self.assertIn("cache/ph2.dat", {entry.path for entry in list_stfs_entries(mutated, renamed_header)})
        self.assertEqual(verify_stfs_hashes(mutated, header=renamed_header)["failures"], [])
        with self.assertRaises(ValueError):
            rename_stfs_entry(original, "cache/ph.dat", "bad/name", header)

    def test_adds_stfs_directory_and_remaps_parent_indices(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = add_stfs_directory(original, "cache/NewFolder", header)
        mutated_header = parse_stfs_header(mutated)
        entries = list_stfs_entries(mutated, mutated_header)
        self.assertTrue(next(item for item in entries if item.path == "cache/NewFolder").is_directory)
        self.assertIn("cache/ph.dat", {item.path for item in entries})
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])
        with self.assertRaises(ValueError):
            add_stfs_directory(original, "cache/" + "x" * 41, header)

    def test_moves_stfs_entry_between_directories_and_rehashes(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = move_stfs_entry(original, "cache/ph.dat", "AvatarAssets", "ph2.dat", header)
        mutated_header = parse_stfs_header(mutated)
        paths = {entry.path for entry in list_stfs_entries(mutated, mutated_header)}
        self.assertIn("AvatarAssets/ph2.dat", paths)
        self.assertNotIn("cache/ph.dat", paths)
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])
        with self.assertRaises(ValueError):
            move_stfs_entry(original, "cache", "cache", header=header)

    def test_moves_directory_with_descendants_and_rehashes(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = move_stfs_entry(original, "cache", "AvatarAssets", "CacheMoved", header)
        mutated_header = parse_stfs_header(mutated)
        paths = {entry.path for entry in list_stfs_entries(mutated, mutated_header)}
        self.assertIn("AvatarAssets/CacheMoved", paths)
        self.assertIn("AvatarAssets/CacheMoved/ph.dat", paths)
        self.assertNotIn("cache/ph.dat", paths)
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])

    def test_removes_empty_stfs_directory_and_rehashes(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        with_directory = add_stfs_directory(original, "cache/EmptyFolder", header)
        directory_header = parse_stfs_header(with_directory)
        mutated = repack_stfs_entries(
            with_directory,
            {},
            remove=("cache/EmptyFolder",),
            header=directory_header,
        )
        mutated_header = parse_stfs_header(mutated)
        self.assertNotIn("cache/EmptyFolder", {entry.path for entry in list_stfs_entries(mutated, mutated_header)})
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])

    def test_reuses_file_table_slot_after_removal(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = repack_stfs_entries(
            original,
            {},
            remove=("cache/ph.dat",),
            additions={"cache/replacement.bin": b"replacement"},
            header=header,
        )
        mutated_header = parse_stfs_header(mutated)
        paths = {entry.path for entry in list_stfs_entries(mutated, mutated_header)}
        self.assertNotIn("cache/ph.dat", paths)
        self.assertIn("cache/replacement.bin", paths)
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])

    def test_cli_supports_explicit_in_place_mutation(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "Account")
        directory = self.fixture_dir / "cli-in-place"
        directory.mkdir(parents=True, exist_ok=True)
        work_path = directory / "profile.con"
        replacement_path = directory / "account.bin"
        report_path = directory / "report.json"
        backup_path = directory / "profile.backup"
        try:
            shutil.copyfile(path, work_path)
            replacement_path.write_bytes(b"\x00" * entry.size)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "work.horizon_clone",
                    str(work_path),
                    "--replace",
                    "Account",
                    "--replacement",
                    str(replacement_path),
                    "--in-place",
                    "--backup",
                    str(backup_path),
                    "--output",
                    str(report_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Wrote unsigned in-place mutation", result.stdout)
            mutated = work_path.read_bytes()
            self.assertEqual(backup_path.read_bytes(), original)
            self.assertEqual(read_stfs_entry(mutated, entry, parse_stfs_header(mutated)), b"\x00" * entry.size)
            self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["sha256"], hashlib.sha256(mutated).hexdigest())
        finally:
            work_path.unlink(missing_ok=True)
            replacement_path.unlink(missing_ok=True)
            report_path.unlink(missing_ok=True)
            backup_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_edits_embedded_xdbf_text(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "FFFE07D1.gpd")
        text_entry = next(item for item in parse_xdbf(read_stfs_entry(original, entry, header)) if item.text is not None)
        directory = self.fixture_dir / "cli-embedded-xdbf-text"
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / "profile.con"
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "work.horizon_clone",
                    str(path),
                    "--xdbf-file",
                    entry.path,
                    "--xdbf-text",
                    str(text_entry.index),
                    "--xdbf-text-value",
                    "Edited Dashboard",
                    "--write",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            mutated = output_path.read_bytes()
            mutated_entry = next(item for item in list_stfs_entries(mutated, parse_stfs_header(mutated)) if item.path == entry.path)
            values = parse_xdbf(read_stfs_entry(mutated, mutated_entry, parse_stfs_header(mutated)))
            self.assertEqual(next(item for item in values if item.index == text_entry.index).text, "Edited Dashboard")
            self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])
        finally:
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_lists_embedded_xdbf_entries(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--list-xdbf"],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("FFFE07D1.gpd", result.stdout)
        self.assertIn("string    106", result.stdout)

    def test_lists_embedded_xdbf_library_api(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        embedded = list_embedded_xdbf(path.read_bytes())
        self.assertTrue(any(entry.path == "FFFE07D1.gpd" for entry, _ in embedded))
        self.assertTrue(any(item.index == 106 for entry, items in embedded if entry.path == "FFFE07D1.gpd" for item in items))

    def test_summarizes_embedded_xdbf_namespaces(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        summaries = summarize_embedded_xdbf(path.read_bytes())
        self.assertEqual(len(summaries), 68)
        fit = next(item for item in summaries if item["file"] == "FFFE07D1.fit")
        self.assertEqual(fit["entry_count"], 4)
        self.assertEqual(fit["achievement_count"], 0)
        dashboard = next(item for item in summaries if item["file"] == "FFFE07D1.gpd")
        self.assertIn(1, dashboard["namespace_counts"])
        self.assertIn(3, dashboard["namespace_counts"])
        self.assertEqual(sum(item["achievement_count"] for item in summaries), len(list_embedded_achievements(path.read_bytes())))

    def test_lists_embedded_achievements_library_api(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        records = list_embedded_achievements(path.read_bytes())
        self.assertTrue(records)
        self.assertIn("achievement", records[0])
        self.assertIn("file", records[0])

    def test_lists_embedded_achievement_image_links(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        links = list_embedded_achievement_image_links(path.read_bytes())
        self.assertEqual(len(links), 2339)
        self.assertEqual(sum(item["status"] == "linked" for item in links), 623)
        self.assertEqual(sum(item["status"] == "missing" for item in links), 1716)

    def test_extracts_unique_embedded_achievement_images(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        output = self.fixture_dir / "achievement-images"
        try:
            result = extract_embedded_achievement_images(path.read_bytes(), output)
            self.assertEqual(result["linked_references"], 623)
            self.assertGreater(result["unique_images"], 0)
            self.assertEqual(len(list(output.glob("*.png"))), result["unique_images"])
        finally:
            shutil.rmtree(output, ignore_errors=True)

    def test_cli_lists_embedded_achievements(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--list-achievements"],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("achievement_id=", result.stdout)
        self.assertIn("gamerscore=", result.stdout)

    def test_cli_exports_embedded_achievements_json(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        directory = self.fixture_dir / "achievement-export"
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / "achievements.json"
        try:
            subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", str(path), "--achievements-output", str(output_path)],
                check=True, capture_output=True, text=True,
            )
            records = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(records)
            self.assertIn("achievement", records[0])

            self.assertIn("file", records[0])
        finally:
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_exports_embedded_achievement_image_links_json(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        directory = self.fixture_dir / "achievement-links-export"
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / "links.json"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", str(path), "--achievement-links-output", str(output_path)],
                check=True, capture_output=True, text=True,
            )
            links = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(len(links), 2339)
            self.assertIn('"linked": 623', result.stdout)
        finally:
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_profile_summary_aggregates_observed_achievement_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        summary = summarize_profile_achievements(path.read_bytes())
        self.assertGreater(summary["gpd_count"], 0)
        self.assertEqual(summary["gpd_count"], 67)
        self.assertEqual(summary["fit_count"], 1)
        self.assertEqual(summary["xdbf_count"], 68)
        self.assertEqual(summary["achievement_entry_count"], len(list_embedded_achievements(path.read_bytes())))
        self.assertIn("raw nonzero flag count", summary["flag_semantics"])
        self.assertEqual(summary["gamerscore_total"], 63450)
        self.assertEqual(summary["unlock_time_count"], 721)
        self.assertEqual(summary["earliest_unlock_time_filetime"], 47966688000000000)
        self.assertEqual(summary["earliest_unlock_time_utc"], "1753-01-01T00:00:00.000000Z")
        self.assertEqual(summary["latest_unlock_time_filetime"], 134191513390450000)
        self.assertEqual(summary["latest_unlock_time_utc"], "2026-03-28T06:02:19.045000Z")

    def test_decodes_observed_gpd_achievement_endianness_and_text(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        entry = next(item for item in list_stfs_entries(data, header) if item.name == "415607E7.gpd")
        achievement = next(item for item in parse_xdbf(read_stfs_entry(data, entry, header)) if item.achievement is not None)
        self.assertEqual(achievement.achievement["achievement_id"], 2)
        self.assertEqual(achievement.achievement["image_id"], 3)
        self.assertEqual(achievement.achievement["gamerscore"], 10)
        self.assertEqual(achievement.achievement["flags"], 0x12)
        self.assertEqual(achievement.achievement["unlock_time_filetime"], 0x01DB50E713A9BC80)
        self.assertEqual(achievement.achievement["unlock_time_utc"], "2024-12-18T00:52:13.512000Z")
        self.assertEqual(achievement.achievement["name"], "100K Club")
        changed = mutate_xdbf_achievement(
            read_stfs_entry(data, entry, header),
            achievement.index,
            unlock_time_filetime=0x01DB50E713A9BC81,
        )
        changed_entry = next(item for item in parse_xdbf(changed) if item.index == achievement.index)
        self.assertEqual(changed_entry.achievement["unlock_time_filetime"], 0x01DB50E713A9BC81)
        self.assertEqual(utc_to_filetime(filetime_to_utc(0x01DB50E713A9BC80)), 0x01DB50E713A9BC80)
        utc_changed = mutate_xdbf_achievement(
            read_stfs_entry(data, entry, header),
            achievement.index,
            unlock_time_utc="2024-12-18T00:52:13.512000Z",
        )
        utc_entry = next(item for item in parse_xdbf(utc_changed) if item.index == achievement.index)
        self.assertEqual(utc_entry.achievement["unlock_time_filetime"], 0x01DB50E713A9BC80)

    def test_bulk_achievement_flags_apply_explicit_raw_mask(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        data = path.read_bytes()
        header = parse_stfs_header(data)
        gpd = next(item for item in list_stfs_entries(data, header) if item.name == "415607E7.gpd")
        payload = read_stfs_entry(data, gpd, header)
        achievements = [item for item in parse_xdbf(payload) if item.achievement is not None]
        changed = mutate_xdbf_achievement_flags(payload, 0x0004, mode="or")
        changed_entries = [item for item in parse_xdbf(changed) if item.achievement is not None]
        self.assertEqual(len(changed_entries), len(achievements))
        for before, after in zip(achievements, changed_entries):
            self.assertEqual(after.achievement["flags"], before.achievement["flags"] | 0x0004)
        restored = mutate_xdbf_achievement_flags(changed, 0x0004, mode="and-not")
        restored_entries = [item for item in parse_xdbf(restored) if item.achievement is not None]
        for before, after in zip(achievements, restored_entries):
            self.assertEqual(after.achievement["flags"], before.achievement["flags"] & ~0x0004)

    def test_profile_achievement_flags_apply_across_embedded_gpd_files(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        mutated = mutate_profile_achievement_flags(original, 0x0004, mode="or")
        self.assertEqual(verify_stfs_hashes(mutated)["failures"], [])
        before = list_embedded_achievements(original)
        after = list_embedded_achievements(mutated)
        self.assertEqual(len(after), len(before))
        self.assertGreater(len(after), 0)
        for left, right in zip(before, after):
            self.assertEqual(right["achievement"]["flags"], left["achievement"]["flags"] | 0x0004)

    def test_profile_achievement_images_apply_across_embedded_gpd_files(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        links = [item for item in list_embedded_achievement_image_links(original) if item["status"] == "linked"]
        self.assertTrue(links)
        link = next(
            item for item in links
            if sum(other["image_id"] == item["image_id"] for other in links) == 1
        )
        header = parse_stfs_header(original)
        file_entry = next(item for item in list_stfs_entries(original, header) if item.path == link["file"])
        payload = read_stfs_entry(original, file_entry, header)
        image = xdbf_achievement_image_payload(payload, int(link["achievement_entry_index"]))
        mutated = mutate_profile_achievement_images(original, {int(link["image_id"]): image}, header)
        self.assertEqual(verify_stfs_hashes(mutated)["failures"], [])

    def test_profile_xdbf_text_replaces_exact_embedded_matches(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        record = next(entry for _, entries in list_embedded_xdbf(original) for entry in entries if entry.namespace == 5 and entry.text)
        old_text = record.text
        mutated = mutate_profile_xdbf_text(original, old_text, old_text + "-edited")
        self.assertEqual(verify_stfs_hashes(mutated)["failures"], [])
        before_matches = [item for item in list_embedded_xdbf(original) for item in item[1] if item.namespace == 5 and item.text == old_text]
        after_matches = [item for item in list_embedded_xdbf(mutated) for item in item[1] if item.namespace == 5 and item.text == old_text + "-edited"]
        self.assertEqual(len(after_matches), len(before_matches))

    def test_cli_edits_embedded_xdbf_achievement(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path.endswith(".gpd"))
        xdbf = parse_xdbf(read_stfs_entry(original, entry, header))
        achievement = next((item for item in xdbf if item.achievement is not None), None)
        if achievement is None:
            self.skipTest("fixture contains no observed achievement entry")
        directory = self.fixture_dir / "cli-embedded-xdbf-achievement"
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / "profile.con"
        try:
            subprocess.run(
                [
                    sys.executable, "-m", "work.horizon_clone", str(path),
                    "--xdbf-file", entry.path, "--achievement", str(achievement.index),
                    "--gamerscore", "1000", "--achievement-flags", "1",
                    "--write", str(output_path),
                ], check=True, capture_output=True, text=True,
            )
            mutated = output_path.read_bytes()
            mutated_header = parse_stfs_header(mutated)
            mutated_entry = next(item for item in list_stfs_entries(mutated, mutated_header) if item.path == entry.path)
            edited = next(item for item in parse_xdbf(read_stfs_entry(mutated, mutated_entry, mutated_header)) if item.index == achievement.index)
            self.assertEqual(edited.achievement["gamerscore"], 1000)
            self.assertEqual(edited.achievement["flags"], 1)
            self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])
        finally:
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_removes_embedded_xdbf_entry(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "FFFE07D1.gpd")
        xdbf_entries = parse_xdbf(read_stfs_entry(original, entry, header))
        removable = next(item for item in xdbf_entries if item.text is not None)
        directory = self.fixture_dir / "cli-embedded-xdbf-remove"
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / "profile.con"
        try:
            subprocess.run(
                [
                    sys.executable, "-m", "work.horizon_clone", str(path),
                    "--xdbf-file", entry.path, "--xdbf-remove", str(removable.index),
                    "--write", str(output_path),
                ], check=True, capture_output=True, text=True,
            )
            mutated = output_path.read_bytes()
            mutated_header = parse_stfs_header(mutated)
            mutated_entry = next(item for item in list_stfs_entries(mutated, mutated_header) if item.path == entry.path)
            remaining = parse_xdbf(read_stfs_entry(mutated, mutated_entry, mutated_header))
            self.assertNotIn(removable.index, {item.index for item in remaining})
            self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])
        finally:
            output_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_cli_exposes_stfs_security_metadata(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--security"],
            check=True,
            capture_output=True,
            text=True,
        )
        security, _ = json.JSONDecoder().raw_decode(result.stdout.lstrip())
        self.assertEqual(security["signature_kind"], "console-certificate")
        self.assertEqual(len(security["licenses"]), 16)

    def test_cli_compares_stfs_signature_regions(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--signature-compare", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "metadata-only")
        self.assertEqual(report["changed_bytes"], 0)
        self.assertTrue(report["stored_signature_bytes_unchanged"])

    def test_cli_exports_stfs_thumbnail_payloads(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        directory = self.fixture_dir / "thumbnail-export"
        directory.mkdir(parents=True, exist_ok=True)
        thumbnail_path = directory / "thumbnail.bin"
        title_path = directory / "title-thumbnail.bin"
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "work.horizon_clone",
                    str(path),
                    "--thumbnail-output",
                    str(thumbnail_path),
                    "--title-thumbnail-output",
                    str(title_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            original = path.read_bytes()
            thumbnails = parse_stfs_thumbnails(original, parse_stfs_header(original))
            self.assertEqual(thumbnail_path.read_bytes(), thumbnails.thumbnail)
            self.assertEqual(title_path.read_bytes(), thumbnails.title_thumbnail)
            self.assertIn("Exported requested thumbnail", result.stdout)
        finally:
            thumbnail_path.unlink(missing_ok=True)
            title_path.unlink(missing_ok=True)
            directory.rmdir()

    def test_rehashes_and_verifies_the_complete_stfs_tree(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        rebuilt = rehash_stfs_hashes(original, header)
        result = verify_stfs_hashes(rebuilt, header=parse_stfs_header(rebuilt))
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["hash_table_failures"], [])
        self.assertTrue(result["header_hash_matches"])
        self.assertTrue(result["top_hash_matches"])

    def test_console_validation_requires_hash_tree_and_package_signature(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        report = stfs_console_validation_report(path.read_bytes())
        self.assertEqual(report["status"], "verified")
        self.assertTrue(report["hash_tree_verified"])
        self.assertTrue(report["package_signature_verified"])
        self.assertFalse(report["console_authority_established"])

    def test_signing_provider_boundary_rejects_empty_signatures(self):
        class EmptyProvider:
            def sign_sha256(self, message):
                return b""

        with self.assertRaises(ValueError):
            sign_with_provider(b"test vector", EmptyProvider())

        self.assertFalse(verify_sha256_pkcs1v15(b"test vector", b"bad", RsaPublicKey(257, 3)))
        region = SignedRegion("development-test", b"test vector")
        class TestProvider:
            def sign_sha256(self, message):
                self.message = message
                return b"signature"

        provider = TestProvider()
        detached = sign_region(region, provider)
        self.assertEqual(detached.region_label, "development-test")
        self.assertEqual(provider.message, region.data)
        detached = DetachedSignature("other-region", detached.algorithm, detached.signature)
        self.assertFalse(verify_region(region, detached, RsaPublicKey(257, 3)))

    def test_external_sha1_signing_provider_requires_absolute_helper(self):
        with self.assertRaises(ValueError):
            CommandSha1SigningProvider("relative-helper")

    def test_external_sha1_signing_provider_uses_bounded_json_protocol(self):
        helper = self.fixture_dir / "signing-helper.exe"
        helper.write_bytes(b"placeholder")
        try:
            provider = CommandSha1SigningProvider(helper)
            completed = mock.Mock(returncode=0, stdout=json.dumps({"signature_base64": "c2lnbmF0dXJl"}), stderr="")
            with mock.patch("work.signing.subprocess.run", return_value=completed) as run:
                self.assertEqual(provider.sign_sha1(b"message"), b"signature")
            request = json.loads(run.call_args.kwargs["input"])
            self.assertEqual(request["algorithm"], "RSA-SHA1-PKCS1v1.5")
            self.assertEqual(request["message_base64"], "bWVzc2FnZQ==")
            self.assertEqual(run.call_args.kwargs["timeout"], 30.0)
            self.assertFalse(run.call_args.kwargs["check"])
        finally:
            helper.unlink(missing_ok=True)

    def test_reads_explicit_development_private_key_json(self):
        path = self.fixture_dir / "development-private-key.json"
        path.write_text(json.dumps({"modulus_hex": "80", "private_exponent_hex": "03"}), encoding="utf-8")
        try:
            key = read_private_key_json(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(key.modulus, 0x80)
        self.assertEqual(key.private_exponent, 3)

    def test_detached_signing_rejects_overwriting_signed_input(self):
        region = self.fixture_dir / "signed-region.bin"
        key = self.fixture_dir / "development-private-key.json"
        region.write_bytes(b"development bytes")
        key.write_text(json.dumps({"modulus_hex": "80", "private_exponent_hex": "03"}), encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sign_detached_signature(region, region, "development", key)
        finally:
            region.unlink(missing_ok=True)
            key.unlink(missing_ok=True)

    def test_sha1_verification_dispatch_is_explicit_and_fail_closed(self):
        key = RsaPublicKey(257, 3)
        self.assertFalse(verify_sha1_pkcs1v15(b"test vector", b"bad", key))
        region = SignedRegion("legacy-region", b"test vector")
        detached = DetachedSignature("legacy-region", "RSA-SHA1-PKCS1v1.5", b"bad")
        self.assertFalse(verify_region(region, detached, key))

    def test_embedded_signature_verifier_requires_explicit_nonoverlapping_region(self):
        data = b"signed-data" + b"\x01" * 32
        self.assertFalse(verify_embedded_signature_region(
            data,
            signed_start=0,
            signed_end=11,
            signature_offset=11,
            modulus=257,
            exponent=3,
        ))
        with self.assertRaises(ValueError):
            verify_embedded_signature_region(
                data,
                signed_start=0,
                signed_end=12,
                signature_offset=11,
                modulus=257,
                exponent=3,
            )
        self.assertFalse(verify_xecrypt_sha1_pkcs1v15(b"signed-data", b"\x01" * 32, RsaPublicKey(257, 3)))

    def test_profile_model_round_trips_observed_metadata(self):
        profile = ProfileData(
            from_device=True,
            xuid=0x0123456789ABCDEF,
            gamertag="Test User",
            gamer_picture=b"\x01\x02",
            profile_id=0xE9ECC9141E317C7B,
            favorite=True,
        )
        self.assertEqual(ProfileData.from_dict(profile.to_dict()), profile)

    def test_profile_data_cli_report_validates_authenticated_envelope(self):
        path = self.fixture_dir / "profile-data.json"
        path.write_text(json.dumps({
            "editor": "profile-data",
            "values": {
                "from_device": True,
                "xuid": 1,
                "gamertag": "Test User",
                "gamer_picture": "0102",
                "profile_id": 2,
                "favorite": False,
            },
        }), encoding="utf-8")
        try:
            report = profile_data_report(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(report["status"], "metadata-only")
        self.assertEqual(report["values"]["xuid"], 1)

    def test_editor_inspect_dispatches_an_explicit_profile_envelope(self):
        path = self.fixture_dir / "editor-profile.json"
        path.write_text(json.dumps({
            "editor": "profile-data",
            "values": {"xuid": 9, "gamertag": "Dispatch", "gamer_picture": "", "profile_id": 10},
        }), encoding="utf-8")
        try:
            report = editor_inspect_report(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(report["editor"], "ProfileData metadata editor")
        self.assertEqual(report["result"]["values"]["xuid"], 9)

    def test_editor_edit_values_uses_declared_profile_plugin(self):
        source = self.fixture_dir / "editor-edit-profile.json"
        values = self.fixture_dir / "editor-edit-values.json"
        source.write_text(json.dumps({"editor": "profile-data", "values": {"xuid": 1}}), encoding="utf-8")
        values.write_text(json.dumps({"xuid": 2, "gamertag": "Edited"}), encoding="utf-8")
        try:
            editor_name, edited = editor_edit_values(source, values)
        finally:
            source.unlink(missing_ok=True)
            values.unlink(missing_ok=True)
        self.assertEqual(editor_name, "ProfileData metadata editor")
        self.assertEqual(json.loads(edited)["values"]["xuid"], 2)

    def test_editor_edit_values_does_not_allow_implicit_in_place_overwrite(self):
        source = self.fixture_dir / "editor-edit-in-place.json"
        values = self.fixture_dir / "editor-edit-in-place-values.json"
        source.write_text(json.dumps({"editor": "profile-data", "values": {"xuid": 1}}), encoding="utf-8")
        values.write_text(json.dumps({"xuid": 2}), encoding="utf-8")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", str(source), "--editor-edit-values", str(values), "--editor-edit-output", str(source)],
                capture_output=True,
                text=True,
            )
        finally:
            source.unlink(missing_ok=True)
            values.unlink(missing_ok=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different from the input path", result.stderr)

    def test_verifies_detached_signature_through_explicit_public_key_boundary(self):
        region = self.fixture_dir / "signed-region.bin"
        signature = self.fixture_dir / "signed-region.sig"
        region.write_bytes(b"development bytes")
        signature.write_bytes(b"not-a-signature")
        try:
            self.assertFalse(verify_detached_signature(region, signature, "development", "RSA-SHA256-PKCS1v1.5", 257, 3))
        finally:
            region.unlink(missing_ok=True)
            signature.unlink(missing_ok=True)

    def test_reads_public_key_json_emitted_by_public_key_command(self):
        path = self.fixture_dir / "public-key.json"
        path.write_text(json.dumps({"exponent": 3, "modulus_hex": "0101"}), encoding="utf-8")
        try:
            self.assertEqual(read_public_key_json(path), (257, 3))
        finally:
            path.unlink(missing_ok=True)

    def test_reports_observed_anti_analysis_markers_without_bypassing_them(self):
        bundle = Path("work/rea-managed-members-latest.json")
        if not bundle.exists():
            self.skipTest("retained REA bundle is not available")
        report = anti_analysis_report(bundle)
        self.assertEqual(report["status"], "observed-only")
        self.assertTrue(any("Debugger" in str(item["type_name"]) for item in report["attribute_markers"]))
        self.assertTrue(any("ZYXDNGuarder" in str(item["full_name"]) for item in report["guarded_types"]))
        self.assertIn("ZYXDNGuarder", report["guarded_type_names"])
        self.assertIn("ZYXDNGuard", report["guarded_method_names"])
        self.assertIn("System.Diagnostics.DebuggerHiddenAttribute", report["attribute_marker_counts"])
        self.assertEqual(report["debugger_api_presence"], "not-observed-in-retained-call-edges")
        self.assertEqual(report["debugger_api_calls"], [])
        self.assertEqual(report["analysis_workaround"]["mode"], "static-and-controlled-runtime-only")
        self.assertTrue(report["guarded_methods"][0].keys() >= {"declaring_type", "name", "token", "rva", "body"})
        self.assertGreater(report["guard_dispatch_stub_count"], 0)
        self.assertTrue(all(item["classification"] == "guard-dispatch-stub" for item in report["guard_dispatch_stubs"]))

    def test_reports_complete_rea_managed_pinvoke_inventory(self):
        bundle = Path("work/rea-export-20261010.json")
        if not bundle.exists():
            self.skipTest("retained REA export bundle is not available")
        report = managed_native_import_report(bundle)
        self.assertEqual(report["counts"]["total"], 54)
        self.assertEqual(report["counts"]["matched"], 54)
        self.assertTrue(any(item["import_name"] == "RtsSaveDecrypt" for item in report["imports"]))

    def test_audits_retained_managed_body_fidelity(self):
        bundle = Path("work/rea-managed-members-latest.json")
        if not bundle.exists():
            self.skipTest("retained REA bundle is not available")
        report = managed_body_fidelity_report(bundle, r"Horizon\.PackageEditors\.Halo")
        self.assertGreater(report["counts"]["selected_methods"], 1000)
        self.assertLess(report["counts"]["unique_file_offsets"], report["counts"]["selected_methods"])
        self.assertGreater(report["counts"]["duplicate_file_offset_groups"], 0)
        self.assertGreater(report["counts"]["throw_without_return"], 1000)

    def test_exposes_observed_skyrim_enum_names_without_guessing_values(self):
        enums = observed_skyrim_enums()
        self.assertEqual({item.name for item in enums}, {"ShoutEnums", "PerkEnums", "MagicEnums"})
        self.assertEqual(len(enum_member_names("ShoutEnums")), 27)
        self.assertTrue(all(item.values_observed for item in enums))
        self.assertTrue(all(set(item.members) == set(item.values or {}) for item in enums))
        summary = observed_skyrim_enum_summary()
        self.assertEqual(summary["underlying_type"], "i4")
        self.assertEqual(summary["enums"]["PerkEnums"]["named_member_count"], 273)
        self.assertTrue(summary["constant_values_observed"])
        self.assertEqual(enum_member_values("ShoutEnums")["AnimalAllegiance"], 392311)

    def test_exposes_observed_gears_entry_id_constants(self):
        entries = gears_of_war_3_entry_ids()
        self.assertGreater(len(entries), 1000)
        self.assertIn("Selected_COG_Character", entries)
        self.assertIn("Horde_Sentry_Level_7", entries)
        summary = gears_entry_id_summary()
        self.assertEqual(summary["declaring_type"], "Horizon.PackageEditors.Gears_of_War_3.EntryID")
        self.assertEqual(summary["named_member_count"], len(entries))
        self.assertTrue(summary["constant_values_observed"])
        self.assertEqual(summary["constant_value_count"], 1139)

    def test_exposes_observed_halo_general_class_names_without_guessing_layouts(self):
        types = halo_general_class_types()
        self.assertEqual(len(types), 103)
        self.assertIn("GameVariant", types)
        self.assertIn("Halo4PlayerTraits", types)
        self.assertIn("HMegaloStrings", types)
        field_types = halo_general_class_field_types()
        self.assertEqual(sum(len(fields) for fields in field_types.values()), 489)
        self.assertEqual(len(field_types), 92)
        counts = halo_general_class_field_counts()
        self.assertEqual(counts["GameVariant"], 3)
        self.assertEqual(counts["Halo4GameOptionsOrdnanceOptions"], 22)
        summary = halo_general_class_method_summary()
        self.assertEqual(summary["method_count"], 1102)
        self.assertEqual(summary["unique_getter_setter_property_count"], 140)
        self.assertEqual(summary["getter_method_count"], 175)
        self.assertEqual(summary["setter_method_count"], 168)
        self.assertEqual(summary["properties_with_getter_and_setter"], 135)
        self.assertEqual(summary["setter_only_properties"], [])
        self.assertIn("IsValid", summary["getter_only_properties"])
        properties = halo_general_class_property_names()
        self.assertEqual(len(properties), 140)
        self.assertIn("InitialEquipment", properties)
        self.assertIn("c09521bc19ea8141a547e37f5ed091fcf", properties)

    def test_exposes_authenticated_shared_horizon_constant_values(self):
        catalogs = observed_catalogs()
        self.assertEqual(
            {item.name for item in catalogs},
            {"ProfileLoadout", "SaveEntryCategory"},
        )
        self.assertEqual(catalog_member_names("ProfileLoadout"), ("All_Loadouts",))
        self.assertIn("Campaign_Level", catalog_member_names("SaveEntryCategory"))
        self.assertTrue(any(item.values_observed for item in catalogs))
        self.assertEqual(catalog_report("shared")["values"]["SaveEntryCategory"]["Campaign_Level"], 6)

    def test_exposes_observed_profile_data_field_contract(self):
        fields = observed_profile_data_fields()
        self.assertEqual(
            [(item.name, item.field_type) for item in fields],
            [
                ("FromDevice", "bool"),
                ("XUID", "u8"),
                ("Gamertag", "string"),
                ("Gamerpicture", "u1[]"),
                ("ProfileId", "u8"),
                ("Favorite", "bool"),
            ],
        )
        self.assertEqual(observed_fields("Horizon.ProfileData"), fields)

    def test_exposes_observed_profile_data_resource_getters(self):
        methods = observed_profile_data_methods()
        self.assertEqual(
            [(item.name, item.parameter_types, item.return_type) for item in methods],
            [
                ("get_GoWJ_Thumb_New", (), "class:957"),
                ("get_GrayDot", (), "class:957"),
            ],
        )

    def test_profile_data_enforces_observed_unsigned_64_bit_fields(self):
        with self.assertRaises(ValueError):
            ProfileData(xuid=-1)
        with self.assertRaises(ValueError):
            ProfileData(profile_id=0x1_0000_0000_0000_0000)
        with self.assertRaises(TypeError):
            ProfileData(gamer_picture="not-bytes")

    def test_reports_aggregate_title_editor_inventory(self):
        inventory = observed_editor_inventory()
        self.assertEqual(
            {item.name: item.observed_type_count for item in inventory},
            {
                "Skyrim": 3,
                "Gears of War 3": 1,
                "Halo general classes": 103,
                "Dragon Ball Xenoverse": 1,
                "Code Veronica X": 1,
                "Devil May Cry": 1,
                "Ninja Gaiden 3": 2,
                "State of Decay": 1,
                "Castle Crashers": 1,
                "Saints Row": 3,
            },
        )
        summary = inventory_summary()
        self.assertEqual(summary["managed_type_count"], 7693)
        self.assertTrue(all(item["implementation_status"] == "catalog-only" for item in summary["editors"]))

    def test_exposes_additional_legacy_title_catalogs(self):
        catalogs = observed_legacy_catalogs()
        self.assertEqual(len(catalogs), 7)
        self.assertEqual(sum(item.type_count for item in catalogs), 10)
        self.assertEqual(sum(item.field_count for item in catalogs), 150)
        self.assertEqual(legacy_catalog_report()["status"], "catalog-only")
        self.assertIn("NinjaGaiden3SkillRyu", catalog_report("legacy")["catalogs"][3]["types"][0]["name"])
        self.assertEqual(legacy_field_names("Bandai", "DBXVAttributes")[1], "MaxHealth")
        self.assertIn("Hatty_Hattington", legacy_field_names("TheBehemoth", "CastleCrashersCharacters"))
        dbxv = catalog_report("legacy")["catalogs"][0]["types"][0]
        self.assertEqual(dbxv["backing_type"], "i4")
        self.assertEqual(dbxv["named_member_count"], 6)
        self.assertTrue(dbxv["value_field_observed"])

    def test_reports_evidence_qualified_capability_ledger(self):
        report = capability_report()
        by_name = {item["name"]: item for item in report["capabilities"]}
        self.assertEqual(report["managed_method_count"], 37401)
        self.assertEqual(by_name["STFS hash verification"]["status"], "implemented")
        self.assertEqual(by_name["Desktop atomic artifact writes"]["status"], "implemented")
        self.assertEqual(by_name["Managed surface editor dispatch"]["status"], "implemented")
        self.assertEqual(by_name["Opaque Account editor dispatch"]["status"], "implemented")
        self.assertEqual(by_name["Halo typed metadata validation"]["status"], "metadata-only")
        self.assertEqual(by_name["Halo metadata editor dispatch"]["status"], "metadata-only")
        self.assertEqual(by_name["Skyrim enum catalogs"]["status"], "metadata-only")
        self.assertEqual(by_name["Gears EntryID validation"]["status"], "metadata-only")
        self.assertEqual(by_name["Authenticated Constant catalog dispatch"]["status"], "metadata-only")
        self.assertEqual(by_name["ProfileData contract"]["status"], "metadata-only")
        self.assertEqual(by_name["ProfileData metadata editor dispatch"]["status"], "metadata-only")
        self.assertEqual(by_name["Account serialization"]["status"], "unresolved")
        self.assertIn("LIVE/PIRS", by_name["Console and remote package signing"]["evidence"])
        self.assertIn("no managed Account type", by_name["Account serialization"]["evidence"])
        self.assertEqual(by_name["Console and remote package signing"]["status"], "provider-boundary")
        self.assertEqual(by_name["Native save/runtime boundaries"]["status"], "provider-boundary")
        self.assertIn("RunHVM=0", by_name["DNG/HVM runtime adapter"]["evidence"])
        self.assertIn("zero/nonzero behavior", by_name["DNG/HVM runtime adapter"]["evidence"])
        self.assertEqual(by_name["Managed feature-surface inventory"]["status"], "observed-only")
        self.assertIn("--managed-feature-surface", by_name["Managed feature-surface inventory"]["entry_points"])
        self.assertIn("NativeSaveBinding", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("CtypesNativeSaveProvider", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("LzoBinding", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("DeviceIoBinding", by_name["Device exploration surface"]["entry_points"])
        self.assertIn("--native-installation", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("--resource-surface", by_name["Embedded UI/resource surface"]["entry_points"])

    def test_reports_observed_native_save_and_runtime_boundaries(self):
        surface = native_surface_report()
        self.assertEqual(surface["status"], "declaration-only")
        self.assertEqual(surface["observed_module_ref_count"], 14)
        self.assertEqual(surface["observed_pinvoke_count"], 54)
        self.assertEqual(surface["unique_import_count"], len(observed_native_imports()))
        probes = {(item["operation"], tuple(item["arguments"])) for item in surface["controlled_runtime_probes"]}
        self.assertIn(("CheckRuntime", ()), probes)
        self.assertIn(("GetUserString", (1, 0, 0)), probes)
        imports = {(item.module, item.import_name) for item in observed_native_imports()}
        self.assertIn(("class3.dll", "RtsSaveEncrypt"), imports)
        self.assertIn(("class3.dll", "RtsSaveDecrypt"), imports)
        self.assertIn(("Horizon.dll", "RunHVM"), imports)
        self.assertIn(("Horizon.dll", "GetUserString"), imports)
        self.assertIn(("mscoree.dll", "CLRCreateInstance"), imports)
        self.assertIn(("lzo.dll", "lzo_version_string"), imports)
        self.assertIn(("kernel32.dll", "CreatePrivateNamespace"), imports)
        self.assertIn(("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptor"), imports)
        self.assertIn(("gdi32.dll", "CreateCompatibleDC"), imports)
        by_import = {(item.module, item.import_name): item for item in observed_native_imports()}
        self.assertEqual(by_import[("class3.dll", "RtsSaveEncrypt")].return_type, "i4")
        self.assertEqual(
            by_import[("class3.dll", "RtsSaveEncrypt")].parameter_types,
            ("u1[]", "u1[]", "u4", "u1[]"),
        )
        self.assertEqual(
            by_import[("Horizon.dll", "GetUserString")].parameter_types,
            ("native-int", "i4", "i4"),
        )
        callers = {(item.caller, item.import_name) for item in observed_native_callers()}
        self.assertIn(("A.cd936781820a998f272eb4df3bd2b8c2a.Startup", "DNG_Runtime"), callers)
        self.assertIn(("A.cd9276f49d88a260398f12b2584c549ca.CheckString", "GetUserString"), callers)

    def test_reports_and_validates_profile_assets(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        report = profile_asset_report(original, header)
        assets = {item["path"]: item for item in report["assets"]}
        self.assertEqual(assets["tile_64.png"]["metadata"]["width"], 64)
        self.assertEqual(assets["tile_32.png"]["metadata"]["height"], 32)
        tile = read_stfs_entry(original, next(item for item in list_stfs_entries(original, header) if item.path == "tile_64.png"), header)
        edited = mutate_profile_assets(original, {"tile_64.png": tile}, header)
        self.assertEqual(verify_stfs_hashes(edited, header=parse_stfs_header(edited))["failures"], [])
        with self.assertRaises(ValueError):
            mutate_profile_assets(original, {"tile_64.png": b"not-a-png"}, header)

    def test_cli_exposes_profile_asset_replacement(self):
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", "--help"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--profile-asset ENTRY SOURCE", result.stdout)
        self.assertIn("--achievement-image INDEX", result.stdout)
        self.assertIn("--profile-achievement-image IMAGE_ID SOURCE", result.stdout)

    def test_reports_observed_device_exploration_surface(self):
        surface = device_surface_report()
        self.assertEqual(surface["status"], "metadata-only")
        members = {(item.declaring_type, item.name) for item in observed_device_members()}
        self.assertIn(("A.c0353b6b5ff8fecef988e28ba8b350fd5", "get_DeviceSize"), members)
        self.assertIn(("A.c481e7f09def65aded5645fc775214ae5", "get_Account_Thumb"), members)
        self.assertIn(("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxHDD_24"), members)
        self.assertIn(("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxMU_24"), members)
        self.assertIn(("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxUSB_24"), members)

    def test_device_binding_requires_provider_and_validates_observed_i8_property(self):
        binding = DeviceBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(DeviceProviderUnavailable):
            binding.get_device_size()

        class Provider:
            def __init__(self):
                self.value = 1024

            def get_device_size(self):
                return self.value

            def set_device_size(self, value):
                self.value = value

        bound = DeviceBinding(Provider())
        self.assertEqual(bound.get_device_size(), 1024)
        bound.set_device_size(-1)
        self.assertEqual(bound.get_device_size(), -1)
        with self.assertRaises(ValueError):
            bound.set_device_size(0x8000_0000_0000_0000)

    def test_device_io_binding_requires_explicit_provider_and_preserves_raw_bytes(self):
        binding = DeviceIoBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(DeviceProviderUnavailable):
            binding.open_read_only(r"\\.\PhysicalDrive0")

        class Provider:
            def open_read_only(self, device_path):
                self.path = device_path
                return 7

            def device_io_control(self, handle, control_code, input_data, output_capacity):
                self.call = (handle, control_code, input_data, output_capacity)
                return b"raw-response"

            def close(self, handle):
                self.closed = handle

        bound = DeviceIoBinding(Provider())
        self.assertEqual(bound.open_read_only(r"\\.\PhysicalDrive0"), 7)
        self.assertEqual(bound.device_io_control(7, 0x222000, b"request", 64), b"raw-response")
        bound.close(7)
        with bound.open_session(r"\\.\PhysicalDrive0") as session:
            self.assertEqual(session.io_control(0x222000, b"request", 64), b"raw-response")
        self.assertFalse(DeviceIoBinding(Provider()).open_session(r"\\.\PhysicalDrive0").write_access)

    def test_native_runtime_requires_explicit_provider(self):
        binding = NativeRuntimeBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(NativeRuntimeUnavailable):
            binding.check_runtime()
        with self.assertRaises(NativeRuntimeUnavailable):
            binding.check_runtime64()

        class Provider:
            def check_runtime(self):
                return True

            def check_runtime64(self):
                return False

            def run_hvm(self):
                return 7

            def get_user_string(self, arg0, arg1, arg2):
                return arg0 + arg1 + arg2

            def get_user_string64(self, arg0, arg1, arg2):
                return arg0 - arg1 - arg2

        bound = NativeRuntimeBinding(Provider())
        self.assertEqual(bound.status, "provider-bound")
        self.assertTrue(bound.check_runtime())
        self.assertFalse(bound.check_runtime64())
        self.assertEqual(bound.run_hvm(), 7)
        self.assertEqual(bound.get_user_string(1, 2, 3), 6)
        self.assertEqual(bound.get_user_string64(9, 2, 1), 6)

    def test_native_runtime_operation_report_preserves_raw_provider_result(self):
        class Provider:
            def check_runtime(self):
                return True

            def check_runtime64(self):
                return False

            def run_hvm(self):
                return 0x1234

            def get_user_string(self, arg0, arg1, arg2):
                return arg0 + arg1 + arg2

            def get_user_string64(self, arg0, arg1, arg2):
                return arg0 - arg1 - arg2

        report = native_runtime_operation_report(
            Path("C:/explicit/Horizon.dll"), "get-user-string64", (9, 2, 1), provider=Provider()
        )
        self.assertEqual(report["result"], 6)
        self.assertEqual(report["arguments"], [9, 2, 1])
        with self.assertRaises(ValueError):
            native_runtime_operation_report(Path("C:/explicit/Horizon.dll"), "run-hvm", (1,), provider=Provider())

    def test_native_lzo_operation_report_preserves_provider_output(self):
        class Provider:
            def lzo_version_string(self):
                return "test-lzo"

            def lzo_version_date(self):
                return "test-date"

            def lzo1x_1_compress(self, source, source_length, destination, destination_length, work_memory):
                destination[:source_length] = source[:source_length]
                destination_length.value = source_length
                return 0

            def lzo1x_decompress(self, source, source_length, destination, destination_length, work_memory):
                destination[:source_length] = source[:source_length]
                destination_length.value = source_length
                return 0

        report = native_lzo_operation_report(
            Path("C:/explicit/lzo.dll"), "compress", source=b"abc", output_capacity=16, provider=Provider()
        )
        self.assertEqual(report["result"]["output_length"], 3)
        self.assertEqual(report["output"], b"abc")
        self.assertEqual(
            native_lzo_operation_report(Path("C:/explicit/lzo.dll"), "version-string", provider=Provider())["result"],
            "test-lzo",
        )

    def test_native_runtime_operation_preflights_supplied_image_without_execution(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        if not dll.exists():
            self.skipTest("supplied Horizon.dll is unavailable")
        with self.assertRaises(OSError):
            native_runtime_operation_report(dll, "check-runtime64")

    def test_x86_runtime_check_executes_supplied_horizon_dll(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 Horizon.dll or 32-bit PowerShell host is unavailable")
        report = native_runtime_operation_report(dll, "check-runtime", powershell_path=host)
        self.assertTrue(report["result"])
        self.assertEqual(report["status"], "provider-bound-raw-result")

    def test_native_runtime_provider_requires_explicit_absolute_image(self):
        with self.assertRaises(ValueError):
            PowerShellNativeRuntimeProvider("Horizon.dll")
        with self.assertRaises(FileNotFoundError):
            PowerShellNativeRuntimeProvider("C:\\does-not-exist\\Horizon.dll")

    def test_native_runtime_provider_reports_supplied_x86_image_without_invoking_exports(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 Horizon.dll or 32-bit PowerShell host is unavailable")
        provider = PowerShellNativeRuntimeProvider(dll, powershell_path=host, host_architecture="x86")
        self.assertEqual(provider.architecture, "x86")
        self.assertEqual(provider.path, dll)

    def test_native_runtime_provider_rejects_wrong_width_operation(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 Horizon.dll or 32-bit PowerShell host is unavailable")
        provider = PowerShellNativeRuntimeProvider(dll, powershell_path=host, host_architecture="x86")
        with self.assertRaises(OSError):
            provider.check_runtime64()
        with self.assertRaises(OSError):
            provider.get_user_string64(1, 2, 3)

    def test_native_runtime_provider_invokes_shipped_runtime_check(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 Horizon.dll or 32-bit PowerShell host is unavailable")
        provider = PowerShellNativeRuntimeProvider(dll, powershell_path=host, host_architecture="x86")
        self.assertIs(provider.check_runtime(), True)

    def test_native_save_requires_explicit_provider_and_preserves_observed_shapes(self):
        binding = NativeSaveBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(NativeSaveUnavailable):
            binding.encrypt(b"in", bytearray(8), 2, b"key")

        class Provider:
            def rts_save_decrypt(self, input_buffer, output_length, output_buffer, input_length, key):
                output_buffer[:input_length] = input_buffer[:input_length]
                output_length.value = input_length
                return 0

            def rts_save_encrypt(self, input_buffer, output_buffer, input_length, key):
                output_buffer[:input_length] = input_buffer[:input_length]
                return 0

        bound = NativeSaveBinding(Provider())
        output = bytearray(8)
        self.assertEqual(bound.encrypt(b"in", output, 2, b"key"), 0)
        self.assertEqual(output[:2], b"in")
        length = UInt32Ref(8)
        self.assertEqual(bound.decrypt(b"in", length, output, 2, b"key"), 0)
        self.assertEqual(length.value, 2)
        with self.assertRaises(ValueError):
            bound.encrypt(b"in", output, 0x1_0000_0000, b"key")
        with self.assertRaises(ValueError):
            bound.encrypt(b"in", output, 3, b"key")

    def test_ctypes_native_save_provider_requires_explicit_absolute_dll_path(self):
        with self.assertRaises(ValueError):
            CtypesNativeSaveProvider("class3.dll")
        with self.assertRaises(FileNotFoundError):
            CtypesNativeSaveProvider("C:\\does-not-exist\\class3.dll")

    def test_x86_powershell_class3_provider_preserves_raw_encrypt_boundary(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\class3.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 class3 DLL or 32-bit PowerShell host is unavailable")
        provider = PowerShellNativeSaveProvider(dll, host)
        output = bytearray(1024)
        status = provider.rts_save_encrypt(b"test", output, 4, bytes(16))
        self.assertEqual(provider.architecture, "x86")
        self.assertIsInstance(status, int)

    def test_native_loader_reports_supplied_dll_architecture_without_loading_it(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\class3.dll")
        if not path.exists():
            self.skipTest("supplied class3.dll is not available")
        image, process = compatible_pe_architecture(path)
        self.assertEqual(image, "x86")
        self.assertIn(process, {"x86", "x86_64"})
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--native-architecture"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["image_architecture"], "x86")

    def test_native_loader_reports_observed_class3_exports_without_loading_it(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\class3.dll")
        if not path.exists():
            self.skipTest("supplied class3.dll is not available")
        exports = pe_export_names(path)
        self.assertIn("RtsSaveDecrypt", exports)
        self.assertIn("RtsSaveEncrypt", exports)
        table = {row["name"]: row for row in pe_export_table(path)}
        self.assertEqual(set(table), set(exports))
        self.assertTrue(all(isinstance(row["ordinal"], int) for row in table.values()))
        self.assertTrue(all(isinstance(row["rva"], int) for row in table.values()))
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--native-exports"],
            capture_output=True,
            text=True,
            check=True,
        )
        cli_exports = json.loads(result.stdout)
        self.assertIn("RtsSaveDecrypt", cli_exports["exports"])
        self.assertEqual({row["name"] for row in cli_exports["export_table"]}, set(exports))
        contract = native_export_contract_report(path)
        self.assertEqual(contract["status"], "verified")
        self.assertEqual(contract["artifact_sha256"], "ebe7eda16e07382d2055a6ba9cc436d58010e546a93f881a2e965f123013e0d6")
        self.assertEqual(contract["export_count"], 2)
        self.assertEqual(len(contract["export_table_sha256"]), 64)
        self.assertEqual(contract["missing_exports"], [])
        self.assertEqual({row["name"] for row in contract["export_table"]}, set(exports))

    def test_native_loader_reports_class3_import_table_without_loading_it(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\class3.dll")
        if not path.exists():
            self.skipTest("supplied class3.dll is not available")
        imports = pe_import_table(path)
        self.assertTrue(imports)
        self.assertTrue(all(row["module"] for row in imports))
        self.assertTrue(any(row["import_name"] == "memcpy" for row in imports))
        report = native_import_table_report(path)
        self.assertEqual(report["status"], "observed-only")
        self.assertEqual(report["artifact_sha256"], "ebe7eda16e07382d2055a6ba9cc436d58010e546a93f881a2e965f123013e0d6")
        self.assertTrue(any(str(module).casefold().startswith("msvcr") for module in report["modules"]))
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--native-imports"],
            capture_output=True,
            text=True,
            check=True,
        )
        cli_report = json.loads(result.stdout)
        self.assertEqual(cli_report["import_count"], len(imports))
        self.assertEqual(cli_report["module_count"], len(report["modules"]))

    def test_native_anti_analysis_report_records_class3_debugger_import_without_bypassing(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\class3.dll")
        if not path.exists():
            self.skipTest("supplied class3.dll is not available")
        report = native_anti_analysis_report(path)
        self.assertEqual(report["status"], "observed-only")
        self.assertIn("IsDebuggerPresent", report["debugger_api_imports"])
        self.assertIn("GetCurrentProcessId", report["process_probe_imports"])
        runtime = native_anti_analysis_report(Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll"))
        self.assertIn("VirtualProtect", runtime["memory_protection_imports"])
        self.assertIn("GetProcAddress", runtime["dynamic_resolution_imports"])
        self.assertEqual(report["analysis_workaround"]["protection_patching"], "not-performed")
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", str(path), "--anti-analysis-native"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("IsDebuggerPresent", json.loads(result.stdout)["debugger_api_imports"])

    def test_native_loader_reports_observed_horizon_runtime_exports(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.dll")
        if not path.exists():
            self.skipTest("supplied Horizon.dll is not available")
        contract = native_export_contract_report(path)
        self.assertEqual(contract["status"], "verified")
        self.assertEqual(contract["missing_exports"], [])

    def test_native_installation_inventory_is_read_only_and_reports_missing_x64_helper(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon")
        if not path.exists():
            self.skipTest("supplied Horizon installation is not available")
        report = native_installation_report(path)
        self.assertIn(report["status"], {"partial", "verified"})
        by_name = {item["name"]: item for item in report["images"]}
        self.assertEqual(by_name["Horizon.dll"]["status"], "verified")
        self.assertGreater(by_name["Horizon.dll"]["import_count"], 0)
        self.assertIn("KERNEL32.dll", by_name["Horizon.dll"]["imported_modules"])
        self.assertIn("IsDebuggerPresent", by_name["class3.dll"]["debugger_api_imports"])
        if not by_name["HVMRun64.dll"]["present"]:
            self.assertEqual(by_name["HVMRun64.dll"]["status"], "missing")

    def test_native_loader_reports_observed_hvm_runtime_exports(self):
        path = Path(r"C:\Program Files (x86)\Daring Development\Horizon\HVMRun64.dll")
        if not path.exists():
            self.skipTest("supplied HVMRun64.dll is not available")
        contract = native_export_contract_report(path)
        self.assertEqual(contract["status"], "verified")
        self.assertEqual(contract["missing_exports"], [])

    def test_account_codec_requires_provider_and_round_trips_provider_bytes(self):
        with self.assertRaises(NativeSaveUnavailable):
            AccountCodec(NativeSaveBinding()).decrypt(b"opaque", b"dev-key", 32)

    def test_account_codec_accepts_explicit_nonpersistent_key_provider(self):
        class SaveProvider:
            def rts_save_decrypt(self, input_buffer, output_length, output_buffer, input_length, key):
                output_buffer[:input_length] = input_buffer[:input_length]
                output_length.value = input_length
                return 0

            def rts_save_encrypt(self, input_buffer, output_buffer, input_length, key):
                output_buffer[:input_length] = input_buffer[:input_length]
                return 0

        class KeyProvider:
            def get_account_key(self, operation, payload_sha256):
                self.request = (operation, payload_sha256)
                return b"dev-key"

        provider = KeyProvider()
        codec = AccountCodec(NativeSaveBinding(SaveProvider()))
        self.assertEqual(codec.decrypt_with_key_provider(b"opaque", provider, 32), b"opaque")
        self.assertEqual(codec.decrypt_with_key_provider_raw(b"opaque", provider, 32), (0, b"opaque"))
        self.assertEqual(codec.decrypt_raw(b"opaque", b"dev-key", 32), (0, b"opaque"))
        self.assertEqual(provider.request[0], "decrypt")
        self.assertEqual(len(provider.request[1]), 64)
        with self.assertRaises(AccountKeyProviderUnavailable):
            codec.decrypt_with_key_provider(b"opaque", None, 32)

    def test_command_account_key_provider_requires_absolute_existing_helper(self):
        with self.assertRaises(ValueError):
            CommandAccountKeyProvider("key-vault-helper.exe")
        with self.assertRaises(FileNotFoundError):
            CommandAccountKeyProvider("C:\\does-not-exist\\key-vault-helper.exe")
        helper = self.fixture_dir / "key-vault-helper.exe"
        helper.write_bytes(b"placeholder")
        try:
            with self.assertRaises(ValueError):
                CommandAccountKeyProvider(helper, timeout=0)
        finally:
            helper.unlink(missing_ok=True)

        class Provider:
            def rts_save_decrypt(self, input_buffer, output_length, output_buffer, input_length, key):
                output_buffer[:input_length] = bytes(value ^ key[0] for value in input_buffer[:input_length])
                output_length.value = input_length
                return 0

            def rts_save_encrypt(self, input_buffer, output_buffer, input_length, key):
                output_buffer[:input_length] = bytes(value ^ key[0] for value in input_buffer[:input_length])
                return input_length

        class ProviderKey:
            def get_account_key(self, operation, payload_sha256):
                return b"dev-key"

        codec = AccountCodec(NativeSaveBinding(Provider()))
        status, raw_encrypted = codec.encrypt_raw(b"profile", b"dev-key", 32)
        self.assertEqual(status, 7)
        self.assertEqual(codec.encrypt_with_key_provider_raw(b"profile", ProviderKey(), 32)[0], 7)
        encrypted = codec.encrypt(b"profile", b"dev-key", 32, output_length=7)
        self.assertEqual(encrypted, raw_encrypted[:7])
        with self.assertRaises(ValueError):
            codec.encrypt(b"profile", b"dev-key", 32)
        self.assertEqual(codec.decrypt(encrypted, b"dev-key", 32), b"profile")

    def test_lzo_requires_explicit_provider_and_preserves_observed_shapes(self):
        binding = LzoBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(LzoUnavailable):
            binding.compress("lzo1x_1", b"in", 2, bytearray(8), Int32Ref(8), b"work")

        class Provider:
            def lzo1x_1_compress(self, source, source_length, destination, destination_length, work_memory):
                destination[:source_length] = source[:source_length]
                destination_length.value = source_length
                return 0

            def lzo2a_999_compress(self, *args):
                return 0

            def lzo1x_decompress(self, *args):
                return 0

            def lzo2a_decompress(self, *args):
                return 0

        bound = LzoBinding(Provider())
        output = bytearray(8)
        length = Int32Ref(8)
        self.assertEqual(bound.compress("lzo1x_1", b"in", 2, output, length, b"work"), 0)
        self.assertEqual(output[:2], b"in")
        self.assertEqual(length.value, 2)
        with self.assertRaises(LzoUnavailable):
            bound.version_string()
        with self.assertRaises(ValueError):
            bound.compress("unknown", b"in", 2, output, length, b"work")
        with self.assertRaises(ValueError):
            bound.compress("lzo1x_1", b"in", 3, output, length, b"work")

        codec = LzoCodec(bound)
        self.assertEqual(codec.compress("lzo1x_1", b"in", 8, b"work"), b"in")
        with self.assertRaises(LzoUnavailable):
            codec.version_string()
        with self.assertRaises(LzoUnavailable):
            LzoCodec(LzoBinding()).decompress("lzo1x", b"in", 8)

    def test_ctypes_lzo_provider_requires_explicit_absolute_dll_path(self):
        with self.assertRaises(ValueError):
            CtypesLzoProvider("lzo.dll")
        with self.assertRaises(FileNotFoundError):
            CtypesLzoProvider("C:\\does-not-exist\\lzo.dll")

    def test_x86_powershell_lzo_provider_round_trips_supplied_dll(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\lzo.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 LZO DLL or 32-bit PowerShell host is unavailable")
        provider = PowerShellLzoProvider(dll, host)
        source = b"Horizon-LZO-test-Horizon-LZO-test"
        work_memory = bytes(65536)
        compressed = bytearray(1024)
        compressed_length = Int32Ref(len(compressed))
        self.assertEqual(provider.lzo1x_1_compress(source, len(source), compressed, compressed_length, work_memory), 0)
        restored = bytearray(1024)
        restored_length = Int32Ref(len(restored))
        self.assertEqual(provider.lzo1x_decompress(bytes(compressed[:compressed_length.value]), compressed_length.value, restored, restored_length, work_memory), 0)
        self.assertEqual(bytes(restored[:restored_length.value]), source)
        self.assertTrue(provider.lzo_version_string())
        self.assertTrue(provider.lzo_version_date())

    def test_x86_powershell_lzo2a_provider_round_trips_with_observed_work_memory(self):
        dll = Path(r"C:\Program Files (x86)\Daring Development\Horizon\lzo.dll")
        host = Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not dll.exists() or not host.exists():
            self.skipTest("supplied x86 LZO DLL or 32-bit PowerShell host is unavailable")
        provider = PowerShellLzoProvider(dll, host)
        source = b"Horizon-LZO-2A-test-" * 8
        work_memory = bytes(262144)
        compressed = bytearray(4096)
        compressed_length = Int32Ref(len(compressed))
        self.assertEqual(provider.lzo2a_999_compress(source, len(source), compressed, compressed_length, work_memory), 0)
        restored = bytearray(len(source) * 2)
        restored_length = Int32Ref(len(restored))
        self.assertEqual(provider.lzo2a_decompress(bytes(compressed[:compressed_length.value]), compressed_length.value, restored, restored_length, work_memory), 0)
        self.assertEqual(bytes(restored[:restored_length.value]), source)
        with self.assertRaises(ValueError):
            provider.lzo2a_999_compress(source, len(source), bytearray(4096), Int32Ref(4096), bytes(65536))

    def test_reports_observed_embedded_resource_surface(self):
        surface = observed_resource_surface()
        self.assertEqual(surface["metadata_resource_record_count"], 206)
        self.assertEqual(surface["resource_count"], 205)
        self.assertEqual(surface["nonembedded_unresolved_count"], 1)
        self.assertEqual(surface["distinct_payload_hashes"], 30)

    def test_classifies_resource_payload_magic_without_execution(self):
        self.assertEqual(classify_resource_payload(b"\x89PNG\r\n\x1a\n"), "png")
        self.assertEqual(classify_resource_payload(b"\xce\xca\xef\xbe\x01"), "dotnet-resources")
        self.assertEqual(classify_resource_payload(b"unknown"), "binary")

    def test_extracts_safe_image_metadata_without_decoding_resource_payloads(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (320).to_bytes(4, "big") + (240).to_bytes(4, "big")
        self.assertEqual(resource_payload_metadata(png)["width"], 320)
        self.assertEqual(resource_payload_metadata(png)["height"], 240)
        gif = b"GIF89a" + (64).to_bytes(2, "little") + (32).to_bytes(2, "little")
        self.assertEqual(resource_payload_metadata(gif)["kind"], "gif")
        self.assertEqual(resource_payload_metadata(gif)["height"], 32)
        self.assertEqual(resource_payload_metadata(b"unknown")["kind"], "binary")

    def test_reports_dotnet_resource_index_metadata_without_deserializing_values(self):
        payload = (
            (0xBEEFCACE).to_bytes(4, "little")
            + (1).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )
        metadata = resource_payload_metadata(payload)
        self.assertEqual(metadata["kind"], "dotnet-resources")
        self.assertEqual(metadata["index_status"], "observed-index")
        self.assertEqual(metadata["resource_count"], 0)
        self.assertEqual(metadata["type_count"], 0)

    def test_parses_dotnet_resource_index_without_deserializing_values(self):
        payload = bytearray()
        payload += (0xBEEFCACE).to_bytes(4, "little")
        payload += (1).to_bytes(4, "little")
        payload += (0).to_bytes(4, "little")
        payload += (2).to_bytes(4, "little")
        payload += (1).to_bytes(4, "little")
        payload += (0).to_bytes(4, "little")
        payload += (0).to_bytes(4, "little")
        payload += (0).to_bytes(4, "little")
        payload += (9).to_bytes(4, "little")
        payload += b"\x04test"
        payload += (0).to_bytes(4, "little")
        payload += b"\x01\x01t\x00"
        report = parse_dotnet_resources(bytes(payload))
        self.assertEqual(report["status"], "observed-index")
        self.assertEqual(report["resource_count"], 1)
        self.assertEqual(report["resources"][0]["name"], "test")
        self.assertEqual(report["resources"][0]["data_length"], 4)
        self.assertEqual(report["resources"][0]["value"]["type_name"], "String")
        self.assertEqual(report["resources"][0]["value"]["value"], "t")

    def test_parses_empty_dotnet_resource_marker(self):
        payload = (
            (0xBEEFCACE).to_bytes(4, "little")
            + (1).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )
        report = parse_dotnet_resources(payload)
        self.assertEqual(report["status"], "observed-index")
        self.assertEqual(report["resource_count"], 0)
        self.assertEqual(report["resources"], [])

    def test_cli_parses_dotnet_resource_index(self):
        payload = bytearray()
        payload += (0xBEEFCACE).to_bytes(4, "little") + (1).to_bytes(4, "little") + (0).to_bytes(4, "little")
        payload += (2).to_bytes(4, "little") + (1).to_bytes(4, "little") + (0).to_bytes(4, "little")
        payload += (0).to_bytes(4, "little") + (0).to_bytes(4, "little") + (9).to_bytes(4, "little")
        payload += b"\x04test" + (0).to_bytes(4, "little") + b"\x01\x01t\x00"
        path = self.fixture_dir / "synthetic.resources"
        path.write_bytes(payload)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", "--dotnet-resource-index", str(path)],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(json.loads(result.stdout)["resources"][0]["name"], "test")
        finally:
            path.unlink(missing_ok=True)

    def test_cli_exports_observed_resource_surface(self):
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", "--resource-surface", "unused"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["resource_count"], 205)

    def test_queries_exported_resource_inventory_without_copying_payloads(self):
        path = self.fixture_dir / "resource-bundle.json"
        path.write_text(json.dumps({
            "records": [{
                "operation": "inspect_managed_artifact",
                "evidence_id": "ev-resource",
                "normalized_result": {
                    "artifact": {"path": "Horizon.exe"},
                    "coverage": {"state": "partial"},
                    "resources": [
                        {"name": "A.ui.resources", "declared_offset": 4, "data_length": 8, "data_sha256": "abc", "embedded": True, "visibility": "public"},
                        {"name": "A.other.resources", "declared_offset": 12, "data_length": 3, "data_sha256": "def", "embedded": True, "visibility": "private"},
                    ],
                },
            }],
        }), encoding="utf-8")
        try:
            report = resource_surface_report(path, "ui")
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(report["counts"], {"matched": 1, "total": 2})
        self.assertEqual(report["resources"][0]["data_sha256"], "abc")

    def test_verifies_shipped_managed_resource_hashes_against_rea_bundle(self):
        executable = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.exe")
        bundle = Path("work/rea-managed-members-latest.json")
        if not executable.exists() or not bundle.exists():
            self.skipTest("supplied Horizon.exe and retained REA bundle are not available")
        report = verify_managed_resource_payloads(executable, bundle, "A\\.c298")
        self.assertEqual(report["counts"], {"verified": 1, "unresolved": 0})
        self.assertEqual(report["resources"][0]["status"], "verified")

    def test_verifies_all_embedded_managed_resource_hashes(self):
        executable = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.exe")
        bundle = Path("work/rea-managed-members-latest.json")
        if not executable.exists() or not bundle.exists():
            self.skipTest("supplied Horizon.exe and retained REA bundle are not available")
        report = verify_managed_resource_payloads(executable, bundle)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"], {"verified": 205, "unresolved": 1})
        self.assertEqual(sum(item["status"] == "verified" for item in report["resources"]), 205)

    def test_extracts_uniquely_verified_managed_resource_payload(self):
        executable = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.exe")
        bundle = Path("work/rea-managed-members-latest.json")
        if not executable.exists() or not bundle.exists():
            self.skipTest("supplied Horizon.exe and retained REA bundle are not available")
        directory_path = Path("work/.test-resource-output")
        shutil.rmtree(directory_path, ignore_errors=True)
        try:
            directory = str(directory_path)
            report = extract_managed_resource_payloads(executable, bundle, directory, "A\\.c298")
            self.assertEqual(report["counts"], {"extracted": 1, "unresolved": 0})
            output = Path(report["resources"][0]["path"])
            self.assertTrue(output.is_file())
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), report["resources"][0]["sha256"])
        finally:
            shutil.rmtree(directory_path, ignore_errors=True)

    def test_cli_extracts_resources_when_bundle_is_also_supplied(self):
        executable = Path(r"C:\Program Files (x86)\Daring Development\Horizon\Horizon.exe")
        bundle = Path("work/rea-managed-members-latest.json")
        if not executable.exists() or not bundle.exists():
            self.skipTest("supplied Horizon.exe and retained REA bundle are not available")
        directory_path = Path("work/.test-resource-cli-output")
        shutil.rmtree(directory_path, ignore_errors=True)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "work.horizon_clone", str(executable),
                 "--resource-bundle", str(bundle), "--resource-pattern", "A\\.c298",
                 "--extract-resources", str(directory_path)],
                check=True, capture_output=True, text=True,
            )
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"], {"extracted": 1, "unresolved": 0})
            self.assertTrue(Path(report["resources"][0]["path"]).is_file())
        finally:
            shutil.rmtree(directory_path, ignore_errors=True)

    def test_exports_observed_title_catalogs(self):
        self.assertIn("EntryID", catalog_report("gears"))
        self.assertEqual(gears_entry_id_values()["SyncID"], 1)
        self.assertEqual(resolve_gears_entry_id("SyncID"), 1)
        self.assertEqual(validate_gears_entry_ids({"SyncID": 1}), {"SyncID": 1})
        with self.assertRaises(ValueError):
            validate_gears_entry_ids({"SyncID": 2})
        self.assertTrue(catalog_report("gears")["summary"]["constant_values_observed"])
        self.assertEqual(len(catalog_report("halo")["types"]), 103)
        self.assertEqual(len(catalog_report("halo")["property_names"]), 140)
        self.assertEqual(halo_general_class_field_types("GameVariant")["c7a62e9b2608ab1560f963117c637c401"], "i4")
        field = "c7a62e9b2608ab1560f963117c637c401"
        self.assertEqual(validate_halo_metadata_values("GameVariant", {field: 7})[field], 7)
        with self.assertRaises(ValueError):
            validate_halo_metadata_values("GameVariant", {field: 0x1_0000_0000})
        array_field = next(name for name, kind in halo_general_class_field_types("Halo4MegaloEngineVariant").items() if kind == "i4[]")
        self.assertEqual(validate_halo_metadata_values("Halo4MegaloEngineVariant", {array_field: [1, -2]})[array_field], [1, -2])
        self.assertIn("ShoutEnums", catalog_report("skyrim"))
        self.assertEqual(catalog_report("skyrim")["values"]["ShoutEnums"]["AnimalAllegiance"], 392311)
        self.assertEqual(resolve_skyrim_enum_member("ShoutEnums", "AnimalAllegiance"), 392311)
        self.assertEqual(validate_skyrim_enum_values("ShoutEnums", {"AnimalAllegiance": 392311}), {"AnimalAllegiance": 392311})
        with self.assertRaises(ValueError):
            validate_skyrim_enum_values("ShoutEnums", {"AnimalAllegiance": 0})
        self.assertIn("SaveEntryCategory", catalog_report("shared"))

    def test_exposes_global_namespace_rows_without_merging_duplicates(self):
        rows = observed_global_types()
        self.assertEqual(len(rows), 35)
        self.assertEqual(sum(item.field_count for item in rows), 5274)
        self.assertEqual(sum(item.method_count for item in rows), 81)
        self.assertEqual([item.field_count for item in rows if item.name == "Helmet"], [65, 87])
        self.assertEqual([item.field_count for item in rows if item.name == "Weapon"], [11, 38])
        report = global_catalog_report()
        self.assertEqual(report["observed_namespace_type_count"], 632)
        self.assertTrue(report["values_observed"])
        self.assertEqual(report["values"]["XGearSlot"]["Pants"], 13)
        self.assertEqual(report["values"]["GeneralContentTypes"]["Title_Updates"], 7)
        self.assertEqual(report["values"]["DifficultyOption"]["Hard"], 2)
        self.assertEqual(report["values"]["XOnlineLanguage"]["Japanese"], 2)
        self.assertEqual(catalog_report("global")["status"], "catalog-only")

    def test_editor_registry_dispatches_xdbf_plugins(self):
        registry = default_registry()
        plugin = registry.resolve(EditorContext(filename="profile.gpd"), b"XDBF\x00")
        self.assertIsInstance(plugin, XdbfEditor)
        self.assertEqual(registry.names(), ("XDBF/GPD editor", "REA managed schema", "REA managed surface", "Opaque Account editor", "ProfileData metadata editor", "Halo metadata editor", "Authenticated Constant catalog editor", "Legacy catalog editor"))
        managed = json.dumps({"records": [{"operation": "inspect_managed_members", "normalized_result": {"artifact": {}, "types": [], "fields": [], "methods": []}}]}).encode()
        managed_plugin = registry.resolve(EditorContext(filename="rea.json"), managed)
        self.assertIsInstance(managed_plugin, ManagedSurfaceEditor)
        self.assertEqual(managed_plugin.inspect(EditorContext(), managed)["status"], "observed-only")
        schema_plugin = registry.resolve(EditorContext(filename="rea.managed-schema.json"), managed)
        self.assertIsInstance(schema_plugin, ManagedSchemaEditor)
        self.assertEqual(schema_plugin.inspect(EditorContext(), managed)["status"], "observed-only")
        account = registry.resolve(EditorContext(filename="Account"), b"opaque")
        self.assertIsInstance(account, AccountEditor)
        self.assertEqual(account.inspect(EditorContext(filename="Account"), b"opaque")["status"], "opaque")
        self.assertEqual(account.replace_same_size(b"opaque", b"edited"), b"edited")
        with self.assertRaises(ValueError):
            account.replace_same_size(b"opaque", b"too-long")
        halo = json.dumps({
            "editor": "halo-metadata",
            "type_name": "GameVariant",
            "values": {"c7a62e9b2608ab1560f963117c637c401": 1},
        }).encode()
        halo_plugin = registry.resolve(EditorContext(filename="variant.json"), halo)
        self.assertIsInstance(halo_plugin, HaloMetadataEditor)
        self.assertEqual(halo_plugin.inspect(EditorContext(), halo)["status"], "metadata-only")
        edited = json.loads(halo_plugin.edit_values(halo, {"c7a62e9b2608ab1560f963117c637c401": 2}))
        self.assertEqual(edited["values"]["c7a62e9b2608ab1560f963117c637c401"], 2)
        constant = json.dumps({"editor": "constant-catalog", "catalog": "skyrim:ShoutEnums", "values": {"AnimalAllegiance": 392311}}).encode()
        constant_plugin = registry.resolve(EditorContext(filename="constants.json"), constant)
        self.assertIsInstance(constant_plugin, ConstantCatalogEditor)
        self.assertEqual(constant_plugin.inspect(EditorContext(), constant)["status"], "metadata-only")
        legacy = json.dumps({
            "editor": "legacy-catalog",
            "catalog": "Bandai:DBXVAttributes",
            "values": {"MaxHealth": 100, "KiBlastSupers": 7},
        }).encode()
        legacy_plugin = registry.resolve(EditorContext(filename="legacy.json"), legacy)
        self.assertIsInstance(legacy_plugin, LegacyCatalogEditor)
        self.assertEqual(legacy_plugin.inspect(EditorContext(), legacy)["status"], "metadata-only")
        with self.assertRaises(ValueError):
            legacy_plugin.edit_values(legacy, {"not_observed": 1})
        profile_data = json.dumps({
            "editor": "profile-data",
            "values": {
                "from_device": True,
                "xuid": 0x0123456789ABCDEF,
                "gamertag": "Test User",
                "gamer_picture": "0102",
                "profile_id": 0xE9ECC9141E317C7B,
                "favorite": True,
            },
        }).encode()
        profile_plugin = registry.resolve(EditorContext(filename="profile.json"), profile_data)
        self.assertIsInstance(profile_plugin, ProfileDataEditor)
        self.assertEqual(profile_plugin.inspect(EditorContext(), profile_data)["status"], "metadata-only")
        with self.assertRaises(ValueError):
            registry.register(XdbfEditor())

        custom = EditorRegistry()
        self.assertIsNone(custom.resolve(EditorContext(), b"NOPE"))

    def test_mutates_fixed_width_stfs_metadata(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = mutate_stfs_metadata(
            original,
            display_name="Edited Profile",
            display_description="Edited Description",
            publisher_name="Publisher",
            title_name="Title",
            transfer_flags=0xA5,
            title_id=0x12345678,
            header=header,
        )
        parsed = parse_stfs_header(mutated)
        self.assertEqual(parsed.display_name, "Edited Profile")
        self.assertEqual(parsed.display_description, "Edited Description")
        self.assertEqual(parsed.publisher_name, "Publisher")
        self.assertEqual(parsed.title_name, "Title")
        self.assertEqual(parsed.transfer_flags, 0xA5)
        self.assertEqual(parsed.title_id, 0x12345678)
        self.assertTrue(verify_stfs_hashes(mutated, header=parsed)["header_hash_matches"])

    def test_reads_and_mutates_bounded_stfs_thumbnails(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        thumbnails = parse_stfs_thumbnails(original, header)
        self.assertEqual(thumbnails.thumbnail_size, header.thumbnail_size)
        self.assertEqual(thumbnails.title_thumbnail_size, header.title_thumbnail_size)
        mutated = mutate_stfs_thumbnails(original, thumbnail=b"thumbnail-test", header=header)
        parsed = parse_stfs_thumbnails(mutated, parse_stfs_header(mutated))
        self.assertEqual(parsed.thumbnail, b"thumbnail-test")
        self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])

    def test_metadata_version_two_uses_reduced_thumbnail_capacity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        payload = b"T" * 0x3D00
        edited = mutate_stfs_thumbnails(original, thumbnail=payload, title_thumbnail=payload)
        thumbnails = parse_stfs_thumbnails(edited, parse_stfs_header(edited))
        self.assertEqual(thumbnails.thumbnail, payload)
        self.assertEqual(thumbnails.title_thumbnail, payload)
        with self.assertRaises(ValueError):
            mutate_stfs_thumbnails(original, thumbnail=b"T" * 0x3D01)

    def test_inspects_stfs_security_metadata_without_claiming_signature_validity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        metadata = parse_stfs_security_metadata(path.read_bytes())
        self.assertEqual(metadata.signature_kind, "console-certificate")
        self.assertEqual(len(metadata.licenses), 16)
        self.assertEqual((metadata.certificate_signature_offset, metadata.certificate_signature_length), (0xAC, 0x100))
        self.assertEqual((metadata.package_signature_offset, metadata.package_signature_length), (0x1AC, 0x80))
        self.assertIsNotNone(metadata.package_signature_sha256)
        regions = stfs_signature_region_report(path.read_bytes())
        self.assertEqual(regions["status"], "metadata-only")
        self.assertEqual([item["name"] for item in regions["regions"]], ["certificate-signature", "package-signature"])
        self.assertEqual(regions["public_key"]["exponent"], 65537)
        key = extract_stfs_public_key(path.read_bytes())
        self.assertEqual(key.exponent, 65537)
        self.assertLessEqual(key.modulus.bit_length(), 1024)
        self.assertGreater(key.modulus.bit_length(), 1000)
        self.assertTrue(metadata.header_sha1_matches)
        self.assertEqual(len(metadata.header_sha1), 40)
        self.assertIsNotNone(metadata.public_modulus_sha256)

    def test_verifies_observed_con_signature_layout_without_claiming_validity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        result = verify_stfs_console_signature(path.read_bytes())
        self.assertEqual(result["algorithm"], "RSA-SHA1-XeCrypt-PKCS1v1.5")
        self.assertEqual((result["signature_offset"], result["signature_length"]), (0x1AC, 0x80))
        self.assertEqual((result["signed_start"], result["signed_end"]), (0x22C, 0x344))
        self.assertTrue(result["verified"])

    def test_rejects_remote_signature_verification_for_console_packages(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        with self.assertRaises(ValueError):
            verify_stfs_remote_signature(path.read_bytes(), 257, 3)

    def test_rejects_remote_signing_for_console_packages(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")

        class Provider:
            def sign_sha1(self, message):
                return b"signature"

        with self.assertRaises(ValueError):
            sign_stfs_remote_package_with_provider(
                path.read_bytes(), Provider(), RsaPublicKey(1 << 2047, 65537)
            )

    def test_cli_exposes_remote_package_signing(self):
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("--sign-stfs-remote-package", result.stdout)

    def test_package_signing_requires_matching_explicit_private_key(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        with self.assertRaises(ValueError):
            sign_stfs_console_package(path.read_bytes(), RsaPrivateKey(1, 1))

    def test_package_signing_accepts_external_sha1_provider(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        stored = original[0x1AC:0x22C]

        class Provider:
            def __init__(self):
                self.messages = []

            def sign_sha1(self, message):
                self.messages.append(message)
                return stored[::-1]

        provider = Provider()
        signed = sign_stfs_console_package_with_provider(original, provider)
        self.assertEqual(signed, original)
        self.assertEqual(len(provider.messages), 1)
        self.assertTrue(verify_stfs_console_signature(signed)["verified"])

    def test_xecrypt_signer_rejects_short_rsa_modulus(self):
        with self.assertRaises(ValueError):
            LocalRsaSha1Signer(RsaPrivateKey(0x80, 3)).sign_sha1(b"test")

    def test_builds_canonical_profile_fatx_path(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        header = parse_stfs_header(path.read_bytes())
        self.assertEqual(stfs_magic_filename(header), "E9ECC9141E317C7B")
        self.assertEqual(
            stfs_fatx_device_path(header),
            "Content\\E9ECC9141E317C7B\\FFFE07D1\\00010000\\E9ECC9141E317C7B",
        )

    def test_parses_metadata_version_two_series_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        header = parse_stfs_header(path.read_bytes())
        self.assertEqual(header.metadata_version, 2)
        self.assertEqual(header.series_id, "00" * 16)
        self.assertEqual(header.season_id, "00" * 16)
        self.assertEqual(header.season_number, 0)
        self.assertEqual(header.episode_number, 0)
        self.assertEqual(len(header.additional_display_names), 6)
        self.assertEqual(len(header.additional_display_descriptions), 6)

    def test_mutates_metadata_version_two_series_fields(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        edited = mutate_stfs_metadata(
            original,
            series_id="00112233445566778899aabbccddeeff",
            season_id="ffeeddccbbaa99887766554433221100",
            season_number=3,
            episode_number=7,
            additional_display_names=("Localized title",),
            additional_display_descriptions=("Localized description",),
        )
        header = parse_stfs_header(edited)
        self.assertEqual(header.series_id, "00112233445566778899aabbccddeeff")
        self.assertEqual(header.season_id, "ffeeddccbbaa99887766554433221100")
        self.assertEqual((header.season_number, header.episode_number), (3, 7))
        self.assertEqual(header.additional_display_names[0], "Localized title")
        self.assertEqual(header.additional_display_descriptions[0], "Localized description")
        self.assertEqual(verify_stfs_hashes(edited, header=header)["failures"], [])

    def test_json_report_includes_content_type_name(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        report = _json_report(inspect(path))
        self.assertEqual(report["stfs_header"]["content_type"], 0x00010000)
        self.assertEqual(report["stfs_header"]["content_type_name"], "Profile")

    def test_desktop_source_exposes_content_type_label(self):
        source = Path(__file__).parents[1].joinpath("work", "horizon_app.py").read_text(encoding="utf-8")
        self.assertIn('header_details["content_type_name"]', source)

    def test_labels_observed_and_unknown_stfs_content_types(self):
        self.assertEqual(stfs_content_type_name(0x00010000), "Profile")
        self.assertEqual(stfs_content_type_name(0x000E0000), "XNA")
        self.assertEqual(stfs_content_type_name(0x00001000), "IPTVDVR")
        self.assertEqual(stfs_content_type_name(0x00006000), "SocialTitle")
        self.assertEqual(stfs_content_type_name(0x02000000), "CommunityGame")
        self.assertEqual(stfs_content_type_name(0x12345678), "Unknown")
        with self.assertRaises(ValueError):
            stfs_content_type_name(-1)

    def test_derives_observed_non_profile_magic_filenames(self):
        header = parse_stfs_header(supplied_fixture().read_bytes()) if supplied_fixture() else None
        if header is None:
            self.skipTest("supplied STFS profile fixture is not available")
        content_id = "00112233445566778899aabbccddeeff0011223344556677"
        replacement = dataclasses.replace(
            header,
            content_type=0x00007000,
            content_id=content_id,
            title_id=0x12345678,
        )
        self.assertEqual(stfs_magic_filename(replacement), "00112233445566778899AABBCCDDEEFF12")
        installer = dataclasses.replace(replacement, content_type=0x000B0000, execution_version=0x01020304)
        self.assertEqual(stfs_magic_filename(installer), "tu01020304_0")
        avatar = dataclasses.replace(
            replacement,
            content_type=0x00009000,
            avatar_asset_id="8899aabbccddeeff0011223344556677",
        )
        self.assertEqual(stfs_magic_filename(avatar), "8899AABBCCDDEEFF0011223344556677")

    def test_compares_stfs_mutations_without_claiming_console_validity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        mutated = bytearray(original)
        mutated[0x300] ^= 0x01
        report = stfs_signature_mutation_report(original, bytes(mutated))
        self.assertEqual(report["status"], "metadata-only")
        self.assertTrue(report["same_length"])
        self.assertGreater(report["changed_outside_signature_regions"], 0)
        self.assertTrue(report["stored_signature_bytes_unchanged"])
        self.assertFalse(report["console_validity_checked"])
        self.assertTrue(report["package_signature_checked"])
        self.assertTrue(report["original_package_signature"]["verified"])
        self.assertFalse(report["mutated_package_signature_verified"])
        self.assertTrue(report["hash_tree"]["verified"])
        self.assertEqual(report["hash_tree"]["failures"], [])

    def test_repacks_entry_with_a_different_size(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        replacement = b"expanded-account" * 400
        mutated = repack_stfs_entries(original, {"Account": replacement}, header)
        entries = list_stfs_entries(mutated, parse_stfs_header(mutated))
        account = next(item for item in entries if item.path == "Account")
        self.assertEqual(read_stfs_entry(mutated, account), replacement)
        self.assertEqual(account.block_count, 2)
        self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])

    def test_repacks_same_size_entry_preserving_authenticated_payload(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "Account")
        payload = bytearray(read_stfs_entry(original, entry, header))
        payload[0] ^= 0x01
        mutated = repack_stfs_entries(original, {entry.path: bytes(payload)}, header)
        mutated_header = parse_stfs_header(mutated)
        mutated_entry = next(item for item in list_stfs_entries(mutated, mutated_header) if item.path == entry.path)
        self.assertEqual(read_stfs_entry(mutated, mutated_entry, mutated_header), bytes(payload))
        self.assertEqual(verify_stfs_hashes(mutated, header=mutated_header)["failures"], [])

    def test_adds_a_file_using_existing_table_and_block_capacity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        payload = b"new profile-sidecar" * 20
        mutated = repack_stfs_entries(original, {}, additions={"sidecar.bin": payload})
        header = parse_stfs_header(mutated)
        entry = next(item for item in list_stfs_entries(mutated, header) if item.path == "sidecar.bin")
        self.assertEqual(read_stfs_entry(mutated, entry, header), payload)
        self.assertEqual(verify_stfs_hashes(mutated, header=header)["failures"], [])
        self.assertEqual(verify_stfs_hashes(mutated, header=header)["hash_table_failures"], [])

    def test_removes_a_file_table_entry(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        mutated = repack_stfs_entries(original, {}, remove=("Account",))
        entries = list_stfs_entries(mutated, parse_stfs_header(mutated))
        self.assertNotIn("Account", {item.path for item in entries})
        self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])

    def test_removes_non_empty_stfs_directory_only_in_explicit_tree_mode(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        self.assertTrue(any(item.path.startswith("cache/") for item in list_stfs_entries(original, header)))
        with self.assertRaises(IsADirectoryError):
            repack_stfs_entries(original, {}, remove=("cache",), header=header)
        mutated = repack_stfs_entries(
            original, {}, remove=("cache",), remove_descendants=True, header=header,
        )
        entries = list_stfs_entries(mutated, parse_stfs_header(mutated))
        self.assertNotIn("cache", {item.path for item in entries})
        self.assertFalse(any(item.path.startswith("cache/") for item in entries))
        self.assertEqual(verify_stfs_hashes(mutated, header=parse_stfs_header(mutated))["failures"], [])


if __name__ == "__main__":
    unittest.main()

