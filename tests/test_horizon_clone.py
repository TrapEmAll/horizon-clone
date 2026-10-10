import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from work.horizon_clone import (
    inspect,
    list_stfs_entries,
    list_embedded_xdbf,
    summarize_embedded_xdbf,
    list_embedded_achievements,
    rename_stfs_entry,
    add_stfs_directory,
    move_stfs_entry,
    mutate_stfs_entry_same_size,
    mutate_stfs_metadata,
    mutate_stfs_thumbnails,
    mutate_xdbf_achievement,
    mutate_xdbf_text,
    repack_xdbf_entries,
    repack_stfs_entries,
    rehash_stfs_hashes,
    mutate_xdbf_entry_same_size,
    parse_stfs_header,
    parse_stfs_security_metadata,
    parse_stfs_thumbnails,
    parse_xdbf,
    xdbf_payload_surface,
    read_stfs_entry,
    verify_stfs_hashes,
)
from work.signing import (
    DetachedSignature,
    RsaPublicKey,
    SignedRegion,
    sign_region,
    sign_with_provider,
    verify_region,
    verify_sha256_pkcs1v15,
)
from work.profile_model import ProfileData
from work.editors import EditorContext, EditorRegistry, XdbfEditor, default_registry
from work.skyrim_catalog import enum_member_names, enum_member_values, observed_skyrim_enum_summary, observed_skyrim_enums
from work.horizon_catalog import catalog_member_names, observed_catalogs
from work.gears_catalog import gears_entry_id_summary, gears_of_war_3_entry_ids
from work.halo_catalog import halo_general_class_field_counts, halo_general_class_method_summary, halo_general_class_property_names, halo_general_class_types
from work.resource_inventory import observed_resource_surface
from work.observed_members import observed_fields, observed_profile_data_fields, observed_profile_data_methods
from work.editor_inventory import capability_report, catalog_report, inventory_summary, observed_editor_inventory
from work.legacy_catalog import legacy_catalog_report, legacy_field_names, observed_legacy_catalogs
from work.global_catalog import global_catalog_report, observed_global_types
from work.native_surface import native_surface_report, observed_native_imports, observed_native_callers
from work.device_surface import device_surface_report, observed_device_members
from work.device_binding import DeviceBinding, DeviceProviderUnavailable
from work.native_runtime import NativeRuntimeBinding, NativeRuntimeUnavailable
from work.native_save import NativeSaveBinding, NativeSaveUnavailable, UInt32Ref
from work.native_compression import Int32Ref, LzoBinding, LzoUnavailable
from work.horizon_app import HorizonApp, _atomic_write_bytes, _atomic_write_text
from work.managed_surface import managed_surface_report


def supplied_fixture():
    value = os.environ.get("HORIZON_PROFILE_FIXTURE")
    return Path(value) if value else None


class ContainerInspectionTests(unittest.TestCase):
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

    def test_desktop_exposes_bulk_gpd_summary_export(self):
        self.assertTrue(hasattr(HorizonApp, "export_gpd_summary"))

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
        name = "Old".encode("utf-16-le") + b"\x00\x00"
        payload = bytearray(0x18 + len(name))
        payload[4:8] = (10).to_bytes(4, "little")
        payload[8:12] = (20).to_bytes(4, "little")
        payload[12:16] = (5).to_bytes(4, "little", signed=True)
        payload[16:20] = (1).to_bytes(4, "little")
        payload[0x18:] = name
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
        self.assertEqual(len(summaries), 67)
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

    def test_exposes_observed_gears_entry_id_names_without_guessing_values(self):
        entries = gears_of_war_3_entry_ids()
        self.assertGreater(len(entries), 1000)
        self.assertIn("Selected_COG_Character", entries)
        self.assertIn("Horde_Sentry_Level_7", entries)
        summary = gears_entry_id_summary()
        self.assertEqual(summary["declaring_type"], "Horizon.PackageEditors.Gears_of_War_3.EntryID")
        self.assertEqual(summary["named_member_count"], len(entries))
        self.assertFalse(summary["constant_values_observed"])

    def test_exposes_observed_halo_general_class_names_without_guessing_layouts(self):
        types = halo_general_class_types()
        self.assertEqual(len(types), 103)
        self.assertIn("GameVariant", types)
        self.assertIn("Halo4PlayerTraits", types)
        self.assertIn("HMegaloStrings", types)
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

    def test_exposes_observed_shared_horizon_catalog_names_without_guessing_values(self):
        catalogs = observed_catalogs()
        self.assertEqual(
            {item.name for item in catalogs},
            {"ProfileLoadout", "SaveEntryCategory"},
        )
        self.assertEqual(catalog_member_names("ProfileLoadout"), ("All_Loadouts",))
        self.assertIn("Campaign_Level", catalog_member_names("SaveEntryCategory"))
        self.assertFalse(any(item.values_observed for item in catalogs))

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
        self.assertEqual(by_name["ProfileData contract"]["status"], "metadata-only")
        self.assertEqual(by_name["Account serialization"]["status"], "unresolved")
        self.assertIn("no managed Account type", by_name["Account serialization"]["evidence"])
        self.assertEqual(by_name["Console signing"]["status"], "provider-boundary")
        self.assertEqual(by_name["Native save/runtime boundaries"]["status"], "provider-boundary")
        self.assertIn("NativeSaveBinding", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("LzoBinding", by_name["Native save/runtime boundaries"]["entry_points"])
        self.assertIn("--resource-surface", by_name["Embedded UI/resource surface"]["entry_points"])

    def test_reports_observed_native_save_and_runtime_boundaries(self):
        surface = native_surface_report()
        self.assertEqual(surface["status"], "declaration-only")
        self.assertEqual(surface["observed_module_ref_count"], 14)
        self.assertEqual(surface["observed_pinvoke_count"], 54)
        imports = {(item.module, item.import_name) for item in observed_native_imports()}
        self.assertIn(("class3.dll", "RtsSaveEncrypt"), imports)
        self.assertIn(("class3.dll", "RtsSaveDecrypt"), imports)
        self.assertIn(("Horizon.dll", "RunHVM"), imports)
        self.assertIn(("Horizon.dll", "GetUserString"), imports)
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

    def test_reports_observed_device_exploration_surface(self):
        surface = device_surface_report()
        self.assertEqual(surface["status"], "metadata-only")
        members = {(item.declaring_type, item.name) for item in observed_device_members()}
        self.assertIn(("A.c0353b6b5ff8fecef988e28ba8b350fd5", "get_DeviceSize"), members)
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

    def test_native_runtime_requires_explicit_provider(self):
        binding = NativeRuntimeBinding()
        self.assertEqual(binding.status, "unavailable")
        with self.assertRaises(NativeRuntimeUnavailable):
            binding.check_runtime()

        class Provider:
            def check_runtime(self):
                return True

            def run_hvm(self):
                return 7

            def get_user_string(self, arg0, arg1, arg2):
                return arg0 + arg1 + arg2

        bound = NativeRuntimeBinding(Provider())
        self.assertEqual(bound.status, "provider-bound")
        self.assertTrue(bound.check_runtime())
        self.assertEqual(bound.run_hvm(), 7)
        self.assertEqual(bound.get_user_string(1, 2, 3), 6)

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
        with self.assertRaises(ValueError):
            bound.compress("unknown", b"in", 2, output, length, b"work")
        with self.assertRaises(ValueError):
            bound.compress("lzo1x_1", b"in", 3, output, length, b"work")

    def test_reports_observed_embedded_resource_surface(self):
        surface = observed_resource_surface()
        self.assertEqual(surface["metadata_resource_record_count"], 206)
        self.assertEqual(surface["resource_count"], 205)
        self.assertEqual(surface["nonembedded_unresolved_count"], 1)
        self.assertEqual(surface["distinct_payload_hashes"], 30)

    def test_cli_exports_observed_resource_surface(self):
        result = subprocess.run(
            [sys.executable, "-m", "work.horizon_clone", "--resource-surface", "unused"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["resource_count"], 205)

    def test_exports_observed_title_catalogs(self):
        self.assertIn("EntryID", catalog_report("gears"))
        self.assertEqual(len(catalog_report("halo")["types"]), 103)
        self.assertEqual(len(catalog_report("halo")["property_names"]), 140)
        self.assertIn("ShoutEnums", catalog_report("skyrim"))
        self.assertEqual(catalog_report("skyrim")["values"]["ShoutEnums"]["AnimalAllegiance"], 392311)
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
        self.assertFalse(report["values_observed"])
        self.assertEqual(catalog_report("global")["status"], "catalog-only")

    def test_editor_registry_dispatches_xdbf_plugins(self):
        registry = default_registry()
        plugin = registry.resolve(EditorContext(filename="profile.gpd"), b"XDBF\x00")
        self.assertIsInstance(plugin, XdbfEditor)
        self.assertEqual(registry.names(), ("XDBF/GPD editor",))
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

    def test_inspects_stfs_security_metadata_without_claiming_signature_validity(self):
        path = supplied_fixture()
        if path is None or not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        metadata = parse_stfs_security_metadata(path.read_bytes())
        self.assertEqual(metadata.signature_kind, "console-certificate")
        self.assertEqual(len(metadata.licenses), 16)
        self.assertIsNotNone(metadata.package_signature_sha256)
        self.assertTrue(metadata.header_sha1_matches)
        self.assertEqual(len(metadata.header_sha1), 40)
        self.assertIsNotNone(metadata.public_modulus_sha256)

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


if __name__ == "__main__":
    unittest.main()

