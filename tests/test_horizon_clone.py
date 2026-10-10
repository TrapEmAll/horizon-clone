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
from work.skyrim_catalog import enum_member_names, observed_skyrim_enums
from work.horizon_catalog import catalog_member_names, observed_catalogs
from work.observed_members import observed_fields, observed_profile_data_fields
from work.editor_inventory import inventory_summary, observed_editor_inventory


def supplied_fixture():
    value = os.environ.get("HORIZON_PROFILE_FIXTURE")
    return Path(value) if value else None


class ContainerInspectionTests(unittest.TestCase):
    fixture_dir = Path(__file__).parent / ".tmp"

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
            profile_id=bytes.fromhex("e9ecc9141e317c7b"),
            favorite=True,
        )
        self.assertEqual(ProfileData.from_dict(profile.to_dict()), profile)

    def test_exposes_observed_skyrim_enum_names_without_guessing_values(self):
        enums = observed_skyrim_enums()
        self.assertEqual({item.name for item in enums}, {"ShoutEnums", "PerkEnums", "MagicEnums"})
        self.assertEqual(len(enum_member_names("ShoutEnums")), 27)
        self.assertFalse(any(item.values_observed for item in enums))

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

    def test_reports_aggregate_title_editor_inventory(self):
        inventory = observed_editor_inventory()
        self.assertEqual(
            {item.name: item.observed_type_count for item in inventory},
            {"Skyrim": 3, "Gears of War 3": 1, "Halo general classes": 103},
        )
        summary = inventory_summary()
        self.assertEqual(summary["managed_type_count"], 7693)
        self.assertTrue(all(item["implementation_status"] == "catalog-only" for item in summary["editors"]))

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

