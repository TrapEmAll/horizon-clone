import hashlib
import unittest
from pathlib import Path

from work.horizon_clone import (
    inspect,
    list_stfs_entries,
    mutate_stfs_entry_same_size,
    mutate_stfs_metadata,
    mutate_xdbf_entry_same_size,
    parse_stfs_header,
    parse_xdbf,
    read_stfs_entry,
    verify_stfs_hashes,
)
from work.signing import RsaPublicKey, sign_with_provider, verify_sha256_pkcs1v15
from work.profile_model import ProfileData


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
        data = header + entry + b"\x00" * 8 + payload

        parsed = parse_xdbf(data)

        self.assertEqual(data_base, 50)
        self.assertEqual(parsed[0].namespace, 5)
        self.assertEqual(parsed[0].text, "Dashboard")
        mutated = mutate_xdbf_entry_same_size(
            data, parsed[0], "Settings!".encode("utf-16-be") + b"\x00\x00"
        )
        self.assertEqual(parse_xdbf(mutated)[0].text, "Settings!")

        with self.assertRaises(ValueError):
            mutate_xdbf_entry_same_size(data, parsed[0], b"short")

    def test_mutates_and_rehashes_supplied_profile_fixture(self):
        path = Path(r"C:\Users\sjisg\Desktop\E9ECC9141E317C7B")
        if not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        entry = next(item for item in list_stfs_entries(original, header) if item.path == "Account")
        replacement = b"\x00" * entry.size

        mutated = mutate_stfs_entry_same_size(original, entry, replacement, header)

        self.assertEqual(read_stfs_entry(mutated, entry, header), replacement)
        result = verify_stfs_hashes(mutated, entry, header)
        self.assertEqual(result["failures"], [])
        self.assertTrue(result["header_hash_matches"])
        self.assertFalse(result["signature_checked"])

    def test_signing_provider_boundary_rejects_empty_signatures(self):
        class EmptyProvider:
            def sign_sha256(self, message):
                return b""

        with self.assertRaises(ValueError):
            sign_with_provider(b"test vector", EmptyProvider())

        self.assertFalse(verify_sha256_pkcs1v15(b"test vector", b"bad", RsaPublicKey(257, 3)))

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

    def test_mutates_fixed_width_stfs_metadata(self):
        path = Path(r"C:\Users\sjisg\Desktop\E9ECC9141E317C7B")
        if not path.exists():
            self.skipTest("supplied STFS profile fixture is not available")
        original = path.read_bytes()
        header = parse_stfs_header(original)
        mutated = mutate_stfs_metadata(
            original,
            display_name="Edited Profile",
            title_id=0x12345678,
            header=header,
        )
        parsed = parse_stfs_header(mutated)
        self.assertEqual(parsed.display_name, "Edited Profile")
        self.assertEqual(parsed.title_id, 0x12345678)
        self.assertTrue(verify_stfs_hashes(mutated, header=parsed)["header_hash_matches"])


if __name__ == "__main__":
    unittest.main()

