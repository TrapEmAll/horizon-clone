import hashlib
import unittest
from pathlib import Path

from work.horizon_clone import inspect, parse_xdbf


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


if __name__ == "__main__":
    unittest.main()

