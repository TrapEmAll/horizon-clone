"""REA-observed embedded resource surface for Horizon.exe.

These are authenticated artifact-level counts. Optional extraction copies only
uniquely hash-matched embedded payloads and never executes them or infers which
resource belongs to a specific UI feature.
"""

from __future__ import annotations

import json
import re
import hashlib
import struct
from pathlib import Path
from typing import Any


def observed_resource_surface() -> dict[str, int]:
    return {
        "metadata_resource_record_count": 206,
        "resource_count": 205,
        "total_bytes": 4_017_795,
        "distinct_payload_hashes": 30,
        "embedded_resource_count": 205,
        "nonembedded_unresolved_count": 1,
    }


def resource_surface_report_from_bundle(bundle: dict[str, Any], pattern: str | None = None) -> dict[str, Any]:
    """Query resource metadata from an exported REA evidence bundle."""

    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("evidence bundle does not contain a records array")
    candidates = [
        record for record in records
        if isinstance(record, dict)
        and record.get("operation") == "inspect_managed_artifact"
        and isinstance(record.get("normalized_result", {}).get("resources"), list)
    ]
    if not candidates:
        raise ValueError("evidence bundle has no managed-resource inventory")
    record = max(candidates, key=lambda item: len(item["normalized_result"]["resources"]))
    result = record["normalized_result"]
    resources = result["resources"]
    matcher = None
    if pattern is not None:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid resource regex: {pattern}") from exc
    selected = [
        {
            "name": item.get("name"),
            "declared_offset": item.get("declared_offset"),
            "data_length": item.get("data_length"),
            "data_sha256": item.get("data_sha256"),
            "embedded": item.get("embedded"),
            "visibility": item.get("visibility"),
        }
        for item in resources
        if isinstance(item, dict) and (matcher is None or matcher.search(str(item.get("name") or "")))
    ]
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "artifact": result.get("artifact"),
        "coverage": result.get("coverage"),
        "pattern": pattern,
        "counts": {"matched": len(selected), "total": len(resources)},
        "resources": selected,
        "limitations": [
            "Resource metadata is authenticated by REA; ownership and UI behavior remain unresolved.",
            "This report does not copy, deserialize, or execute shipped resource payloads.",
        ],
    }


def resource_surface_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Read and query an exported REA managed-resource evidence bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return resource_surface_report_from_bundle(bundle, pattern)


def verify_managed_resource_payloads(
    executable_path: str | Path,
    bundle_path: str | Path,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Compare file-backed managed-resource candidates with REA hashes.

    The verifier is deliberately read-only.  It checks both the raw declared
    span and the standard four-byte length-prefixed payload candidate, and
    reports ambiguity instead of choosing an unverified layout.
    """

    report = resource_surface_report(bundle_path, pattern)
    data = Path(executable_path).read_bytes()
    blob_offset, blob_size = _managed_resource_blob(data)
    results: list[dict[str, Any]] = []
    for item in report["resources"]:
        if not item.get("embedded") or not isinstance(item.get("declared_offset"), int) or not isinstance(item.get("data_length"), int):
            results.append({"name": item.get("name"), "status": "unresolved", "reason": "resource is not an embedded file-backed payload"})
            continue
        offset = item["declared_offset"]
        length = item["data_length"]
        expected = item.get("data_sha256")
        candidates = _resource_payload_candidates(data, blob_offset, blob_size, offset, length)
        matches = [kind for kind, payload in candidates if hashlib.sha256(payload).hexdigest() == expected]
        results.append({
            "name": item.get("name"),
            "declared_offset": offset,
            "data_length": length,
            "expected_sha256": expected,
            "status": "verified" if len(matches) == 1 else "unresolved",
            "matching_candidates": matches,
            "candidate_count": len(candidates),
        })
    return {
        "status": "verified" if results and all(item["status"] == "verified" for item in results) else "partial",
        "executable": str(executable_path),
        "resource_blob": {"file_offset": blob_offset, "byte_length": blob_size},
        "counts": {
            "verified": sum(item["status"] == "verified" for item in results),
            "unresolved": sum(item["status"] != "verified" for item in results),
        },
        "resources": results,
        "limitations": [
            "Verification compares authenticated REA hashes only; it does not deserialize or execute resources.",
            "A resource is unresolved when neither tested byte-span candidate matches uniquely.",
        ],
    }


def extract_managed_resource_payloads(
    executable_path: str | Path,
    bundle_path: str | Path,
    output_dir: str | Path,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Extract only embedded resource payloads with a unique REA hash match."""

    report = resource_surface_report(bundle_path, pattern)
    data = Path(executable_path).read_bytes()
    blob_offset, blob_size = _managed_resource_blob(data)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for index, item in enumerate(report["resources"]):
        name = item.get("name")
        offset = item.get("declared_offset")
        length = item.get("data_length")
        expected = item.get("data_sha256")
        if not item.get("embedded") or not isinstance(offset, int) or not isinstance(length, int) or not isinstance(expected, str):
            results.append({"name": name, "status": "unresolved", "reason": "resource is not an embedded file-backed payload"})
            continue
        matches = [
            (kind, payload)
            for kind, payload in _resource_payload_candidates(data, blob_offset, blob_size, offset, length)
            if hashlib.sha256(payload).hexdigest() == expected
        ]
        if len(matches) != 1:
            results.append({"name": name, "status": "unresolved", "reason": "resource span did not produce a unique authenticated payload", "matching_candidates": [kind for kind, _ in matches]})
            continue
        kind, payload = matches[0]
        output_path = destination / f"resource-{index:03d}-{expected[:16]}.bin"
        if output_path.exists():
            raise FileExistsError(output_path)
        output_path.write_bytes(payload)
        results.append({"name": name, "status": "extracted", "path": str(output_path), "bytes": len(payload), "sha256": expected, "source": kind, "payload_kind": classify_resource_payload(payload), "payload_metadata": resource_payload_metadata(payload)})
    extracted = sum(item["status"] == "extracted" for item in results)
    unresolved = len(results) - extracted
    return {
        "status": "verified" if unresolved == 0 else "partial",
        "executable": str(executable_path),
        "output_dir": str(destination),
        "counts": {"extracted": extracted, "unresolved": unresolved},
        "resources": results,
        "limitations": [
            "Extraction is byte-for-byte and hash-verified; resources are not deserialized or executed.",
            "Resource ownership and UI feature semantics remain unresolved.",
        ],
    }


def parse_dotnet_resources(data: bytes) -> dict[str, Any]:
    """Parse the standard .NET ``.resources`` index without deserializing values.

    Horizon's embedded resource records are authenticated by REA, but the
    resource values are intentionally kept opaque here.  This parser exposes
    the name/type tables and byte spans needed for inspection or extraction;
    it never instantiates a ``ResourceReader`` value.
    """

    if not isinstance(data, bytes):
        raise TypeError("resource data must be bytes")
    if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != 0xBEEFCACE:
        raise ValueError("input is not a .NET resources payload")
    reader_version, header_size = struct.unpack_from("<II", data, 4)
    header_end = 12 + header_size
    if header_end > len(data):
        raise ValueError(".NET resources header exceeds the payload")
    cursor = header_end
    if cursor + 12 > len(data):
        raise ValueError(".NET resources payload has no resource table header")
    resource_manager_version, resource_count, type_count = struct.unpack_from("<III", data, cursor)
    cursor += 12

    def read_7bit_integer(position: int) -> tuple[int, int]:
        value = 0
        shift = 0
        for _ in range(5):
            if position >= len(data):
                raise ValueError("truncated .NET resources length")
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, position
            shift += 7
        raise ValueError("invalid .NET resources length")

    def decode_safe_value(payload: bytes) -> dict[str, Any]:
        """Decode only standard primitive resource values.

        User-defined resource types are intentionally left opaque.  This
        avoids reproducing ``ResourceReader`` deserialization, which could
        instantiate arbitrary formatter types from an untrusted payload.
        """

        type_code, position = read_7bit_integer_from(payload, 0)
        type_names_by_code = {
            0: "Null",
            1: "String",
            2: "Boolean",
            3: "Char",
            4: "Byte",
            5: "SByte",
            6: "Int16",
            7: "UInt16",
            8: "Int32",
            9: "UInt32",
            10: "Int64",
            11: "UInt64",
            12: "Single",
            13: "Double",
            14: "Decimal",
            15: "DateTime",
            16: "TimeSpan",
            32: "ByteArray",
            33: "Stream",
        }
        type_name = type_names_by_code.get(type_code, type_names[type_code - 0x40] if 0x40 <= type_code < 0x40 + len(type_names) else None)
        result: dict[str, Any] = {
            "type_code": type_code,
            "type_name": type_name or "UserDefined",
            "decoded": False,
        }
        if type_code == 0:
            result.update({"decoded": True, "value": None})
            return result
        if type_code == 1:
            length, position = read_7bit_integer_from(payload, position)
            end = position + length * 2
            if end > len(payload):
                raise ValueError("truncated .NET resources string value")
            result.update({"decoded": True, "value": payload[position:end].decode("utf-16le")})
            return result
        formats = {
            2: (1, "Boolean", "<?"), 3: (2, "Char", "<H"), 4: (1, "Byte", "<B"),
            5: (1, "SByte", "<b"), 6: (2, "Int16", "<h"), 7: (2, "UInt16", "<H"),
            8: (4, "Int32", "<i"), 9: (4, "UInt32", "<I"), 10: (8, "Int64", "<q"),
            11: (8, "UInt64", "<Q"), 12: (4, "Single", "<f"), 13: (8, "Double", "<d"),
            14: (16, "Decimal", None), 15: (8, "DateTime", None), 16: (8, "TimeSpan", None),
        }
        if type_code in formats:
            width, type_name, value_format = formats[type_code]
            end = position + width
            if end > len(payload):
                raise ValueError("truncated .NET resources primitive value")
            decoded: dict[str, Any] = {"decoded": True, "value_hex": payload[position:end].hex()}
            if value_format is not None:
                decoded["value"] = struct.unpack(value_format, payload[position:end])[0]
            result.update({"type_name": type_name, **decoded})
            return result
        if type_code in {32, 33}:
            length, position = read_7bit_integer_from(payload, position)
            end = position + length
            if end > len(payload):
                raise ValueError("truncated .NET resources binary value")
            result.update({"decoded": True, "value_length": length, "value_sha256": hashlib.sha256(payload[position:end]).hexdigest()})
            return result
        result["opaque_reason"] = "user-defined resource type is not deserialized"
        return result

    def read_7bit_integer_from(value: bytes, position: int) -> tuple[int, int]:
        result = 0
        shift = 0
        for _ in range(5):
            if position >= len(value):
                raise ValueError("truncated .NET resources length")
            byte = value[position]
            position += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result, position
            shift += 7
        raise ValueError("invalid .NET resources length")

    type_names: list[str] = []
    for _ in range(type_count):
        length, cursor = read_7bit_integer(cursor)
        end = cursor + length
        if end > len(data):
            raise ValueError("truncated .NET resources type name")
        type_names.append(data[cursor:end].decode("utf-8", errors="replace"))
        cursor = end
    if resource_count == 0:
        return {
            "status": "observed-index",
            "reader_version": reader_version,
            "resource_manager_version": resource_manager_version,
            "resource_count": 0,
            "type_count": type_count,
            "type_names": type_names,
            "data_section_offset": None,
            "resources": [],
            "limitations": [
                "The payload contains no named resource values or data section.",
                "User-defined resource values are never deserialized or instantiated.",
            ],
        }
    cursor = (cursor + 7) & ~7
    table_end = cursor + resource_count * 8 + 4
    if table_end > len(data):
        raise ValueError("truncated .NET resources index tables")
    hashes = list(struct.unpack_from(f"<{resource_count}I", data, cursor)) if resource_count else []
    cursor += resource_count * 4
    name_positions = list(struct.unpack_from(f"<{resource_count}I", data, cursor)) if resource_count else []
    cursor += resource_count * 4
    data_section_offset = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    name_section_start = cursor
    data_section_start = name_section_start + data_section_offset
    if data_section_start > len(data):
        raise ValueError(".NET resources data section exceeds the payload")

    names: list[dict[str, Any]] = []
    for index, (name_position, name_hash) in enumerate(zip(name_positions, hashes)):
        position = name_section_start + name_position
        length, position = read_7bit_integer(position)
        name_end = position + length
        if name_end + 4 > data_section_start or name_end > len(data):
            raise ValueError(".NET resources name entry exceeds the name section")
        encoded_name = data[position:name_end]
        if len(encoded_name) % 2 == 0 and encoded_name[1::2].count(0) >= len(encoded_name) // 2:
            name = encoded_name.decode("utf-16le", errors="replace")
            name_encoding = "utf-16le"
        else:
            name = encoded_name.decode("utf-8", errors="replace")
            name_encoding = "utf-8"
        value_offset = struct.unpack_from("<I", data, name_end)[0]
        names.append({
            "index": index,
            "name": name,
            "name_encoding": name_encoding,
            "name_position": name_position,
            "name_hash": name_hash,
            "data_offset": value_offset,
        })

    ordered_offsets = sorted({item["data_offset"] for item in names if item["data_offset"] <= len(data) - data_section_start})
    for item in names:
        start = data_section_start + item["data_offset"]
        following = next((offset for offset in ordered_offsets if offset > item["data_offset"]), len(data) - data_section_start)
        end = data_section_start + following
        if start > end or end > len(data):
            raise ValueError(".NET resources data entry exceeds the payload")
        payload = data[start:end]
        item["data_length"] = len(payload)
        item["data_sha256"] = hashlib.sha256(payload).hexdigest()
        item["payload_kind"] = classify_resource_payload(payload)
        try:
            item["value"] = decode_safe_value(payload)
        except ValueError as exc:
            item["value"] = {
                "decoded": False,
                "opaque_reason": "resource value could not be decoded safely",
                "decode_error": str(exc),
            }

    return {
        "status": "observed-index",
        "reader_version": reader_version,
        "resource_manager_version": resource_manager_version,
        "resource_count": resource_count,
        "type_count": type_count,
        "type_names": type_names,
        "data_section_offset": data_section_offset,
        "resources": names,
        "limitations": [
            "Only standard primitive, string, byte-array, and stream type codes are decoded; user-defined values remain opaque.",
            "User-defined resource values are never deserialized or instantiated.",
            "The parser reports spans from the standard name/data index and does not infer UI ownership.",
        ],
    }


def _resource_payload_candidates(data: bytes, blob_offset: int, blob_size: int, offset: int, length: int) -> list[tuple[str, bytes]]:
    candidates: list[tuple[str, bytes]] = []
    raw_start = blob_offset + offset
    raw_end = raw_start + length
    if 0 <= offset <= blob_size and raw_end <= blob_offset + blob_size:
        candidates.append(("raw-span", data[raw_start:raw_end]))
    prefix_end = raw_start + 4 + length
    if 0 <= offset <= blob_size and prefix_end <= blob_offset + blob_size:
        candidates.append(("length-prefixed-payload", data[raw_start + 4:prefix_end]))
    return candidates


def classify_resource_payload(payload: bytes) -> str:
    """Classify an extracted payload by an exact, non-executing magic check."""

    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if payload.startswith(b"BM"):
        return "bmp"
    if payload.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if payload.startswith(b"RIFF") and len(payload) >= 12 and payload[8:12] == b"WAVE":
        return "wav"
    if payload.startswith(b"PK\x03\x04"):
        return "zip"
    if payload.startswith(b"\x1f\x8b"):
        return "gzip"
    if payload.startswith(b"MZ"):
        return "pe-or-dos"
    if payload.startswith(b"\xce\xca\xef\xbe"):
        return "dotnet-resources"
    return "binary"


def resource_payload_metadata(payload: bytes) -> dict[str, Any]:
    """Return safe format and image-dimension metadata without decoding assets."""

    if not isinstance(payload, bytes):
        raise TypeError("resource payload must be bytes")
    kind = classify_resource_payload(payload)
    result: dict[str, Any] = {"kind": kind, "bytes": len(payload)}
    if kind == "png" and len(payload) >= 24 and payload[12:16] == b"IHDR":
        result.update({"width": struct.unpack_from(">I", payload, 16)[0], "height": struct.unpack_from(">I", payload, 20)[0]})
    elif kind == "gif" and len(payload) >= 10:
        result.update({"width": struct.unpack_from("<H", payload, 6)[0], "height": struct.unpack_from("<H", payload, 8)[0]})
    elif kind == "bmp" and len(payload) >= 26:
        dib_size = struct.unpack_from("<I", payload, 14)[0]
        if dib_size >= 40 and len(payload) >= 26:
            width = struct.unpack_from("<i", payload, 18)[0]
            height = struct.unpack_from("<i", payload, 22)[0]
            result.update({"width": abs(width), "height": abs(height), "top_down": height < 0})
    elif kind == "ico" and len(payload) >= 22:
        count = struct.unpack_from("<H", payload, 4)[0]
        dimensions = []
        for index in range(count):
            offset = 6 + index * 16
            if offset + 8 > len(payload):
                break
            width, height = payload[offset] or 256, payload[offset + 1] or 256
            dimensions.append({"width": width, "height": height})
        result["images"] = dimensions
    elif kind == "jpeg":
        dimensions = _jpeg_dimensions(payload)
        if dimensions is not None:
            result.update({"width": dimensions[0], "height": dimensions[1]})
    elif kind == "dotnet-resources":
        try:
            parsed = parse_dotnet_resources(payload)
        except ValueError as exc:
            result.update({"index_status": "unresolved", "index_error": str(exc)})
        else:
            result.update({
                "index_status": parsed["status"],
                "resource_count": parsed["resource_count"],
                "type_count": parsed["type_count"],
                "type_names": parsed["type_names"],
            })
    return result


def _jpeg_dimensions(payload: bytes) -> tuple[int, int] | None:
    """Read JPEG SOF dimensions using bounded marker parsing."""

    if len(payload) < 4 or payload[:2] != b"\xff\xd8":
        return None
    offset = 2
    sof_markers = set(range(0xC0, 0xC4)) | set(range(0xC5, 0xC8)) | set(range(0xC9, 0xCC)) | set(range(0xCD, 0xD0))
    while offset + 3 < len(payload):
        if payload[offset] != 0xFF:
            offset += 1
            continue
        while offset < len(payload) and payload[offset] == 0xFF:
            offset += 1
        if offset >= len(payload):
            return None
        marker = payload[offset]
        offset += 1
        if marker in {0xD8, 0xD9}:
            continue
        if marker == 0xDA:
            return None
        if offset + 2 > len(payload):
            return None
        segment_length = struct.unpack_from(">H", payload, offset)[0]
        if segment_length < 2 or offset + segment_length > len(payload):
            return None
        if marker in sof_markers and segment_length >= 7:
            return (
                struct.unpack_from(">H", payload, offset + 3)[0],
                struct.unpack_from(">H", payload, offset + 5)[0],
            )
        offset += segment_length
    return None


def _managed_resource_blob(data: bytes) -> tuple[int, int]:
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("input is not a readable PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("input has an invalid PE signature")
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = optional + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
    if directory < 0 or directory + 15 * 8 > len(data):
        raise ValueError("input has an unsupported PE optional header")
    cli_rva, _cli_size = struct.unpack_from("<II", data, directory + 14 * 8)
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    section_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = optional + section_size

    def rva_to_offset(rva: int) -> int:
        for index in range(section_count):
            current = section_table + index * 40
            if current + 40 > len(data):
                break
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, current + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                offset = raw_pointer + rva - virtual_address
                if offset < len(data):
                    return offset
        raise ValueError(f"RVA 0x{rva:x} is not mapped to file data")

    cli_offset = rva_to_offset(cli_rva)
    if cli_offset + 32 > len(data):
        raise ValueError("input has a truncated CLI header")
    resources_rva, resources_size = struct.unpack_from("<II", data, cli_offset + 24)
    if not resources_rva or not resources_size:
        raise ValueError("input has no managed resource blob")
    blob_offset = rva_to_offset(resources_rva)
    if blob_offset + resources_size > len(data):
        raise ValueError("managed resource blob exceeds the PE image")
    return blob_offset, resources_size

