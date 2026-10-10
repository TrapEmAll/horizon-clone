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
        results.append({"name": name, "status": "extracted", "path": str(output_path), "bytes": len(payload), "sha256": expected, "source": kind})
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

