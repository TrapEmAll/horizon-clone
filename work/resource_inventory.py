"""REA-observed embedded resource surface for Horizon.exe.

These are authenticated artifact-level counts only. The module does not copy
or execute shipped resources and does not infer which resource belongs to a
specific UI feature.
"""

from __future__ import annotations

import json
import re
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

