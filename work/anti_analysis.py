"""Evidence-only report of managed anti-analysis markers observed by REA."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def anti_analysis_report_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("evidence bundle does not contain a records array")
    artifact_records = [
        record for record in records
        if isinstance(record, dict) and record.get("operation") == "inspect_managed_artifact"
    ]
    member_records = [
        record for record in records
        if isinstance(record, dict) and record.get("operation") == "inspect_managed_members"
    ]
    if not artifact_records or not member_records:
        raise ValueError("evidence bundle lacks managed artifact/member evidence")
    artifact = max(artifact_records, key=lambda item: len(item.get("normalized_result", {}).get("attributes", [])))
    members = max(member_records, key=lambda item: len(item.get("normalized_result", {}).get("types", [])))
    attributes = artifact.get("normalized_result", {}).get("attributes", [])
    types = members.get("normalized_result", {}).get("types", [])
    methods = members.get("normalized_result", {}).get("methods", [])
    marker_pattern = re.compile(r"Debugger|SuppressIldasm|Debuggable|Obfuscat|Guard", re.IGNORECASE)
    attribute_markers = [
        {"type_name": item.get("type_name"), "decoded_fixed_string": item.get("decoded_fixed_string"), "token": item.get("token")}
        for item in attributes
        if isinstance(item, dict) and marker_pattern.search(str(item.get("type_name") or ""))
    ]
    guarded_types = [
        {
            "full_name": item.get("full_name"),
            "field_count": item.get("field_list", {}).get("count"),
            "method_count": item.get("method_list", {}).get("count"),
        }
        for item in types
        if isinstance(item, dict) and marker_pattern.search(str(item.get("full_name") or ""))
    ]
    guarded_methods = [
        {
            "declaring_type": item.get("declaring_type"),
            "name": item.get("name"),
            "token": item.get("token"),
            "rva": item.get("rva"),
            "body": item.get("body"),
        }
        for item in methods
        if isinstance(item, dict) and marker_pattern.search(str(item.get("declaring_type") or ""))
    ]
    marker_counts: dict[str, int] = {}
    for item in attribute_markers:
        type_name = str(item.get("type_name") or "unknown")
        marker_counts[type_name] = marker_counts.get(type_name, 0) + 1
    guarded_method_names = sorted({str(item.get("name")) for item in guarded_methods if item.get("name")})
    return {
        "status": "observed-only",
        "artifact": artifact.get("normalized_result", {}).get("artifact"),
        "evidence_ids": {"artifact": artifact.get("evidence_id"), "members": members.get("evidence_id")},
        "attribute_markers": attribute_markers,
        "attribute_marker_counts": dict(sorted(marker_counts.items())),
        "guarded_types": guarded_types,
        "guarded_type_names": sorted({str(item.get("full_name")) for item in guarded_types if item.get("full_name")}),
        "guarded_method_count": len(guarded_methods),
        "guarded_method_names": guarded_method_names,
        "guarded_methods": guarded_methods,
        "limitations": [
            "Static metadata does not establish runtime anti-debug behavior or intent.",
            "This report does not disable, patch, execute, or bypass any protection.",
        ],
    }


def anti_analysis_report(bundle_path: str | Path) -> dict[str, Any]:
    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return anti_analysis_report_from_bundle(bundle)

