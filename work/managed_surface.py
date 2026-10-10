"""Evidence-backed managed-member surface extraction.

REA can export a complete managed-members evidence bundle when the inline MCP
response is too large.  This module turns that retained evidence into a small,
queryable report without loading or executing the inspected assembly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _member_record(bundle: dict[str, Any]) -> dict[str, Any]:
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("evidence bundle does not contain a records array")
    candidates = [
        record
        for record in records
        if isinstance(record, dict) and record.get("operation") == "inspect_managed_members"
    ]
    if not candidates:
        raise ValueError("evidence bundle has no inspect_managed_members record")
    return max(
        candidates,
        key=lambda record: len(record.get("normalized_result", {}).get("methods", [])),
    )


def managed_surface_report_from_bundle(bundle: dict[str, Any], pattern: str | None = None) -> dict[str, Any]:
    """Return an observed managed surface from an already-decoded bundle."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    artifact = result.get("artifact") or {}
    types = result.get("types") or []
    fields = result.get("fields") or []
    methods = result.get("methods") or []
    report: dict[str, Any] = {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "artifact": artifact,
        "counts": {"types": len(types), "fields": len(fields), "methods": len(methods)},
        "identity_scope": result.get("identity_scope"),
        "limitations": [
            "Managed metadata is an observed surface, not a save-file layout.",
            "Metadata tokens are build-local coordinates bound to the artifact digest and MVID.",
            "No assembly was loaded or executed by this report.",
        ],
    }
    if pattern is None:
        return report
    try:
        matcher = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"invalid managed-surface regex: {pattern}") from exc

    def matches(member: dict[str, Any], *keys: str) -> bool:
        return any(matcher.search(str(member.get(key) or "")) for key in keys)

    report["pattern"] = pattern
    report["types"] = [
        {"full_name": item.get("full_name"), "field_list": item.get("field_list"), "method_list": item.get("method_list")}
        for item in types
        if matches(item, "full_name", "namespace", "name")
    ]
    report["fields"] = [
        {"declaring_type": item.get("declaring_type"), "name": item.get("name"), "token": item.get("token"), "signature": item.get("signature")}
        for item in fields
        if matches(item, "declaring_type", "name")
    ]
    report["methods"] = [
        {"declaring_type": item.get("declaring_type"), "name": item.get("name"), "token": item.get("token"), "signature": item.get("signature")}
        for item in methods
        if matches(item, "declaring_type", "name")
    ]
    return report


def managed_surface_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return observed managed types, fields, and methods matching *pattern*.

    The default report includes counts and no member dump.  A regex pattern is
    an explicit request for the matching surface and is evaluated locally over
    the exported REA evidence.  Tokens remain build-local and are never treated
    as stable file offsets.
    """

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return managed_surface_report_from_bundle(bundle, pattern)


def managed_schema_report_from_bundle(bundle: dict[str, Any], pattern: str | None = None) -> dict[str, Any]:
    """Join the observed managed metadata into type-centric editor schemas.

    The result is still metadata-only: field names and signatures are not
    treated as save offsets or as proof of a serializer.
    """

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = result.get("types") or []
    fields = result.get("fields") or []
    methods = result.get("methods") or []
    matcher = None
    if pattern is not None:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid managed-schema regex: {pattern}") from exc

    selected_types = [
        item for item in types
        if isinstance(item, dict)
        and (matcher is None or matcher.search(str(item.get("full_name") or "")))
    ]
    by_type: dict[str, dict[str, Any]] = {}
    for item in selected_types:
        name = str(item.get("full_name") or "")
        by_type[name] = {
            "full_name": name,
            "token": item.get("token"),
            "fields": [],
            "methods": [],
        }
    selected_names = set(by_type)
    for item in fields:
        if isinstance(item, dict) and item.get("declaring_type") in selected_names:
            by_type[item["declaring_type"]]["fields"].append({
                "name": item.get("name"),
                "token": item.get("token"),
                "signature": item.get("signature"),
            })
    for item in methods:
        if isinstance(item, dict) and item.get("declaring_type") in selected_names:
            by_type[item["declaring_type"]]["methods"].append({
                "name": item.get("name"),
                "token": item.get("token"),
                "signature": item.get("signature"),
            })
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {
            "matched_types": len(by_type),
            "matched_fields": sum(len(item["fields"]) for item in by_type.values()),
            "matched_methods": sum(len(item["methods"]) for item in by_type.values()),
            "total_types": len(types),
            "total_fields": len(fields),
            "total_methods": len(methods),
        },
        "types": list(by_type.values()),
        "limitations": [
            "Managed metadata is not a save-file layout and supplies no field offsets.",
            "The joined schema does not establish serialization, validation, or mutation behavior.",
            "Metadata tokens are build-local coordinates bound to the shipped artifact.",
        ],
    }


def managed_schema_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return joined type/field/method metadata from a retained REA bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return managed_schema_report_from_bundle(bundle, pattern)

