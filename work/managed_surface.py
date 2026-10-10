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

