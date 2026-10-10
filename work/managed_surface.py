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


def _artifact_record(bundle: dict[str, Any]) -> dict[str, Any]:
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("evidence bundle does not contain a records array")
    candidates = [
        record for record in records
        if isinstance(record, dict) and record.get("operation") == "inspect_managed_artifact"
    ]
    if not candidates:
        raise ValueError("evidence bundle has no inspect_managed_artifact record")
    return max(candidates, key=lambda record: len(record.get("normalized_result", {}).get("references", [])))


def managed_reference_report_from_bundle(bundle: dict[str, Any], pattern: str | None = None) -> dict[str, Any]:
    """Return the authenticated assembly-reference surface from REA evidence."""

    record = _artifact_record(bundle)
    result = record.get("normalized_result") or {}
    references = [item for item in result.get("references") or [] if isinstance(item, dict)]
    matcher = None
    if pattern is not None:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid managed-reference regex: {pattern}") from exc
    selected = [
        {
            "name": item.get("name"),
            "version": item.get("version"),
            "culture": item.get("culture"),
            "flags": item.get("flags"),
            "public_key_or_token": item.get("public_key_or_token"),
            "token": item.get("token"),
        }
        for item in references
        if matcher is None or matcher.search(str(item.get("name") or ""))
    ]
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "artifact": result.get("artifact"),
        "assembly": result.get("assembly"),
        "pattern": pattern,
        "counts": {"matched": len(selected), "total": len(references)},
        "references": selected,
        "limitations": [
            "Assembly references authenticate declared dependency metadata only; they do not prove that a file is present or loaded.",
            "No assembly was loaded, resolved through a CLR, or executed by this report.",
        ],
    }


def managed_reference_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return declared assembly references from a retained REA artifact bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-artifact bundle: {path}") from exc
    return managed_reference_report_from_bundle(bundle, pattern)


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


def managed_editor_family_report_from_bundle(
    bundle: dict[str, Any], pattern: str | None = None
) -> dict[str, Any]:
    """Group authenticated managed types into queryable editor families."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = [item for item in result.get("types") or [] if isinstance(item, dict)]
    fields = [item for item in result.get("fields") or [] if isinstance(item, dict)]
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    matcher = re.compile(pattern, re.IGNORECASE) if pattern else None

    def family_name(full_name: str) -> str:
        if full_name.startswith("Horizon.PackageEditors."):
            remainder = full_name[len("Horizon.PackageEditors."):]
            return "Horizon.PackageEditors." + (remainder.split(".", 1)[0] or "(root)")
        if full_name.startswith("Horizon."):
            return "Horizon"
        if full_name.startswith("A."):
            return "obfuscated"
        return full_name.split(".", 1)[0] or "(global)"

    selected = [
        item for item in types
        if isinstance(item.get("full_name"), str)
        and (matcher is None or matcher.search(item["full_name"]))
    ]
    selected_names = {item["full_name"] for item in selected}
    grouped: dict[str, dict[str, Any]] = {}
    for item in selected:
        name = item["full_name"]
        family = family_name(name)
        group = grouped.setdefault(family, {"family": family, "type_count": 0, "field_count": 0, "method_count": 0, "sample_types": []})
        group["type_count"] += 1
        if len(group["sample_types"]) < 12:
            group["sample_types"].append(name)
    for item in fields:
        declaring = item.get("declaring_type")
        if declaring in selected_names:
            grouped[family_name(declaring)]["field_count"] += 1
    for item in methods:
        declaring = item.get("declaring_type")
        if declaring in selected_names:
            grouped[family_name(declaring)]["method_count"] += 1
    families = sorted(grouped.values(), key=lambda item: item["family"].lower())
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {"matched_families": len(families), "matched_types": len(selected_names), "total_types": len(types), "total_fields": len(fields), "total_methods": len(methods)},
        "families": families,
        "limitations": [
            "Family grouping is derived from authenticated managed type names only.",
            "Counts do not establish editor registration, save offsets, serialization, or mutation behavior.",
        ],
    }


def managed_editor_family_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return editor-family counts from a retained REA managed-members bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-members bundle: {path}") from exc
    try:
        return managed_editor_family_report_from_bundle(bundle, pattern)
    except re.error as exc:
        raise ValueError(f"invalid managed-editor-family regex: {pattern}") from exc


def managed_named_namespace_report_from_bundle(
    bundle: dict[str, Any], pattern: str | None = None
) -> dict[str, Any]:
    """Summarize stable, non-obfuscated top-level managed namespaces."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = [item for item in result.get("types") or [] if isinstance(item, dict)]
    fields = [item for item in result.get("fields") or [] if isinstance(item, dict)]
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    matcher = re.compile(pattern, re.IGNORECASE) if pattern else None

    def is_named(full_name: str) -> bool:
        return bool(full_name) and not full_name.startswith(("A.", "<")) and not re.fullmatch(r"c[0-9a-f]{32}(?:`\d+)?(?:\..*)?", full_name, re.IGNORECASE)

    selected = [
        item for item in types
        if is_named(str(item.get("full_name") or ""))
        and (matcher is None or matcher.search(str(item.get("full_name") or "")))
    ]
    selected_names = {str(item["full_name"]) for item in selected}
    grouped: dict[str, dict[str, Any]] = {}
    for item in selected:
        full_name = str(item["full_name"])
        namespace = full_name.split(".", 1)[0]
        group = grouped.setdefault(namespace, {"namespace": namespace, "type_count": 0, "field_count": 0, "method_count": 0, "sample_types": []})
        group["type_count"] += 1
        if len(group["sample_types"]) < 16:
            group["sample_types"].append(full_name)
    for item in fields:
        declaring = item.get("declaring_type")
        if declaring in selected_names:
            grouped[str(declaring).split(".", 1)[0]]["field_count"] += 1
    for item in methods:
        declaring = item.get("declaring_type")
        if declaring in selected_names:
            grouped[str(declaring).split(".", 1)[0]]["method_count"] += 1
    namespaces = sorted(grouped.values(), key=lambda item: item["namespace"].lower())
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {"matched_namespaces": len(namespaces), "matched_types": len(selected_names), "total_types": len(types)},
        "namespaces": namespaces,
        "limitations": [
            "The filter excludes names beginning with obfuscator/compiler conventions; exclusion is not proof of editor ownership.",
            "Namespace counts do not establish registration, save offsets, serialization, or mutation behavior.",
        ],
    }


def managed_named_namespace_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return stable named namespace counts from retained REA evidence."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-members bundle: {path}") from exc
    try:
        return managed_named_namespace_report_from_bundle(bundle, pattern)
    except re.error as exc:
        raise ValueError(f"invalid managed-namespace regex: {pattern}") from exc


def managed_guarded_methods_report_from_bundle(
    bundle: dict[str, Any], pattern: str | None = None
) -> dict[str, Any]:
    """List methods whose observed body contains a throw and no return opcode."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
    guarded: list[dict[str, Any]] = []
    for item in methods:
        name = str(item.get("name") or "")
        declaring = str(item.get("declaring_type") or "")
        if matcher is not None and not matcher.search(f"{declaring}.{name}"):
            continue
        body = item.get("body") or {}
        counts = body.get("opcode_counts") or {}
        if body.get("status") == "present" and counts.get("throw", 0) and not counts.get("ret", 0):
            guarded.append({
                "declaring_type": declaring,
                "name": name,
                "token": item.get("token"),
                "signature": item.get("signature"),
                "body": {
                    "instruction_count": body.get("instruction_count"),
                    "opcode_counts": counts,
                    "il_sha256": body.get("il_sha256"),
                    "exception_regions": body.get("exception_regions") or [],
                },
                "status": "throw-observed-no-return",
            })
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {"guarded_methods": len(guarded), "total_methods": len(methods)},
        "methods": guarded,
        "limitations": [
            "The report identifies a throw opcode with no observed ret opcode; it does not execute the method or prove every path throws.",
            "A guarded method is not treated as an implementation contract or bypassed by the clone.",
        ],
    }


def managed_guarded_methods_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return throw-observed managed methods from retained REA evidence."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-members bundle: {path}") from exc
    try:
        return managed_guarded_methods_report_from_bundle(bundle, pattern)
    except re.error as exc:
        raise ValueError(f"invalid guarded-method regex: {pattern}") from exc


def managed_schema_report_from_bundle(
    bundle: dict[str, Any],
    pattern: str | None = None,
    include_bodies: bool = False,
    method_pattern: str | None = None,
    include_field_accesses: bool = False,
) -> dict[str, Any]:
    """Join the observed managed metadata into type-centric editor schemas.

    The result is still metadata-only: field names and signatures are not
    treated as save offsets or as proof of a serializer.
    """

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = result.get("types") or []
    fields = result.get("fields") or []
    methods = result.get("methods") or []
    field_accesses = result.get("field_accesses") or []
    matcher = None
    if pattern is not None:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid managed-schema regex: {pattern}") from exc
    method_matcher = None
    if method_pattern is not None:
        try:
            method_matcher = re.compile(method_pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid managed-schema method regex: {method_pattern}") from exc

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
        if (
            isinstance(item, dict)
            and item.get("declaring_type") in selected_names
            and (method_matcher is None or method_matcher.search(str(item.get("name") or "")))
        ):
            method = {
                "name": item.get("name"),
                "token": item.get("token"),
                "signature": item.get("signature"),
            }
            if include_bodies:
                body = item.get("body") or {}
                method["body"] = {
                    "status": body.get("status"),
                    "rva": body.get("rva"),
                    "file_offset": body.get("file_offset"),
                    "il_sha256": body.get("il_sha256"),
                    "opcode_counts": body.get("opcode_counts"),
                    "instruction_count": body.get("instruction_count"),
                    "exception_regions": body.get("exception_regions"),
                }
            by_type[item["declaring_type"]]["methods"].append(method)
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "include_bodies": include_bodies,
        "method_pattern": method_pattern,
        "include_field_accesses": include_field_accesses,
        "counts": {
            "matched_types": len(by_type),
            "matched_fields": sum(len(item["fields"]) for item in by_type.values()),
            "matched_methods": sum(len(item["methods"]) for item in by_type.values()),
            "total_types": len(types),
            "total_fields": len(fields),
            "total_methods": len(methods),
        },
        "types": list(by_type.values()),
        "field_accesses": (
            [
                {
                    "method": item.get("method"),
                    "method_token": item.get("method_token"),
                    "field_name": item.get("field_name"),
                    "field_token": item.get("field_token"),
                    "opcode": item.get("opcode"),
                }
                for item in field_accesses
                if isinstance(item, dict)
                and (method_matcher is None or method_matcher.search(str(item.get("method") or "")))
            ]
            if include_field_accesses
            else []
        ),
        "limitations": [
            "Managed metadata is not a save-file layout and supplies no field offsets.",
            "The joined schema does not establish serialization, validation, or mutation behavior.",
            "Metadata tokens are build-local coordinates bound to the shipped artifact.",
        ],
    }


def managed_schema_report(
    bundle_path: str | Path,
    pattern: str | None = None,
    include_bodies: bool = False,
    method_pattern: str | None = None,
    include_field_accesses: bool = False,
) -> dict[str, Any]:
    """Return joined type/field/method metadata from a retained REA bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return managed_schema_report_from_bundle(bundle, pattern, include_bodies, method_pattern, include_field_accesses)


def managed_io_contract_report_from_bundle(
    bundle: dict[str, Any],
    pattern: str | None = None,
    method_pattern: str = r"^(get_|set_|Read|Write|Load|Save|Compress|Decompress)",
) -> dict[str, Any]:
    """Return static managed I/O contracts for reconstruction work."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = result.get("types") or []
    methods = result.get("methods") or []
    fields = result.get("field_accesses") or []
    calls = result.get("call_edges") or []
    type_matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
    method_matcher = re.compile(method_pattern, re.IGNORECASE)
    selected_names = {
        str(item.get("full_name") or "")
        for item in types
        if isinstance(item, dict) and (type_matcher is None or type_matcher.search(str(item.get("full_name") or "")))
    }
    selected_methods = [
        item for item in methods
        if isinstance(item, dict)
        and item.get("declaring_type") in selected_names
        and method_matcher.search(str(item.get("name") or ""))
    ]
    contracts: list[dict[str, Any]] = []
    for item in selected_methods:
        token = str(item.get("token"))
        body = item.get("body") or {}
        contracts.append({
            "declaring_type": item.get("declaring_type"),
            "name": item.get("name"),
            "token": item.get("token"),
            "signature": item.get("signature"),
            "body": {
                "status": body.get("status"),
                "rva": body.get("rva"),
                "file_offset": body.get("file_offset"),
                "instruction_count": body.get("instruction_count"),
                "opcode_counts": body.get("opcode_counts"),
                "il_sha256": body.get("il_sha256"),
                "anchors": body.get("anchors") or [],
                "exception_regions": body.get("exception_regions") or [],
            },
            "field_accesses": [
                {"field_name": access.get("field_name"), "field_token": access.get("field_token"), "opcode": access.get("opcode")}
                for access in fields
                if isinstance(access, dict) and str(access.get("method_token")) == token
            ],
            "call_targets": [
                {"opcode": edge.get("opcode"), "target_kind": edge.get("target_kind"), "target_name": edge.get("target_name"), "target_token": edge.get("target_token")}
                for edge in calls
                if isinstance(edge, dict) and str(edge.get("caller_token")) == token
            ],
        })
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "method_pattern": method_pattern,
        "counts": {
            "matched_types": len(selected_names),
            "matched_methods": len(contracts),
            "methods_with_field_accesses": sum(bool(item["field_accesses"]) for item in contracts),
            "methods_with_call_targets": sum(bool(item["call_targets"]) for item in contracts),
        },
        "methods": contracts,
        "limitations": [
            "CIL anchors and tokens are artifact-local evidence, not a serializer implementation.",
            "The report does not infer field offsets, endianness, validation, or native protocol semantics.",
        ],
    }


def managed_io_contract_report(
    bundle_path: str | Path,
    pattern: str | None = None,
    method_pattern: str = r"^(get_|set_|Read|Write|Load|Save|Compress|Decompress)",
) -> dict[str, Any]:
    """Return selected static managed I/O contracts from a retained bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return managed_io_contract_report_from_bundle(bundle, pattern, method_pattern)

