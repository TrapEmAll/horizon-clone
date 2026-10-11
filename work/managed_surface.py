"""Evidence-backed managed-member surface extraction.

REA can export a complete managed-members evidence bundle when the inline MCP
response is too large.  This module turns that retained evidence into a small,
queryable report without loading or executing the inspected assembly.
"""

from __future__ import annotations

import json
import re
from collections import Counter
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


def managed_artifact_report_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return authenticated managed-artifact identity and coverage metadata."""

    record = _artifact_record(bundle)
    result = record.get("normalized_result") or {}
    resources = [item for item in result.get("resources") or [] if isinstance(item, dict)]
    references = [item for item in result.get("references") or [] if isinstance(item, dict)]
    metadata = result.get("metadata") or {}
    coverage = result.get("coverage") or {}
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "artifact": result.get("artifact"),
        "pe": result.get("pe"),
        "classification": result.get("classification"),
        "module": result.get("module"),
        "assembly": result.get("assembly"),
        "target_frameworks": result.get("target_frameworks") or [],
        "metadata": {
            "status": metadata.get("status"),
            "version": metadata.get("version"),
            "stream_names": metadata.get("stream_names") or [],
            "table_row_counts": metadata.get("table_row_counts") or {},
        },
        "coverage": coverage,
        "counts": {"references": len(references), "resources": len(resources)},
        "limitations": [
            "This report preserves static PE/CLI evidence only; it does not load, resolve, decompile, or execute the assembly.",
            "Partial metadata or resource coverage is reported as observed and is not silently completed by inference.",
        ],
    }


def managed_artifact_report(bundle_path: str | Path) -> dict[str, Any]:
    """Return identity and coverage from a retained REA managed-artifact bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-artifact bundle: {path}") from exc
    return managed_artifact_report_from_bundle(bundle)


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


_FEATURE_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("profile-and-social", ("profile", "gamertag", "gamer", "gamerscore", "friend", "message")),
    ("achievement-and-score", ("achievement", "score", "challenge", "medal")),
    ("device-and-storage", ("device", "fatx", "usb", "drive", "storage", "content", "package")),
    ("save-and-serialization", ("save", "load", "read", "write", "serialize", "deserialize", "compress", "decompress")),
    ("editor-and-ui", ("editor", "form", "dialog", "control", "menu", "thumb", "image", "resource")),
    ("runtime-and-security", ("runtime", "check", "guard", "crypto", "encrypt", "decrypt", "sign", "verify")),
)


def managed_feature_surface_report_from_bundle(
    bundle: dict[str, Any], pattern: str | None = None
) -> dict[str, Any]:
    """Classify observed managed names into evidence-only feature buckets.

    This is a prioritization aid for reconstruction.  A bucket means that a
    literal term occurred in an authenticated type or method name; it does
    not establish registration, runtime reachability, or file-format behavior.
    """

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = [item for item in result.get("types") or [] if isinstance(item, dict)]
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    try:
        matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
    except re.error as exc:
        raise ValueError(f"invalid managed-feature regex: {pattern}") from exc

    selected_types = [
        item for item in types
        if matcher is None or matcher.search(str(item.get("full_name") or ""))
    ]
    selected_names = {str(item.get("full_name") or "") for item in selected_types}
    selected_methods = [
        item for item in methods
        if item.get("declaring_type") in selected_names
        and (matcher is None or matcher.search(str(item.get("name") or "")) or matcher.search(str(item.get("declaring_type") or "")))
    ]

    buckets: list[dict[str, Any]] = []
    for bucket, terms in _FEATURE_TERMS:
        type_hits: dict[str, set[str]] = {}
        method_hits: dict[str, set[str]] = {}
        for item in selected_types:
            name = str(item.get("full_name") or "")
            lowered = name.casefold()
            for term in terms:
                if term in lowered:
                    type_hits.setdefault(term, set()).add(name)
        for item in selected_methods:
            declaring = str(item.get("declaring_type") or "")
            name = str(item.get("name") or "")
            lowered = f"{declaring}.{name}".casefold()
            for term in terms:
                if term in lowered:
                    method_hits.setdefault(term, set()).add(f"{declaring}.{name}")
        if type_hits or method_hits:
            buckets.append({
                "feature": bucket,
                "terms": sorted(set(type_hits) | set(method_hits)),
                "type_count": len({name for names in type_hits.values() for name in names}),
                "method_count": len({name for names in method_hits.values() for name in names}),
                "sample_types": sorted({name for names in type_hits.values() for name in names})[:12],
                "sample_methods": sorted({name for names in method_hits.values() for name in names})[:16],
            })
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {
            "selected_types": len(selected_types),
            "selected_methods": len(selected_methods),
            "feature_buckets": len(buckets),
        },
        "features": buckets,
        "limitations": [
            "Buckets are literal-name classifications over authenticated managed metadata.",
            "Names do not establish runtime reachability, UI ownership, serialization, or mutation behavior.",
            "The report does not load, execute, patch, or bypass the target assembly.",
        ],
    }


def managed_feature_surface_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return evidence-only feature buckets from a retained REA bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-feature bundle: {path}") from exc
    return managed_feature_surface_report_from_bundle(bundle, pattern)


def managed_property_contract_report_from_bundle(
    bundle: dict[str, Any],
    type_pattern: str | None = None,
    property_pattern: str | None = None,
    include_bodies: bool = False,
) -> dict[str, Any]:
    """Join authenticated managed getter/setter names into property contracts.

    The accessor convention is a derived naming relationship.  It is useful
    for reconstructing metadata editors, but it is not evidence of a backing
    field, offset, or serialized representation.
    """

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    types = [item for item in result.get("types") or [] if isinstance(item, dict)]
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    calls = [item for item in result.get("call_edges") or [] if isinstance(item, dict)]
    try:
        type_matcher = re.compile(type_pattern, re.IGNORECASE) if type_pattern else None
        property_matcher = re.compile(property_pattern, re.IGNORECASE) if property_pattern else None
    except re.error as exc:
        raise ValueError(f"invalid managed-property regex: {exc}") from exc
    selected_types = {
        str(item.get("full_name") or "")
        for item in types
        if type_matcher is None or type_matcher.search(str(item.get("full_name") or ""))
    }
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in methods:
        declaring = str(item.get("declaring_type") or "")
        name = str(item.get("name") or "")
        if declaring not in selected_types or not (name.startswith("get_") or name.startswith("set_")):
            continue
        property_name = name[4:]
        if property_matcher is not None and not property_matcher.search(property_name):
            continue
        key = (declaring, property_name)
        contract = grouped.setdefault(key, {"declaring_type": declaring, "property": property_name, "get": None, "set": None})
        accessor = "get" if name.startswith("get_") else "set"
        body = item.get("body") or {}
        value: dict[str, Any] = {
            "name": name,
            "token": item.get("token"),
            "signature": item.get("signature"),
        }
        if include_bodies:
            value["body"] = {
                "status": body.get("status"),
                "rva": body.get("rva"),
                "file_offset": body.get("file_offset"),
                "instruction_count": body.get("instruction_count"),
                "il_sha256": body.get("il_sha256"),
                "opcode_counts": body.get("opcode_counts") or {},
            }
        value["call_targets"] = [
            {"opcode": edge.get("opcode"), "target_kind": edge.get("target_kind"), "target_name": edge.get("target_name"), "target_token": edge.get("target_token")}
            for edge in calls
            if str(edge.get("caller_token")) == str(item.get("token"))
        ]
        contract[accessor] = value
    contracts = []
    for contract in sorted(grouped.values(), key=lambda item: (item["declaring_type"].casefold(), item["property"].casefold())):
        getter = contract["get"] is not None
        setter = contract["set"] is not None
        contract["access"] = "read-write" if getter and setter else "read-only" if getter else "write-only"
        contracts.append(contract)
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "type_pattern": type_pattern,
        "property_pattern": property_pattern,
        "include_bodies": include_bodies,
        "counts": {
            "matched_types": len(selected_types),
            "property_contracts": len(contracts),
            "read_write": sum(item["access"] == "read-write" for item in contracts),
            "read_only": sum(item["access"] == "read-only" for item in contracts),
            "write_only": sum(item["access"] == "write-only" for item in contracts),
        },
        "properties": contracts,
        "limitations": [
            "Getter/setter pairing is derived from managed naming conventions.",
            "The report does not establish backing fields, offsets, serialization order, validation, or runtime reachability.",
            "The report does not load, execute, patch, or bypass the target assembly.",
        ],
    }


def managed_property_contract_report(
    bundle_path: str | Path,
    type_pattern: str | None = None,
    property_pattern: str | None = None,
    include_bodies: bool = False,
) -> dict[str, Any]:
    """Return derived getter/setter contracts from a retained REA bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-property bundle: {path}") from exc
    return managed_property_contract_report_from_bundle(bundle, type_pattern, property_pattern, include_bodies)


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


def managed_body_fidelity_report_from_bundle(
    bundle: dict[str, Any], pattern: str | None = None
) -> dict[str, Any]:
    """Measure whether retained method bodies are distinct enough to guide reconstruction."""

    record = _member_record(bundle)
    result = record.get("normalized_result") or {}
    methods = [item for item in result.get("methods") or [] if isinstance(item, dict)]
    matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
    selected = [
        item for item in methods
        if matcher is None
        or matcher.search(f"{item.get('declaring_type') or ''}.{item.get('name') or ''}")
    ]
    status_counts: Counter[str] = Counter()
    hash_groups: dict[str, list[dict[str, Any]]] = {}
    offset_groups: dict[str, list[dict[str, Any]]] = {}
    throw_without_return = 0
    for item in selected:
        body = item.get("body") or {}
        status_counts[str(body.get("status") or "unknown")] += 1
        il_hash = body.get("il_sha256")
        file_offset = body.get("file_offset")
        summary = {
            "declaring_type": item.get("declaring_type"),
            "name": item.get("name"),
            "token": item.get("token"),
            "file_offset": file_offset,
            "il_sha256": il_hash,
            "opcode_counts": body.get("opcode_counts") or {},
        }
        if il_hash:
            hash_groups.setdefault(str(il_hash), []).append(summary)
        if file_offset is not None:
            offset_groups.setdefault(str(file_offset), []).append(summary)
        counts = body.get("opcode_counts") or {}
        if counts.get("throw", 0) and not counts.get("ret", 0):
            throw_without_return += 1

    def duplicate_groups(groups: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        return [
            {"key": key, "count": len(items), "sample_methods": items[:5]}
            for key, items in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0]))
            if len(items) > 1
        ]

    duplicate_hashes = duplicate_groups(hash_groups)
    duplicate_offsets = duplicate_groups(offset_groups)
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {
            "selected_methods": len(selected),
            "body_statuses": dict(sorted(status_counts.items())),
            "unique_il_hashes": len(hash_groups),
            "unique_file_offsets": len(offset_groups),
            "duplicate_il_hash_groups": len(duplicate_hashes),
            "duplicate_file_offset_groups": len(duplicate_offsets),
            "throw_without_return": throw_without_return,
        },
        "duplicate_il_hashes": duplicate_hashes,
        "duplicate_file_offsets": duplicate_offsets,
        "limitations": [
            "Duplicate body hashes or file offsets are observations about the retained REA output, not proof of runtime equivalence.",
            "This report does not execute, patch, or bypass guard code and does not infer a save-file layout.",
        ],
    }


def managed_body_fidelity_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    """Return managed-body distinctness evidence from a retained REA bundle."""

    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read managed-members bundle: {path}") from exc
    try:
        return managed_body_fidelity_report_from_bundle(bundle, pattern)
    except re.error as exc:
        raise ValueError(f"invalid managed-body regex: {pattern}") from exc


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

    def method_role(name: str) -> str:
        lowered = name.casefold()
        if lowered.startswith("get_") or lowered.startswith("set_"):
            return "property"
        if lowered.startswith("read"):
            return "read"
        if lowered.startswith("write"):
            return "write"
        if lowered.startswith("load"):
            return "load"
        if lowered.startswith("save"):
            return "save"
        if lowered.startswith("compress"):
            return "compress"
        if lowered.startswith("decompress"):
            return "decompress"
        return "other"

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
        opcode_counts = body.get("opcode_counts") or {}
        structural_stub_opcodes = {"ldstr", "newobj", "throw"}
        observed_opcodes = {str(opcode) for opcode, count in opcode_counts.items() if count}
        if body.get("status") in {None, "unavailable", "unknown"}:
            implementation_readiness = "body-unavailable"
        elif observed_opcodes and observed_opcodes <= structural_stub_opcodes and opcode_counts.get("throw", 0):
            implementation_readiness = "throw-only-stub"
        else:
            implementation_readiness = "observed-body"
        contracts.append({
            "declaring_type": item.get("declaring_type"),
            "name": item.get("name"),
            "role": method_role(str(item.get("name") or "")),
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
            "implementation_readiness": implementation_readiness,
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
    family_counts: dict[str, dict[str, int]] = {}
    role_counts: dict[str, int] = {}
    readiness_counts: dict[str, int] = {}
    for type_name in sorted(selected_names):
        parts = type_name.split(".")
        if len(parts) >= 3 and parts[:2] == ["Horizon", "PackageEditors"]:
            family = ".".join(parts[:3])
            family_counts.setdefault(family, {"types": 0, "methods": 0})["types"] += 1
    for contract in contracts:
        role = str(contract["role"])
        role_counts[role] = role_counts.get(role, 0) + 1
        readiness = str(contract["implementation_readiness"])
        readiness_counts[readiness] = readiness_counts.get(readiness, 0) + 1
        type_name = str(contract.get("declaring_type") or "")
        parts = type_name.split(".")
        if len(parts) >= 3 and parts[:2] == ["Horizon", "PackageEditors"]:
            family = ".".join(parts[:3])
            family_counts.setdefault(family, {"types": 0, "methods": 0})["methods"] += 1
            readiness = str(contract["implementation_readiness"])
            readiness_counts_for_family = family_counts[family].setdefault("implementation_readiness", {})
            readiness_counts_for_family[readiness] = readiness_counts_for_family.get(readiness, 0) + 1
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
        "family_counts": [
            {"family": family, **counts}
            for family, counts in sorted(family_counts.items())
        ],
        "role_counts": {role: role_counts[role] for role in sorted(role_counts)},
        "implementation_readiness_counts": {
            status: readiness_counts[status] for status in sorted(readiness_counts)
        },
        "methods": contracts,
        "limitations": [
            "CIL anchors and tokens are artifact-local evidence, not a serializer implementation.",
            "throw-only-stub is a structural classification of retained body opcodes, not a claim about runtime intent.",
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

