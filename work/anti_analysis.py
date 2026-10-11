"""Evidence-only report of managed anti-analysis markers observed by REA."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .native_loader import compatible_pe_architecture, pe_import_table


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
    debugger_api_names = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
    }
    observed_call_targets = sorted({
        str(anchor.get("operand"))
        for item in guarded_methods
        for anchor in (item.get("body") or {}).get("anchors", [])
        if isinstance(anchor, dict) and anchor.get("opcode") == "call" and anchor.get("operand")
    })
    debugger_api_calls = [
        target for target in observed_call_targets
        if any(name.casefold() in target.casefold() for name in debugger_api_names)
    ]
    guard_dispatch_stubs = []
    for item in guarded_methods:
        body = item.get("body") or {}
        counts = body.get("opcode_counts") or {}
        anchors = body.get("anchors") or []
        call_targets = [
            anchor.get("operand")
            for anchor in anchors
            if anchor.get("opcode") == "call" and anchor.get("operand")
        ]
        constants = [
            anchor.get("operand")
            for anchor in anchors
            if anchor.get("operand_kind") == "constant"
        ]
        # This is deliberately a structural classification.  It records the
        # repeated guard-dispatch shape without interpreting the constants or
        # attempting to neutralize the call target.
        if (
            "Guard" in str(item.get("declaring_type") or "")
            and counts.get("call") == 1
            and counts.get("ret") == 1
            and len(constants) >= 2
            and call_targets
        ):
            guard_dispatch_stubs.append(
                {
                    "declaring_type": item.get("declaring_type"),
                    "name": item.get("name"),
                    "token": item.get("token"),
                    "rva": item.get("rva"),
                    "call_target": call_targets[0],
                    "constant_operands": constants,
                    "il_sha256": body.get("il_sha256"),
                    "classification": "guard-dispatch-stub",
                }
            )
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
        "guard_dispatch_stub_count": len(guard_dispatch_stubs),
        "guard_dispatch_stubs": guard_dispatch_stubs,
        "debugger_api_calls": debugger_api_calls,
        "debugger_api_presence": "observed" if debugger_api_calls else "not-observed-in-retained-call-edges",
        "analysis_workaround": {
            "mode": "static-and-controlled-runtime-only",
            "target_execution": "not-executed",
            "protection_patching": "not-performed",
        },
        "limitations": [
            "Static metadata does not establish runtime anti-debug behavior or intent.",
            "Absence of a debugger API in retained call edges is not proof that no indirect or native check exists.",
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


def native_anti_analysis_report(path: str | Path) -> dict[str, Any]:
    """Report anti-analysis-related native imports without loading the image."""

    source = Path(path)
    imports = list(pe_import_table(source))
    names = sorted({str(item["import_name"]) for item in imports if item.get("import_name")})
    debugger_apis = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "_crt_debugger_hook",
    }
    process_probe_apis = {
        "OpenProcess",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "QueryPerformanceCounter",
        "GetTickCount",
    }
    dynamic_resolution_apis = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}
    memory_protection_apis = {"VirtualProtect", "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx", "IsBadReadPtr", "IsBadWritePtr"}
    return {
        "status": "observed-only",
        "path": str(source),
        "artifact_sha256": __import__("hashlib").sha256(source.read_bytes()).hexdigest(),
        "image_architecture": compatible_pe_architecture(source)[0],
        "import_count": len(imports),
        "debugger_api_imports": sorted(set(names) & debugger_apis),
        "process_probe_imports": sorted(set(names) & process_probe_apis),
        "dynamic_resolution_imports": sorted(set(names) & dynamic_resolution_apis),
        "memory_protection_imports": sorted(set(names) & memory_protection_apis),
        "analysis_workaround": {
            "mode": "static-import-table-only",
            "target_execution": "not-executed",
            "protection_patching": "not-performed",
        },
        "limitations": [
            "An imported API does not prove that every call path reaches it or establish its runtime arguments.",
            "Indirect calls, delay-load imports, and dynamically resolved symbols are not complete in this report.",
            "This report does not disable, patch, or bypass anti-analysis behavior.",
        ],
    }

