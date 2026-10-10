"""Evidence-qualified native boundary inventory for the Horizon executable.

The managed assembly declares native imports for save encryption, LZO
compression, device I/O, and the DNG/HVM runtime.  This module records those
imports without guessing calling signatures or loading the supplied DLLs.
Implementations may register an authorized provider for a specific boundary;
the default report remains declaration-only until that provider is available.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from pathlib import Path
from typing import Any

from .native_loader import compatible_pe_architecture, pe_export_names


@dataclass(frozen=True)
class NativeImport:
    module: str
    import_name: str
    managed_member: str
    parameter_types: tuple[str, ...] = ()
    return_type: str | None = None
    signature_status: str = "unresolved"


@dataclass(frozen=True)
class NativeBoundaryCaller:
    caller: str
    caller_token: str
    native_module: str
    import_name: str
    native_token: str


_IMPORTS = (
    NativeImport("class3.dll", "RtsSaveDecrypt", "cca5cc966e0f636907b7609991eb6fc5b", ("u1[]", "u4&", "u1[]", "u4", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("class3.dll", "RtsSaveEncrypt", "cd77fe1cb3b73087691882c6c7f2294c8", ("u1[]", "u1[]", "u4", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("lzo.dll", "__lzo_init_v2", "c0c113c5b2dcd0f3b7041c50ec2ceca26"),
    NativeImport("lzo.dll", "lzo1x_1_compress", "ceefcc0a79577b3961c571ae5e197fc4d", ("u1[]", "i4", "u1[]", "i4&", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("lzo.dll", "lzo1x_decompress", "c6a7a33e36ec95e3930e66c20d863eb7f", ("u1[]", "i4", "u1[]", "i4&", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("lzo.dll", "lzo2a_decompress", "ca7e2a3a612f9a47075525bd9737590ca", ("u1[]", "i4", "u1[]", "i4&", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("lzo.dll", "lzo2a_999_compress", "c0a7807f4177e6edf7a13748212d100ed", ("u1[]", "i4", "u1[]", "i4&", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("Horizon.dll", "DNG_Runtime", "CheckRuntime", (), "bool", "managed-signature-observed"),
    NativeImport("HVMRun64.dll", "DNG_Runtime", "CheckRuntime64", (), "bool", "managed-signature-observed"),
    NativeImport("Horizon.dll", "RunHVM", "RunHVM", (), "native-int", "managed-signature-observed"),
    NativeImport("Horizon.dll", "GetUserString", "GetUserString", ("native-int", "i4", "i4"), "native-int", "managed-signature-observed"),
    NativeImport("HVMRun64.dll", "GetUserString", "GetUserString64", ("native-int", "i4", "i4"), "native-int", "managed-signature-observed"),
    NativeImport("kernel32.dll", "CreateFile", "c6b0c273b82304b5a7930d023f4216ef6"),
    NativeImport("kernel32.dll", "DeviceIoControl", "c6fa7d4b3e02e746aa7ff333d58c9bc69"),
    NativeImport("kernel32.dll", "OpenProcess", "c03042ece34c27ba1a806575444d50397"),
    NativeImport("kernel32.dll", "GetCurrentProcessId", "c93158a15d45229fd20b89d9a0549739a"),
    NativeImport("kernel32.dll", "LoadLibrary", "cf679fd9f6c59e8ef69de1d0a13a66a92"),
    NativeImport("kernel32.dll", "GetProcAddress", "cd5b905efc1f972f4e17985a4f93487d0"),
    NativeImport("user32.dll", "GetClassName", "c79f42735c598892acba3928571d69719"),
    NativeImport("User32.dll", "SetClipboardViewer", "ca843b1fae2e630a858573abd0826d0d2"),
    NativeImport("User32.dll", "ChangeClipboardChain", "c031773323c946cba8fa553af87e9c225"),
    NativeImport("user32.dll", "SendMessage", "ca6af21fb32f06ee8a4cad76df8da9681"),
    NativeImport("Shell32.dll", "SHChangeNotify", "c9d1bfd4854791d5b37464b00e07a8500"),
    NativeImport("dwmapi.dll", "DwmIsCompositionEnabled", "cb03e5b098e17d04852dd273c74367631"),
)


_CALLERS = (
    NativeBoundaryCaller(
        "A.cd936781820a998f272eb4df3bd2b8c2a.Startup",
        "0x060083ff",
        "Horizon.dll",
        "DNG_Runtime",
        "0x060083f8",
    ),
    NativeBoundaryCaller(
        "A.cd936781820a998f272eb4df3bd2b8c2a.Startup",
        "0x060083ff",
        "HVMRun64.dll",
        "DNG_Runtime",
        "0x060083f9",
    ),
    NativeBoundaryCaller(
        "A.cd9276f49d88a260398f12b2584c549ca.CheckString",
        "0x060083f6",
        "Horizon.dll",
        "GetUserString",
        "0x060083fd",
    ),
    NativeBoundaryCaller(
        "A.cd9276f49d88a260398f12b2584c549ca.CheckString",
        "0x060083f6",
        "HVMRun64.dll",
        "GetUserString",
        "0x060083fe",
    ),
    NativeBoundaryCaller(
        "A.cd9875b4b93f8a70f17be0ebd9671669a.ZYXDNGuard",
        "0x060084ae",
        "lzo.dll",
        "__lzo_init_v2",
        "0x060004ba",
    ),
)


def observed_native_imports() -> tuple[NativeImport, ...]:
    """Return the exact deduplicated imports retained from REA evidence."""

    return _IMPORTS


def observed_native_callers() -> tuple[NativeBoundaryCaller, ...]:
    """Return REA-resolved managed-to-native call edges."""

    return _CALLERS


def native_surface_report() -> dict[str, object]:
    """Describe native dependencies without claiming their implementation."""

    groups: dict[str, list[dict[str, str]]] = {}
    for item in _IMPORTS:
        groups.setdefault(item.module, []).append(asdict(item))
    return {
        "status": "declaration-only",
        "observed_module_ref_count": 14,
        "observed_pinvoke_count": 54,
        "imports": [asdict(item) for item in _IMPORTS],
        "managed_callers": [asdict(item) for item in _CALLERS],
        "modules": groups,
        "unresolved": [
            "native calling signatures",
            "class3.dll save-encryption semantics",
            "DNG/HVM runtime protocol",
            "device IOCTL protocol",
        ],
    }


def native_export_contract_report(path: str | Path) -> dict[str, object]:
    """Compare one supplied native image with its REA-observed export contract."""

    source = Path(path)
    expected_by_name = {
        "class3.dll": ("RtsSaveDecrypt", "RtsSaveEncrypt"),
        "lzo.dll": ("__lzo_init_v2", "lzo1x_1_compress", "lzo2a_999_compress", "lzo1x_decompress", "lzo2a_decompress"),
        "horizon.dll": ("CheckRuntime", "DNG_Runtime", "GetUserString", "RunHVM"),
    }
    expected = expected_by_name.get(source.name.lower(), ())
    exports = pe_export_names(source)
    missing = [name for name in expected if name not in exports]
    return {
        "path": str(source),
        "image_architecture": compatible_pe_architecture(source)[0],
        "expected_exports": list(expected),
        "observed_exports": list(exports),
        "missing_exports": missing,
        "status": "verified" if expected and not missing else "unresolved",
        "limitations": [
            "Export presence does not establish native calling semantics or codec/save algorithms.",
            "Unknown filenames have no authenticated contract in the current REA evidence.",
        ],
    }


def managed_native_import_report_from_bundle(bundle: dict[str, Any], pattern: str | None = None) -> dict[str, Any]:
    """Return the complete REA-authenticated managed P/Invoke inventory."""

    records = bundle.get("records")
    if not isinstance(records, list):
        raise ValueError("evidence bundle does not contain a records array")
    candidates = [
        record for record in records
        if isinstance(record, dict) and record.get("operation") == "inspect_managed_native_boundaries"
    ]
    if not candidates:
        raise ValueError("evidence bundle has no managed native-boundary record")
    record = max(candidates, key=lambda item: len(item.get("normalized_result", {}).get("pinvoke_imports", [])))
    imports = record.get("normalized_result", {}).get("pinvoke_imports", [])
    matcher = None
    if pattern is not None:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid native-import regex: {pattern}") from exc
    selected = [
        {
            "import_scope_name": item.get("import_scope_name"),
            "import_name": item.get("import_name"),
            "member_name": item.get("member_name"),
            "member_token": item.get("member_token"),
            "call_convention": item.get("call_convention"),
            "char_set": item.get("char_set"),
            "verification": item.get("verification"),
        }
        for item in imports
        if isinstance(item, dict)
        and (matcher is None or matcher.search(f"{item.get('import_scope_name', '')}!{item.get('import_name', '')}"))
    ]
    return {
        "status": "observed-only",
        "authority": "shipped-artifact",
        "evidence_id": record.get("evidence_id"),
        "pattern": pattern,
        "counts": {"matched": len(selected), "total": len(imports)},
        "imports": selected,
        "limitations": [
            "P/Invoke metadata proves managed declarations only; it does not prove a loaded DLL, implementation, or runtime call behavior.",
            "Calling convention and character-set metadata remain declaration evidence, not native protocol verification.",
        ],
    }


def managed_native_import_report(bundle_path: str | Path, pattern: str | None = None) -> dict[str, Any]:
    path = Path(bundle_path)
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read evidence bundle: {path}") from exc
    return managed_native_import_report_from_bundle(bundle, pattern)


