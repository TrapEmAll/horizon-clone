"""Evidence-qualified native boundary inventory for the Horizon executable.

The managed assembly declares native imports for save encryption, LZO
compression, device I/O, and the DNG/HVM runtime.  This module records those
imports without guessing calling signatures or loading the supplied DLLs.
Implementations may register an authorized provider for a specific boundary;
the default report remains declaration-only until that provider is available.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
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
    NativeImport("mscoree.dll", "StrongNameSignatureVerificationEx", "c8d325a235ad83752f6bb854a87baa830"),
    NativeImport("mscoree.dll", "CLRCreateInstance", "c15c3f92ac2dbeb716090d8a7713f8cac"),
    NativeImport("class3.dll", "RtsSaveDecrypt", "cca5cc966e0f636907b7609991eb6fc5b", ("u1[]", "u4&", "u1[]", "u4", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("class3.dll", "RtsSaveEncrypt", "cd77fe1cb3b73087691882c6c7f2294c8", ("u1[]", "u1[]", "u4", "u1[]"), "i4", "managed-signature-observed"),
    NativeImport("lzo.dll", "__lzo_init_v2", "c0c113c5b2dcd0f3b7041c50ec2ceca26"),
    NativeImport("lzo.dll", "lzo_version_string", "c393d046d6c7fc1668a41ecc1c8f242ab"),
    NativeImport("lzo.dll", "lzo_version_date", "c439d9e13e969dae72874a5547cb77e8d"),
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
    NativeImport("kernel32.dll", "SetLastError", "cbabdcaeac696c20e177cfb65fda8f350"),
    NativeImport("kernel32.dll", "CloseHandle", "cc3e1d047b154474ab86768e8191942e0"),
    NativeImport("kernel32.dll", "CreateBoundaryDescriptor", "c0b557dd8c3ec918a0cf18da3349090f8"),
    NativeImport("kernel32.dll", "AddSIDToBoundaryDescriptor", "cac6e04119a96de6baa5f4cb3ed3c3881"),
    NativeImport("kernel32.dll", "LocalFree", "ccb361c823d7d7bf3e3b3287c00f368f9"),
    NativeImport("kernel32.dll", "CreatePrivateNamespace", "cf170c19809d361546c62dccf355d66a0"),
    NativeImport("Kernel32.dll", "CreateFileMapping", "cdf5c7db571acbea31e678decf4e1b238"),
    NativeImport("Kernel32.dll", "MapViewOfFile", "c8242cc53a8f78a9ce7146f69a31b50f1"),
    NativeImport("advapi32.dll", "CreateWellKnownSid", "c1bf62f82eb1896117435a3b3b5f8b8fb"),
    NativeImport("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptor", "c031e24990e47bb8a3fa84c84d7647399"),
    NativeImport("msvcrt.dll", "memcpy", "c80af2ad771305818e53a5a186e50fd11"),
    NativeImport("msvcrt.dll", "memset", "ccf1f3902f876288b452ce4606087ed83"),
    NativeImport("kernel32.dll", "OpenProcess", "c03042ece34c27ba1a806575444d50397"),
    NativeImport("kernel32.dll", "GetCurrentProcessId", "c93158a15d45229fd20b89d9a0549739a"),
    NativeImport("kernel32.dll", "LoadLibrary", "cf679fd9f6c59e8ef69de1d0a13a66a92"),
    NativeImport("kernel32.dll", "GetProcAddress", "cd5b905efc1f972f4e17985a4f93487d0"),
    NativeImport("user32.dll", "GetClassName", "c79f42735c598892acba3928571d69719"),
    NativeImport("User32.dll", "SetClipboardViewer", "ca843b1fae2e630a858573abd0826d0d2"),
    NativeImport("User32.dll", "ChangeClipboardChain", "c031773323c946cba8fa553af87e9c225"),
    NativeImport("user32.dll", "SendMessage", "ca6af21fb32f06ee8a4cad76df8da9681"),
    NativeImport("user32.dll", "UpdateLayeredWindow", "cafa3318f0660c0d705e1aab5863bc0b5"),
    NativeImport("user32.dll", "GetDC", "c64db9e99c27aaee37f22789c7e6dfa42"),
    NativeImport("user32.dll", "ReleaseDC", "c7e9c4d82626f5f5054d17b81f52d2801"),
    NativeImport("gdi32.dll", "CreateCompatibleDC", "c3159e9b1190fa57babbe7ead91d4d97c"),
    NativeImport("gdi32.dll", "DeleteDC", "c34e3c638721b3ae1b56820439703b9bc"),
    NativeImport("gdi32.dll", "SelectObject", "cf9cec4a48c1189cd730ae43a5749d8b1"),
    NativeImport("gdi32.dll", "DeleteObject", "ce333808ce54d922c6e29894eefd51f05"),
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
        "unique_import_count": len(_IMPORTS),
        "imports": [asdict(item) for item in _IMPORTS],
        "managed_callers": [asdict(item) for item in _CALLERS],
        "modules": groups,
        "controlled_runtime_probes": [
            {"image": "Horizon.dll", "operation": "CheckRuntime", "arguments": [], "result": True, "result_kind": "bool", "status": "observed-on-supplied-installation"},
            {"image": "Horizon.dll", "operation": "RunHVM", "arguments": [], "result": 0, "result_kind": "native-int", "status": "observed-on-supplied-installation"},
            {"image": "Horizon.dll", "operation": "GetUserString", "arguments": [0, 1, 0], "result_class": "nonzero-native-int", "status": "observed-on-supplied-installation"},
            {"image": "Horizon.dll", "operation": "GetUserString", "arguments": [0, 0, 1], "result_class": "nonzero-native-int", "status": "observed-on-supplied-installation"},
            {"image": "Horizon.dll", "operation": "GetUserString", "arguments": [1, 0, 0], "result_class": "zero-native-int", "status": "observed-on-supplied-installation"},
        ],
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
        "hvmrun64.dll": ("CheckRuntime", "DNG_Runtime", "GetUserString", "RunHVM"),
    }
    expected = expected_by_name.get(source.name.lower(), ())
    exports = pe_export_names(source)
    missing = [name for name in expected if name not in exports]
    export_table_sha256 = hashlib.sha256("\n".join(exports).encode("utf-8")).hexdigest()
    artifact_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    return {
        "path": str(source),
        "artifact_sha256": artifact_sha256,
        "image_architecture": compatible_pe_architecture(source)[0],
        "export_count": len(exports),
        "export_table_sha256": export_table_sha256,
        "expected_exports": list(expected),
        "observed_exports": list(exports),
        "missing_exports": missing,
        "status": "verified" if expected and not missing else "unresolved",
        "limitations": [
            "Export presence does not establish native calling semantics or codec/save algorithms.",
            "Unknown filenames have no authenticated contract in the current REA evidence.",
        ],
    }


def native_installation_report(directory: str | Path) -> dict[str, object]:
    """Inventory the observed native deployment without loading any DLLs."""

    root = Path(directory)
    expected = {
        "class3.dll": ("x86", ("RtsSaveDecrypt", "RtsSaveEncrypt")),
        "lzo.dll": ("x86", ("__lzo_init_v2", "lzo1x_1_compress", "lzo2a_999_compress", "lzo1x_decompress", "lzo2a_decompress")),
        "Horizon.dll": ("x86", ("CheckRuntime", "DNG_Runtime", "GetUserString", "RunHVM")),
        "HVMRun64.dll": ("x86_64", ("CheckRuntime", "DNG_Runtime", "GetUserString", "RunHVM")),
    }
    images: list[dict[str, object]] = []
    for filename, (expected_architecture, expected_exports) in expected.items():
        path = root / filename
        item: dict[str, object] = {
            "name": filename,
            "path": str(path),
            "expected_architecture": expected_architecture,
            "expected_exports": list(expected_exports),
            "present": path.is_file(),
        }
        if path.is_file():
            try:
                architecture, process_architecture = compatible_pe_architecture(path)
                exports = pe_export_names(path)
                item.update({
                    "image_architecture": architecture,
                    "process_architecture": process_architecture,
                    "observed_exports": list(exports),
                    "missing_exports": [name for name in expected_exports if name not in exports],
                    "architecture_matches_contract": architecture == expected_architecture,
                })
            except (OSError, ValueError) as exc:
                item.update({"status": "unreadable", "error": str(exc)})
            else:
                item["status"] = "verified" if not item["missing_exports"] and item["architecture_matches_contract"] else "mismatch"
        else:
            item["status"] = "missing"
        images.append(item)
    present = sum(bool(item["present"]) for item in images)
    return {
        "status": "verified" if present == len(images) and all(item["status"] == "verified" for item in images) else "partial",
        "directory": str(root),
        "images": images,
        "present_count": present,
        "expected_count": len(images),
        "limitations": [
            "This inventory reads PE headers and export tables only; it never loads or executes a native image.",
            "Export presence does not establish native calling semantics or save/key-vault behavior.",
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


