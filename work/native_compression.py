"""Provider boundary for the LZO imports observed by REA.

The managed declarations establish buffer shapes and return types only. This
module deliberately does not load ``lzo.dll`` or claim codec compatibility.
"""

from __future__ import annotations

import ctypes
import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from .native_loader import compatible_pe_architecture, require_compatible_pe_architecture
from typing import Protocol


@dataclass
class Int32Ref:
    """Mutable stand-in for the native ``i4&`` argument."""

    value: int

    def __post_init__(self) -> None:
        _validate_i32(self.value, "Int32Ref.value")


class LzoProvider(Protocol):
    def lzo_version_string(self) -> bytes | str: ...
    def lzo_version_date(self) -> bytes | str: ...
    def lzo1x_1_compress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int: ...
    def lzo2a_999_compress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int: ...
    def lzo1x_decompress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int: ...
    def lzo2a_decompress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int: ...


class LzoUnavailable(RuntimeError):
    """Raised when no explicit compatible LZO provider was supplied."""


class CtypesLzoProvider:
    """Explicit Windows adapter for the four REA-observed ``lzo.dll`` exports."""

    def __init__(self, dll_path: str | Path) -> None:
        path = Path(dll_path)
        if not path.is_absolute():
            raise ValueError("lzo.dll path must be absolute")
        if not path.is_file():
            raise FileNotFoundError(path)
        require_compatible_pe_architecture(path)
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise OSError("lzo.dll provider requires Windows ctypes.WinDLL")
        self.path = path
        try:
            self._dll = loader(str(path))
        except OSError as exc:
            raise OSError(
                f"unable to load explicit lzo.dll provider {path}; "
                "verify that the DLL architecture matches the Python process"
            ) from exc
        self._functions = {
            name: self._bind(name)
            for name in (
                "lzo1x_1_compress",
                "lzo2a_999_compress",
                "lzo1x_decompress",
                "lzo2a_decompress",
            )
        }
        self._version_functions = {
            name: self._bind_version(name)
            for name in ("lzo_version_string", "lzo_version_date")
        }

    def _bind(self, name: str):
        try:
            function = getattr(self._dll, name)
        except AttributeError as exc:
            raise OSError(f"{self.path} does not export {name}") from exc
        pointer = ctypes.POINTER(ctypes.c_ubyte)
        function.argtypes = (pointer, ctypes.c_int32, pointer, ctypes.POINTER(ctypes.c_int32), pointer)
        function.restype = ctypes.c_int32
        return function

    def _bind_version(self, name: str):
        try:
            function = getattr(self._dll, name)
        except AttributeError as exc:
            raise OSError(f"{self.path} does not export {name}") from exc
        function.argtypes = ()
        function.restype = ctypes.c_char_p
        return function

    def lzo_version_string(self) -> bytes:
        value = self._version_functions["lzo_version_string"]()
        if not value:
            raise OSError("lzo.dll returned no version string")
        return bytes(value)

    def lzo_version_date(self) -> bytes:
        value = self._version_functions["lzo_version_date"]()
        if not value:
            raise OSError("lzo.dll returned no version date")
        return bytes(value)

    @staticmethod
    def _input(value: bytes):
        if not value:
            raise ValueError("LZO source/work memory must be non-empty")
        return (ctypes.c_ubyte * len(value)).from_buffer_copy(value)

    @staticmethod
    def _output(value: bytearray):
        if not value:
            raise ValueError("LZO destination must be non-empty")
        return (ctypes.c_ubyte * len(value)).from_buffer(value)

    def _invoke(self, name: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        source_buffer = self._input(source)
        destination_buffer = self._output(destination)
        work_buffer = self._input(work_memory)
        native_length = ctypes.c_int32(destination_length.value)
        result = self._functions[name](source_buffer, source_length, destination_buffer, ctypes.byref(native_length), work_buffer)
        destination_length.value = native_length.value
        return int(result)

    def lzo1x_1_compress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        return self._invoke("lzo1x_1_compress", source, source_length, destination, destination_length, work_memory)

    def lzo2a_999_compress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        return self._invoke("lzo2a_999_compress", source, source_length, destination, destination_length, work_memory)

    def lzo1x_decompress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        return self._invoke("lzo1x_decompress", source, source_length, destination, destination_length, work_memory)

    def lzo2a_decompress(self, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        return self._invoke("lzo2a_decompress", source, source_length, destination, destination_length, work_memory)


class PowerShellLzoProvider:
    """Bridge the x86 LZO DLL through an explicit 32-bit PowerShell host.

    This is for hosts where the application process is x64 but the supplied
    native DLL is x86.  The DLL path and host path are explicit; no DLL search
    or Horizon process is used.  Keys and other secrets are not involved.
    """

    _OPERATIONS = {
        "lzo1x_1_compress": "lzo1x_1_compress",
        "lzo2a_999_compress": "lzo2a_999_compress",
        "lzo1x_decompress": "lzo1x_decompress",
        "lzo2a_decompress": "lzo2a_decompress",
    }

    def __init__(self, dll_path: str | Path, powershell_path: str | Path | None = None, timeout: float = 30.0) -> None:
        path = Path(dll_path)
        if not path.is_absolute():
            raise ValueError("lzo.dll path must be absolute")
        if not path.is_file():
            raise FileNotFoundError(path)
        architecture, _ = compatible_pe_architecture(path)
        if architecture != "x86":
            raise OSError(f"LZO DLL must be x86 for the 32-bit host, got {architecture}")
        host = Path(powershell_path) if powershell_path else Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
        if not host.is_file():
            raise FileNotFoundError(host)
        self.path = path
        self.powershell_path = host
        self.timeout = timeout
        self.architecture = architecture

    def _invoke(self, name: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        if name not in self._OPERATIONS:
            raise ValueError(f"unknown LZO operation: {name}")
        if not source or not work_memory:
            raise ValueError("LZO source/work memory must be non-empty")
        if name == "lzo2a_999_compress" and len(work_memory) < 262144:
            raise ValueError("the supplied lzo2a compressor requires at least 262144 bytes of work memory")
        if source_length < 0 or source_length > len(source):
            raise ValueError("source_length exceeds source")
        if destination_length.value < 0 or destination_length.value > len(destination):
            raise ValueError("destination_length exceeds destination")
        path_literal = str(self.path).replace('"', '""')
        code = f'''using System; using System.Runtime.InteropServices; public static class HorizonLzoHost {{
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern int lzo1x_1_compress(byte[] s,int sl,byte[] d,ref int dl,byte[] w);
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern int lzo2a_999_compress(byte[] s,int sl,byte[] d,ref int dl,byte[] w);
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern int lzo1x_decompress(byte[] s,int sl,byte[] d,ref int dl,byte[] w);
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern int lzo2a_decompress(byte[] s,int sl,byte[] d,ref int dl,byte[] w); }}'''
        script = """
$ErrorActionPreference = 'Stop'
$code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CODE__'))
Add-Type -TypeDefinition $code
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$source = [Convert]::FromBase64String($request.source)
$work = [Convert]::FromBase64String($request.work)
$destination = New-Object byte[] $request.capacity
$length = $request.capacity
$result = [HorizonLzoHost]::$($request.operation)($source, $request.source_length, $destination, [ref]$length, $work)
if ($length -lt 0 -or $length -gt $destination.Length) { throw 'native LZO returned an invalid output length' }
[pscustomobject]@{ result = $result; length = $length; output = [Convert]::ToBase64String($destination, 0, $length) } | ConvertTo-Json -Compress
"""
        values = {
            "__CODE__": base64.b64encode(code.encode("utf-8")).decode("ascii"),
        }
        for marker, value in values.items():
            script = script.replace(marker, value)
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        completed = subprocess.run(
            [str(self.powershell_path), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            input=json.dumps({
                "source": base64.b64encode(source[:source_length]).decode("ascii"),
                "work": base64.b64encode(work_memory).decode("ascii"),
                "capacity": destination_length.value,
                "operation": self._OPERATIONS[name],
                "source_length": source_length,
            }),
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode:
            detail = " | ".join(part for part in (completed.stderr.strip(), completed.stdout.strip()) if part)
            raise OSError(f"32-bit LZO provider failed: {detail}")
        try:
            result = json.loads(completed.stdout.strip().splitlines()[-1])
            output = base64.b64decode(result["output"], validate=True)
            native_length = int(result["length"])
            status = int(result["result"])
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            raise OSError("32-bit LZO provider returned malformed output") from exc
        if native_length != len(output) or native_length > len(destination):
            raise OSError("32-bit LZO provider returned an invalid output length")
        destination[:native_length] = output
        destination_length.value = native_length
        return status

    def _invoke_version(self, name: str) -> str:
        if name not in {"lzo_version_string", "lzo_version_date"}:
            raise ValueError(f"unknown LZO version operation: {name}")
        path_literal = str(self.path).replace('"', '""')
        code = f'''using System; using System.Runtime.InteropServices; public static class HorizonLzoVersionHost {{
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern IntPtr lzo_version_string();
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.Cdecl)] public static extern IntPtr lzo_version_date(); }}'''
        script = """
$ErrorActionPreference = 'Stop'
$code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CODE__'))
Add-Type -TypeDefinition $code
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$pointer = [HorizonLzoVersionHost]::$($request.operation)()
if ($pointer -eq [IntPtr]::Zero) { throw 'native LZO returned a null version pointer' }
[pscustomobject]@{ value = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($pointer) } | ConvertTo-Json -Compress
"""
        script = script.replace("__CODE__", base64.b64encode(code.encode("utf-8")).decode("ascii"))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        completed = subprocess.run(
            [str(self.powershell_path), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            input=json.dumps({"operation": name}),
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode:
            detail = " | ".join(part for part in (completed.stderr.strip(), completed.stdout.strip()) if part)
            raise OSError(f"32-bit LZO version provider failed: {detail}")
        try:
            value = json.loads(completed.stdout.strip().splitlines()[-1])["value"]
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OSError("32-bit LZO version provider returned malformed output") from exc
        if not isinstance(value, str) or not value:
            raise OSError("32-bit LZO version provider returned an invalid value")
        return value

    def lzo_version_string(self) -> str:
        return self._invoke_version("lzo_version_string")

    def lzo_version_date(self) -> str:
        return self._invoke_version("lzo_version_date")

    def lzo1x_1_compress(self, source, source_length, destination, destination_length, work_memory):
        return self._invoke("lzo1x_1_compress", source, source_length, destination, destination_length, work_memory)

    def lzo2a_999_compress(self, source, source_length, destination, destination_length, work_memory):
        return self._invoke("lzo2a_999_compress", source, source_length, destination, destination_length, work_memory)

    def lzo1x_decompress(self, source, source_length, destination, destination_length, work_memory):
        return self._invoke("lzo1x_decompress", source, source_length, destination, destination_length, work_memory)

    def lzo2a_decompress(self, source, source_length, destination, destination_length, work_memory):
        return self._invoke("lzo2a_decompress", source, source_length, destination, destination_length, work_memory)


@dataclass(frozen=True)
class LzoBinding:
    provider: LzoProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def compress(self, variant: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        method = {"lzo1x_1": "lzo1x_1_compress", "lzo2a_999": "lzo2a_999_compress"}.get(variant)
        if method is None:
            raise ValueError(f"unknown LZO compressor: {variant}")
        return self._invoke(method, source, source_length, destination, destination_length, work_memory)

    def decompress(self, variant: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        method = {"lzo1x": "lzo1x_decompress", "lzo2a": "lzo2a_decompress"}.get(variant)
        if method is None:
            raise ValueError(f"unknown LZO decompressor: {variant}")
        return self._invoke(method, source, source_length, destination, destination_length, work_memory)

    def version_string(self) -> str:
        return self._version("lzo_version_string")

    def version_date(self) -> str:
        return self._version("lzo_version_date")

    def _version(self, method: str) -> str:
        provider = self._require()
        value = getattr(provider, method, None)
        if value is None:
            raise LzoUnavailable(f"explicit LZO provider does not expose {method}")
        result = value()
        if isinstance(result, bytes):
            result = result.decode("ascii", errors="strict")
        if not isinstance(result, str) or not result:
            raise ValueError(f"LZO provider returned an invalid {method} value")
        return result

    def _invoke(self, method: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        if not isinstance(source, bytes) or not isinstance(destination, bytearray) or not isinstance(work_memory, bytes):
            raise TypeError("LZO source/work_memory must be bytes and destination must be bytearray")
        _validate_i32(source_length, "source_length")
        _validate_span(source_length, len(source), "source_length")
        _validate_span(destination_length.value, len(destination), "destination_length")
        result = getattr(self._require(), method)(source, source_length, destination, destination_length, work_memory)
        _validate_i32(destination_length.value, "destination_length")
        _validate_span(destination_length.value, len(destination), "provider destination_length")
        return _validate_i32(result, "provider result")

    def _require(self) -> LzoProvider:
        if self.provider is None:
            raise LzoUnavailable("LZO operations require an explicit compatible provider")
        return self.provider


def _validate_i32(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not -0x80000000 <= value <= 0x7FFFFFFF:
        raise ValueError(f"{name} must be a signed 32-bit integer")
    return value


def _validate_span(value: int, capacity: int, name: str) -> None:
    """Validate a managed array length before crossing the provider boundary."""

    if value < 0 or value > capacity:
        raise ValueError(f"{name} exceeds its supplied buffer")

