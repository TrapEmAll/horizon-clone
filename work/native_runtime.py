"""Provider boundary for the observed DNG/HVM native declarations.

The managed evidence establishes return and parameter types, but not the
meaning of the native arguments.  The adapter therefore keeps raw integer
arguments and requires an explicit provider supplied by the caller.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .native_loader import compatible_pe_architecture


class NativeRuntimeProvider(Protocol):
    def check_runtime(self) -> bool:
        ...

    def check_runtime64(self) -> bool:
        ...

    def run_hvm(self) -> int:
        ...

    def get_user_string(self, arg0: int, arg1: int, arg2: int) -> int:
        ...

    def get_user_string64(self, arg0: int, arg1: int, arg2: int) -> int:
        ...


class NativeRuntimeUnavailable(RuntimeError):
    """Raised when no explicit compatible native runtime was supplied."""


class PowerShellNativeRuntimeProvider:
    """Invoke the observed runtime exports through an explicit PowerShell host.

    The provider binds only the declarations recovered by REA.  It does not
    infer the meaning of the native handles or strings and does not search for
    DLLs.  The caller must select the matching image and host architecture.
    """

    def __init__(
        self,
        dll_path: str | Path,
        *,
        powershell_path: str | Path | None = None,
        host_architecture: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        path = Path(dll_path)
        if not path.is_absolute():
            raise ValueError("runtime DLL path must be absolute")
        if not path.is_file():
            raise FileNotFoundError(path)
        architecture, _ = compatible_pe_architecture(path)
        if architecture not in {"x86", "x86_64"}:
            raise OSError(f"runtime DLL must be x86 or x86_64, got {architecture}")
        if host_architecture is not None and host_architecture not in {"x86", "x86_64"}:
            raise ValueError("host_architecture must be x86 or x86_64")
        if host_architecture is not None and host_architecture != architecture:
            raise OSError(f"runtime DLL architecture {architecture} does not match host {host_architecture}")
        default_host = (
            Path(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
            if architecture == "x86"
            else Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        )
        host = Path(powershell_path) if powershell_path else default_host
        if not host.is_file():
            raise FileNotFoundError(host)
        self.path = path
        self.powershell_path = host
        self.architecture = architecture
        self.timeout = timeout

    def _invoke(self, operation: str, arg0: int = 0, arg1: int = 0, arg2: int = 0) -> int | bool:
        if operation not in {"CheckRuntime", "RunHVM", "GetUserString"}:
            raise ValueError(f"unknown runtime operation: {operation}")
        for name, value in (("arg0", arg0), ("arg1", arg1), ("arg2", arg2)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
        path_literal = str(self.path).replace('"', '""')
        code = f'''using System; using System.Runtime.InteropServices; public static class HorizonRuntimeHost {{
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.StdCall, EntryPoint="DNG_Runtime")] public static extern bool CheckRuntime();
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.StdCall, EntryPoint="RunHVM")] public static extern IntPtr RunHVM();
 [DllImport(@"{path_literal}", CallingConvention=CallingConvention.StdCall, EntryPoint="GetUserString")] public static extern IntPtr GetUserString(IntPtr a0,int a1,int a2); }}'''
        script = """
$ErrorActionPreference = 'Stop'
$code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CODE__'))
Add-Type -TypeDefinition $code
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
switch ($request.operation) {
  'CheckRuntime' { $value = [HorizonRuntimeHost]::CheckRuntime(); $kind = 'bool' }
  'RunHVM' { $value = [HorizonRuntimeHost]::RunHVM().ToInt64(); $kind = 'int64' }
  'GetUserString' { $value = [HorizonRuntimeHost]::GetUserString([IntPtr]$request.arg0,[int]$request.arg1,[int]$request.arg2).ToInt64(); $kind = 'int64' }
  default { throw 'unknown runtime operation' }
}
[pscustomobject]@{ kind = $kind; value = $value } | ConvertTo-Json -Compress
""".replace("__CODE__", base64.b64encode(code.encode("utf-8")).decode("ascii"))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        completed = subprocess.run(
            [str(self.powershell_path), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            input=json.dumps({"operation": operation, "arg0": arg0, "arg1": arg1, "arg2": arg2}),
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode:
            detail = " | ".join(part for part in (completed.stderr.strip(), completed.stdout.strip()) if part)
            raise OSError(f"native runtime provider failed: {detail}")
        try:
            result = json.loads(completed.stdout.strip().splitlines()[-1])
            kind = str(result["kind"])
            value = result["value"]
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OSError("native runtime provider returned malformed output") from exc
        if kind == "bool":
            if not isinstance(value, bool):
                raise OSError("native runtime provider returned a non-boolean CheckRuntime result")
            return value
        if not isinstance(value, int) or isinstance(value, bool) or not -0x8000000000000000 <= value <= 0x7FFFFFFFFFFFFFFF:
            raise OSError("native runtime provider returned an invalid native-int result")
        return value

    def check_runtime(self) -> bool:
        return bool(self._invoke("CheckRuntime"))

    def check_runtime64(self) -> bool:
        """Invoke the observed export contract on an explicitly supplied x64 image."""

        return bool(self._invoke("CheckRuntime"))

    def run_hvm(self) -> int:
        return int(self._invoke("RunHVM"))

    def get_user_string(self, arg0: int, arg1: int, arg2: int) -> int:
        return int(self._invoke("GetUserString", arg0, arg1, arg2))

    def get_user_string64(self, arg0: int, arg1: int, arg2: int) -> int:
        """Invoke the HVMRun64 string boundary without decoding its handle."""

        return int(self._invoke("GetUserString", arg0, arg1, arg2))


@dataclass(frozen=True)
class NativeRuntimeBinding:
    provider: NativeRuntimeProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def check_runtime(self) -> bool:
        return self._require().check_runtime()

    def check_runtime64(self) -> bool:
        return self._require().check_runtime64()

    def run_hvm(self) -> int:
        return self._require().run_hvm()

    def get_user_string(self, arg0: int, arg1: int, arg2: int) -> int:
        return self._require().get_user_string(arg0, arg1, arg2)

    def get_user_string64(self, arg0: int, arg1: int, arg2: int) -> int:
        return self._require().get_user_string64(arg0, arg1, arg2)

    def _require(self) -> NativeRuntimeProvider:
        if self.provider is None:
            raise NativeRuntimeUnavailable(
                "DNG/HVM runtime requires an explicit compatible provider"
            )
        return self.provider


