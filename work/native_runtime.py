"""Provider boundary for the observed DNG/HVM native declarations.

The managed evidence establishes return and parameter types, but not the
meaning of the native arguments.  The adapter therefore keeps raw integer
arguments and requires an explicit provider supplied by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class NativeRuntimeProvider(Protocol):
    def check_runtime(self) -> bool:
        ...

    def run_hvm(self) -> int:
        ...

    def get_user_string(self, arg0: int, arg1: int, arg2: int) -> int:
        ...


class NativeRuntimeUnavailable(RuntimeError):
    """Raised when no explicit compatible native runtime was supplied."""


@dataclass(frozen=True)
class NativeRuntimeBinding:
    provider: NativeRuntimeProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def check_runtime(self) -> bool:
        return self._require().check_runtime()

    def run_hvm(self) -> int:
        return self._require().run_hvm()

    def get_user_string(self, arg0: int, arg1: int, arg2: int) -> int:
        return self._require().get_user_string(arg0, arg1, arg2)

    def _require(self) -> NativeRuntimeProvider:
        if self.provider is None:
            raise NativeRuntimeUnavailable(
                "DNG/HVM runtime requires an explicit compatible provider"
            )
        return self.provider


