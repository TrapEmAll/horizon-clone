"""Provider boundary for the LZO imports observed by REA.

The managed declarations establish buffer shapes and return types only. This
module deliberately does not load ``lzo.dll`` or claim codec compatibility.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class Int32Ref:
    """Mutable stand-in for the native ``i4&`` argument."""

    value: int

    def __post_init__(self) -> None:
        _validate_i32(self.value, "Int32Ref.value")


class LzoProvider(Protocol):
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
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise OSError("lzo.dll provider requires Windows ctypes.WinDLL")
        self.path = path
        self._dll = loader(str(path))
        self._functions = {
            name: self._bind(name)
            for name in (
                "lzo1x_1_compress",
                "lzo2a_999_compress",
                "lzo1x_decompress",
                "lzo2a_decompress",
            )
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

    def _invoke(self, method: str, source: bytes, source_length: int, destination: bytearray, destination_length: Int32Ref, work_memory: bytes) -> int:
        if not isinstance(source, bytes) or not isinstance(destination, bytearray) or not isinstance(work_memory, bytes):
            raise TypeError("LZO source/work_memory must be bytes and destination must be bytearray")
        _validate_i32(source_length, "source_length")
        _validate_span(source_length, len(source), "source_length")
        _validate_span(destination_length.value, len(destination), "destination_length")
        result = getattr(self._require(), method)(source, source_length, destination, destination_length, work_memory)
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

