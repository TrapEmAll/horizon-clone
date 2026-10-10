"""Provider boundary for the LZO imports observed by REA.

The managed declarations establish buffer shapes and return types only. This
module deliberately does not load ``lzo.dll`` or claim codec compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass
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

