"""Explicit provider boundary for the observed class3 save declarations.

REA recovered the managed shapes of ``RtsSaveDecrypt`` and
``RtsSaveEncrypt`` but not their algorithm, buffer ownership, or key format.
This module models only those shapes. It never loads ``class3.dll`` and does
not interpret or persist key material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class UInt32Ref:
    """Mutable stand-in for the native ``u4&`` argument."""

    value: int

    def __post_init__(self) -> None:
        _validate_u32(self.value, "UInt32Ref.value")


class NativeSaveProvider(Protocol):
    def rts_save_decrypt(self, input_buffer: bytes, output_length: UInt32Ref, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        ...

    def rts_save_encrypt(self, input_buffer: bytes, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        ...


class NativeSaveUnavailable(RuntimeError):
    """Raised when no explicit compatible save provider was supplied."""


@dataclass(frozen=True)
class NativeSaveBinding:
    provider: NativeSaveProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def decrypt(self, input_buffer: bytes, output_length: UInt32Ref, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        _validate_buffers(input_buffer, output_buffer, key)
        _validate_u32(input_length, "input_length")
        _validate_span(input_length, len(input_buffer), "input_length")
        _validate_span(output_length.value, len(output_buffer), "output_length")
        result = self._require().rts_save_decrypt(input_buffer, output_length, output_buffer, input_length, key)
        return _validate_i32_result(result)

    def encrypt(self, input_buffer: bytes, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        _validate_buffers(input_buffer, output_buffer, key)
        _validate_u32(input_length, "input_length")
        _validate_span(input_length, len(input_buffer), "input_length")
        result = self._require().rts_save_encrypt(input_buffer, output_buffer, input_length, key)
        return _validate_i32_result(result)

    def _require(self) -> NativeSaveProvider:
        if self.provider is None:
            raise NativeSaveUnavailable("class3.dll save operations require an explicit compatible provider")
        return self.provider


def _validate_buffers(input_buffer: bytes, output_buffer: bytearray, key: bytes) -> None:
    if not isinstance(input_buffer, bytes):
        raise TypeError("input_buffer must be bytes")
    if not isinstance(output_buffer, bytearray):
        raise TypeError("output_buffer must be bytearray")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")


def _validate_u32(value: int, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be an unsigned 32-bit integer")


def _validate_i32_result(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not -0x80000000 <= value <= 0x7FFFFFFF:
        raise ValueError("native save provider result must be a signed 32-bit integer")
    return value


def _validate_span(value: int, capacity: int, name: str) -> None:
    if value > capacity:
        raise ValueError(f"{name} exceeds its supplied buffer")

