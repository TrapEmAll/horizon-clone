"""Explicit provider boundary for the observed class3 save declarations.

REA recovered the managed shapes of ``RtsSaveDecrypt`` and
``RtsSaveEncrypt`` but not their algorithm, buffer ownership, or key format.
This module models only those shapes. It never loads ``class3.dll`` and does
not interpret or persist key material.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from pathlib import Path
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


class CtypesNativeSaveProvider:
    """Explicit Windows adapter for the REA-observed ``class3.dll`` exports.

    Construction is intentionally path-explicit.  The adapter does not search
    DLL directories, persist keys, or infer the key format; the caller owns
    authorization and lifecycle of every key passed to an operation.
    """

    def __init__(self, dll_path: str | Path) -> None:
        path = Path(dll_path)
        if not path.is_absolute():
            raise ValueError("class3.dll path must be absolute")
        if not path.is_file():
            raise FileNotFoundError(path)
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise OSError("class3.dll provider requires Windows ctypes.WinDLL")
        self.path = path
        try:
            self._dll = loader(str(path))
        except OSError as exc:
            raise OSError(
                f"unable to load explicit class3.dll provider {path}; "
                "verify that the DLL architecture matches the Python process"
            ) from exc
        self._decrypt = self._bind("RtsSaveDecrypt", decrypt=True)
        self._encrypt = self._bind("RtsSaveEncrypt", decrypt=False)

    def _bind(self, name: str, *, decrypt: bool):
        try:
            function = getattr(self._dll, name)
        except AttributeError as exc:
            raise OSError(f"{self.path} does not export {name}") from exc
        byte_pointer = ctypes.POINTER(ctypes.c_ubyte)
        function.restype = ctypes.c_int32
        function.argtypes = (
            byte_pointer,
            ctypes.POINTER(ctypes.c_uint32),
            byte_pointer,
            ctypes.c_uint32,
            byte_pointer,
        ) if decrypt else (
            byte_pointer,
            byte_pointer,
            ctypes.c_uint32,
            byte_pointer,
        )
        return function

    @staticmethod
    def _bytes(value: bytes):
        if not value:
            raise ValueError("native save buffers and keys must be non-empty")
        return (ctypes.c_ubyte * len(value)).from_buffer_copy(value)

    @staticmethod
    def _output(value: bytearray):
        if not value:
            raise ValueError("native save output buffer must be non-empty")
        return (ctypes.c_ubyte * len(value)).from_buffer(value)

    def rts_save_decrypt(self, input_buffer: bytes, output_length: UInt32Ref, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        source = self._bytes(input_buffer)
        destination = self._output(output_buffer)
        key_buffer = self._bytes(key)
        native_length = ctypes.c_uint32(output_length.value)
        result = self._decrypt(source, ctypes.byref(native_length), destination, input_length, key_buffer)
        output_length.value = native_length.value
        return int(result)

    def rts_save_encrypt(self, input_buffer: bytes, output_buffer: bytearray, input_length: int, key: bytes) -> int:
        source = self._bytes(input_buffer)
        destination = self._output(output_buffer)
        key_buffer = self._bytes(key)
        return int(self._encrypt(source, destination, input_length, key_buffer))


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

