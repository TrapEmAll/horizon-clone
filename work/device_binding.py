"""Provider boundary for the authenticated Horizon device-size property."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class DeviceProvider(Protocol):
    def get_device_size(self) -> int: ...
    def set_device_size(self, value: int) -> None: ...


class DeviceProviderUnavailable(RuntimeError):
    """Raised when no explicit device provider was supplied."""


class DeviceIoProvider(Protocol):
    def open_read_only(self, device_path: str) -> int: ...
    def device_io_control(self, handle: int, control_code: int, input_data: bytes, output_capacity: int) -> bytes: ...
    def close(self, handle: int) -> None: ...


class WindowsDeviceIoProvider:
    """Explicit Windows adapter for the observed device imports.

    The caller supplies the device path and IOCTL. No FATX command values are
    inferred, and the adapter never requests generic-write access. IOCTL
    safety semantics remain the caller's responsibility.
    """

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self) -> None:
        if not hasattr(ctypes, "WinDLL"):
            raise OSError("Windows device IO requires ctypes.WinDLL")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._create_file = self._kernel32.CreateFileW
        self._create_file.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        self._create_file.restype = wintypes.HANDLE
        self._device_io_control = self._kernel32.DeviceIoControl
        self._device_io_control.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
        )
        self._device_io_control.restype = wintypes.BOOL
        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = (wintypes.HANDLE,)
        self._close_handle.restype = wintypes.BOOL

    def open_read_only(self, device_path: str) -> int:
        if not isinstance(device_path, str) or not device_path:
            raise ValueError("device_path must be a non-empty string")
        handle = self._create_file(
            device_path,
            self.GENERIC_READ,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)

    def device_io_control(self, handle: int, control_code: int, input_data: bytes = b"", output_capacity: int = 0) -> bytes:
        if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
            raise ValueError("handle must be a positive native handle")
        if not isinstance(control_code, int) or isinstance(control_code, bool) or not 0 <= control_code <= 0xFFFFFFFF:
            raise ValueError("control_code must be an unsigned 32-bit integer")
        if not isinstance(input_data, bytes):
            raise TypeError("input_data must be bytes")
        if not isinstance(output_capacity, int) or isinstance(output_capacity, bool) or output_capacity < 0:
            raise ValueError("output_capacity must be a non-negative integer")
        input_buffer = ctypes.create_string_buffer(input_data) if input_data else None
        output_buffer = ctypes.create_string_buffer(output_capacity) if output_capacity else None
        returned = wintypes.DWORD(0)
        ok = self._device_io_control(
            wintypes.HANDLE(handle), control_code,
            input_buffer, len(input_data), output_buffer, output_capacity,
            ctypes.byref(returned), None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return output_buffer.raw[:returned.value] if output_buffer is not None else b""

    def close(self, handle: int) -> None:
        if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
            raise ValueError("handle must be a positive native handle")
        if not self._close_handle(wintypes.HANDLE(handle)):
            raise ctypes.WinError(ctypes.get_last_error())


@dataclass(frozen=True)
class DeviceIoBinding:
    provider: DeviceIoProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def open_read_only(self, device_path: str) -> int:
        return self._require().open_read_only(device_path)

    def device_io_control(self, handle: int, control_code: int, input_data: bytes = b"", output_capacity: int = 0) -> bytes:
        return self._require().device_io_control(handle, control_code, input_data, output_capacity)

    def close(self, handle: int) -> None:
        self._require().close(handle)

    def _require(self) -> DeviceIoProvider:
        if self.provider is None:
            raise DeviceProviderUnavailable("device IO requires an explicit compatible provider")
        return self.provider


@dataclass(frozen=True)
class DeviceBinding:
    """Model the observed ``i8`` property without opening a physical device."""

    provider: DeviceProvider | None = None

    @property
    def status(self) -> str:
        return "provider-bound" if self.provider is not None else "unavailable"

    def get_device_size(self) -> int:
        value = self._require().get_device_size()
        return _validate_i64(value)

    def set_device_size(self, value: int) -> None:
        provider = self._require()
        _validate_i64(value)
        provider.set_device_size(value)

    def _require(self) -> DeviceProvider:
        if self.provider is None:
            raise DeviceProviderUnavailable("device access requires an explicit compatible provider")
        return self.provider


def _validate_i64(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not -0x8000000000000000 <= value <= 0x7FFFFFFFFFFFFFFF:
        raise ValueError("device size must be a signed 64-bit integer")
    return value

