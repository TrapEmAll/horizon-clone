"""Provider boundary for the authenticated Horizon device-size property."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class DeviceProvider(Protocol):
    def get_device_size(self) -> int: ...
    def set_device_size(self, value: int) -> None: ...


class DeviceProviderUnavailable(RuntimeError):
    """Raised when no explicit device provider was supplied."""


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

