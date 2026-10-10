"""Read-only host volume inventory for the device-exploration boundary.

Horizon declares Windows device APIs, but REA does not establish Xbox FATX or
IOCTL semantics.  This module provides the verifiable part: host-visible
volume identity and capacity, without opening a handle for mutation.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeviceVolume:
    root: str
    drive_type: str
    volume_label: str | None
    filesystem: str | None
    serial_number: int | None
    total_bytes: int | None
    free_bytes: int | None


@dataclass(frozen=True)
class HostDeviceEntry:
    """Read-only directory entry exposed by the host device explorer."""

    name: str
    relative_path: str
    is_directory: bool
    size: int | None
    modified_ns: int | None


_DRIVE_TYPES = {0: "unknown", 1: "no-root", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}


def enumerate_host_volumes() -> tuple[DeviceVolume, ...]:
    """Enumerate Windows logical volumes using read-only system queries."""

    if os.name != "nt":
        return ()
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    result: list[DeviceVolume] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        drive_type = _DRIVE_TYPES.get(ctypes.windll.kernel32.GetDriveTypeW(root), "unknown")
        label = ctypes.create_unicode_buffer(261)
        filesystem = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_uint32()
        maximum = ctypes.c_uint32()
        flags = ctypes.c_uint32()
        got_volume = ctypes.windll.kernel32.GetVolumeInformationW(
            root, label, len(label), ctypes.byref(serial), ctypes.byref(maximum), ctypes.byref(flags),
            filesystem, len(filesystem)
        )
        try:
            usage = shutil.disk_usage(root)
            total_bytes, free_bytes = usage.total, usage.free
        except OSError:
            total_bytes = free_bytes = None
        result.append(DeviceVolume(
            root=root,
            drive_type=drive_type,
            volume_label=label.value if got_volume else None,
            filesystem=filesystem.value if got_volume else None,
            serial_number=int(serial.value) if got_volume else None,
            total_bytes=total_bytes,
            free_bytes=free_bytes,
        ))
    return tuple(result)


def device_inventory_report() -> dict[str, object]:
    """Return a read-only host inventory with explicit Xbox limitations."""

    supported = os.name == "nt"
    return {
        "status": "host-visible-read-only" if supported else "unsupported-host",
        "volumes": [asdict(item) for item in enumerate_host_volumes()],
        "limitations": [
            "This inventory reports host-visible logical volumes only.",
            "Xbox FATX enumeration, IOCTL values, and device-specific metadata remain unresolved.",
            "No volume is opened for mutation by this API.",
        ],
    }


def enumerate_host_device_entries(root: str | Path, relative: str | Path = ".") -> tuple[HostDeviceEntry, ...]:
    """List one host-visible directory without allowing path escape.

    This is deliberately read-only and does not follow directory entries while
    enumerating.  It models the safe host portion of Horizon's explorer; FATX
    directory records and device IOCTLs remain provider-specific.
    """

    root_path = Path(root)
    if not root_path.is_absolute():
        raise ValueError("device explorer root must be absolute")
    root_path = Path(os.path.abspath(root_path))
    if not root_path.is_dir():
        raise NotADirectoryError(root_path)
    target = Path(os.path.abspath(root_path / relative))
    try:
        target.relative_to(root_path)
    except ValueError as exc:
        raise ValueError("device explorer path escapes its root") from exc
    if not target.is_dir():
        raise NotADirectoryError(target)

    entries: list[HostDeviceEntry] = []
    for item in sorted(target.iterdir(), key=lambda value: value.name.casefold()):
        try:
            stat = item.stat(follow_symlinks=False)
            is_directory = stat.S_ISDIR(stat.st_mode)
            size = None if is_directory else stat.st_size
            modified_ns = stat.st_mtime_ns
        except OSError:
            size = modified_ns = None
            is_directory = item.is_dir()
        entries.append(HostDeviceEntry(
            name=item.name,
            relative_path=item.relative_to(root_path).as_posix(),
            is_directory=is_directory,
            size=size,
            modified_ns=modified_ns,
        ))
    return tuple(entries)

