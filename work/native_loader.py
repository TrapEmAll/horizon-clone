"""Explicit native-image diagnostics used by optional provider adapters."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def compatible_pe_architecture(path: str | Path) -> tuple[str, str]:
    """Return ``(image_architecture, process_architecture)`` for a PE image.

    This reads only the DOS/PE headers and never loads or executes the image.
    """

    source = Path(path)
    data = source.read_bytes()
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError(f"{source} is not a readable PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{source} has an invalid PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    image = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}.get(machine, f"machine-0x{machine:04x}")
    process = "x86_64" if struct.calcsize("P") == 8 else "x86"
    return image, process


def require_compatible_pe_architecture(path: str | Path) -> None:
    image, process = compatible_pe_architecture(path)
    if image != process:
        raise OSError(f"native image is {image}, but the current Python process is {process}")

