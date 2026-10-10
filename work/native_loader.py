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


def pe_export_names(path: str | Path) -> tuple[str, ...]:
    """Read named exports from a PE export directory without loading it."""

    source = Path(path)
    data = source.read_bytes()
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError(f"{source} is not a readable PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{source} has an invalid PE signature")
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    directory_offset = optional_offset + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
    if directory_offset < 0 or directory_offset + 8 > len(data):
        raise ValueError(f"{source} has an unsupported PE optional header")
    export_rva, export_size = struct.unpack_from("<II", data, directory_offset)
    if not export_rva or not export_size:
        return ()
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_offset = optional_offset + optional_size

    def rva_to_offset(rva: int) -> int:
        for index in range(section_count):
            current = section_offset + index * 40
            if current + 40 > len(data):
                break
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, current + 8)
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                offset = raw_pointer + (rva - virtual_address)
                if offset < len(data):
                    return offset
        raise ValueError(f"{source} export RVA 0x{rva:x} is not mapped to file data")

    directory = rva_to_offset(export_rva)
    if directory + 40 > len(data):
        raise ValueError(f"{source} has a truncated export directory")
    (_characteristics, _timestamp, _major, _minor, _name, _base,
     _function_count, name_count, _functions, names_rva, _ordinals) = struct.unpack_from("<IIHHIIIIIII", data, directory)
    names_offset = rva_to_offset(names_rva)
    result: list[str] = []
    for index in range(name_count):
        pointer = names_offset + index * 4
        if pointer + 4 > len(data):
            raise ValueError(f"{source} has a truncated export-name table")
        name_offset = rva_to_offset(struct.unpack_from("<I", data, pointer)[0])
        end = data.find(b"\0", name_offset)
        if end < 0:
            raise ValueError(f"{source} has an unterminated export name")
        result.append(data[name_offset:end].decode("ascii"))
    return tuple(result)

