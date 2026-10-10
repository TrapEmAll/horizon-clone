"""Clean-room Xbox 360 content-container inspector.

This module intentionally limits itself to evidence-backed, non-destructive
inspection.  It does not copy Horizon code/resources and does not claim to
re-sign or rewrite a container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Iterable


MAGIC = b"CON "
STFS_MAGICS = {b"CON ", b"LIVE", b"PIRS"}
BLOCK_SIZE = 0x1000
FIRST_DATA_OFFSET = 0xC000
_PRINTABLE = re.compile(r"[\x20-\x7e]{4,}")


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    encoding: str
    value: str


@dataclass(frozen=True)
class ContainerReport:
    path: str
    size: int
    sha256: str
    magic: str
    package_kind: str
    stfs_header: StfsHeader | None
    entries: tuple[StfsEntry, ...]
    utf16_strings: tuple[ExtractedString, ...]
    ascii_strings: tuple[ExtractedString, ...]

    @property
    def is_container(self) -> bool:
        return self.magic == MAGIC.decode("ascii")


@dataclass(frozen=True)
class StfsHeader:
    magic: str
    header_size: int
    content_type: int
    metadata_version: int
    content_size: int
    title_id: int
    platform: int
    console_id: str
    profile_id: str
    block_separation: int
    file_table_block_count: int
    file_table_block_number: int
    allocated_block_count: int
    display_name: str


@dataclass(frozen=True)
class StfsEntry:
    index: int
    name: str
    is_directory: bool
    consecutive: bool
    block_count: int
    first_block: int
    path_indicator: int
    size: int
    path: str


@dataclass(frozen=True)
class XdbfEntry:
    index: int
    namespace: int
    entry_id: int
    offset: int
    length: int
    data_offset: int
    text: str | None
    achievement: dict | None


def parse_xdbf(data: bytes) -> tuple[XdbfEntry, ...]:
    """Parse XDBF/GPD entry indexes and common text/achievement payloads."""
    if len(data) < 0x18 or data[:4] != b"XDBF":
        raise ValueError("not an Xbox XDBF file")
    version, table_length, entry_count, free_length, _ = (
        int.from_bytes(data[offset : offset + 4], "big")
        for offset in (4, 8, 12, 16, 20)
    )
    if version != 0x10000:
        raise ValueError(f"unsupported XDBF version: 0x{version:X}")
    table_offset = 0x18
    free_offset = table_offset + table_length * 0x12
    data_base = free_offset + free_length * 8
    if data_base > len(data) or entry_count > table_length:
        raise ValueError("invalid XDBF table dimensions")
    result: list[XdbfEntry] = []
    for index in range(entry_count):
        offset = table_offset + index * 0x12
        namespace = int.from_bytes(data[offset : offset + 2], "big")
        entry_id = int.from_bytes(data[offset + 2 : offset + 10], "big")
        data_offset = int.from_bytes(data[offset + 10 : offset + 14], "big")
        length = int.from_bytes(data[offset + 14 : offset + 18], "big")
        start, end = data_base + data_offset, data_base + data_offset + length
        if end > len(data):
            raise ValueError(f"XDBF entry {index} points beyond the file")
        payload = data[start:end]
        text = None
        achievement = None
        if namespace == 5:
            text = payload.decode("utf-16-be", errors="replace").rstrip("\x00")
        elif namespace == 1 and entry_id not in (0x100000000, 0x200000000) and len(payload) >= 0x18:
            name_end = payload.find(b"\x00\x00", 0x18)
            if name_end >= 0 and name_end % 2:
                name_end += 1
            name = payload[0x18:name_end if name_end >= 0 else len(payload)].decode("utf-16-le", errors="replace").rstrip("\x00")
            achievement = {
                "achievement_id": int.from_bytes(payload[4:8], "little"),
                "image_id": int.from_bytes(payload[8:12], "little"),
                "gamerscore": int.from_bytes(payload[12:16], "little", signed=True),
                "flags": int.from_bytes(payload[16:20], "little"),
                "name": name,
            }
        result.append(XdbfEntry(index, namespace, entry_id, offset, length, start, text, achievement))
    return tuple(result)


def _u16be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _u16le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _u64be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "big")


def _u24le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 3], "little")


def _fixed_text(data: bytes, offset: int, size: int, encoding: str = "ascii") -> str:
    return data[offset : offset + size].decode(encoding, errors="replace").rstrip("\x00 ")


def parse_stfs_header(data: bytes) -> StfsHeader:
    if len(data) < 0x39D:
        raise ValueError("file is too small to contain an STFS metadata header")
    magic = data[:4]
    if magic not in STFS_MAGICS:
        raise ValueError(f"unsupported STFS magic: {magic!r}")
    return StfsHeader(
        magic=magic.decode("ascii"),
        header_size=_u32be(data, 0x340),
        content_type=_u32be(data, 0x344),
        metadata_version=_u32be(data, 0x348),
        content_size=_u64be(data, 0x34C),
        title_id=_u32be(data, 0x360),
        platform=data[0x364],
        console_id=data[0x36C:0x371].hex(),
        profile_id=data[0x371:0x379].hex(),
        block_separation=data[0x37B],
        file_table_block_count=_u16le(data, 0x37C),
        file_table_block_number=_u24le(data, 0x37E),
        allocated_block_count=_u32be(data, 0x395),
        display_name=_fixed_text(data, 0x411, 0x80, "utf-16-be"),
    )


def _backing_block(block: int, shift: int) -> int:
    first = ((block + 0xAA) // 0xAA) << shift
    result = first + block
    if block >= 0xAA:
        result += ((block + 0x70E4) // 0x70E4) << shift
    if block >= 0x70E4:
        result += 1 << shift
    return result


def block_offset(block: int, header_size: int, block_separation: int) -> int:
    """Return the physical offset for a logical STFS data block."""
    if block < 0:
        raise ValueError("block number cannot be negative")
    first_hash_table = (header_size + 0xFFF) & 0xFFFFF000
    shift = 0 if block_separation & 1 else 1
    return first_hash_table + (_backing_block(block, shift) << 12)


def _next_block(data: bytes, block: int, header: StfsHeader) -> int:
    shift = 0 if header.block_separation & 1 else 1
    if block < 0xAA:
        hash_block = 0
    else:
        step = 0xAB if shift == 0 else 0xAC
        hash_block = (block // 0xAA) * step + ((block // 0x70E4) + 1 << shift)
        if block // 0x70E4:
            hash_block += 1 << shift
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    address = first_hash_table + (hash_block << 12)
    # For packages with more than one level of hash tables, the top-level
    # status selects one of two level-0 hash-table halves. This matters for
    # CON packages such as the supplied profile fixture.
    if header.allocated_block_count <= 0xAA:
        address += (header.block_separation & 2) << 11
    elif header.allocated_block_count <= 0x70E4:
        top_block = 0xAB if shift == 0 else 0xAC
        top = first_hash_table + (top_block << 12) + (block // 0xAA) * 0x18
        if top + 0x15 > len(data):
            return -1
        address += (data[top + 0x14] & 0x40) << 6
    else:
        # The supplied fixture is level 1. Keep level-2 packages readable
        # only when their top-level layout is unambiguous.
        return -1
    record = address + (block % 0xAA) * 0x18
    if record + 0x18 > len(data):
        return -1
    next_block = int.from_bytes(data[record + 0x15 : record + 0x18], "big")
    return -1 if next_block >= 0xFFFFFE else next_block


def _entry_path(entries: list[StfsEntry], index: int) -> str:
    parts: list[str] = [entries[index].name]
    current = entries[index]
    seen: set[int] = set()
    while current.path_indicator >= 0 and current.path_indicator < len(entries):
        if current.index in seen:
            raise ValueError("cycle detected in STFS directory table")
        seen.add(current.index)
        current = entries[current.path_indicator]
        parts.append(current.name)
    return "/".join(reversed(parts))


def list_stfs_entries(data: bytes, header: StfsHeader | None = None) -> tuple[StfsEntry, ...]:
    header = header or parse_stfs_header(data)
    entries: list[StfsEntry] = []
    block = header.file_table_block_number
    for _ in range(header.file_table_block_count):
        address = block_offset(block, header.header_size, header.block_separation)
        if address + BLOCK_SIZE > len(data):
            raise ValueError("file table points beyond the end of the container")
        for slot in range(64):
            raw = data[address + slot * 0x40 : address + (slot + 1) * 0x40]
            name_length = raw[0x28] & 0x3F
            if not name_length:
                continue
            name_bytes = raw[:name_length]
            if not all(0x20 <= value <= 0x7E for value in name_bytes):
                continue
            path_indicator = int.from_bytes(raw[0x32:0x34], "big")
            entries.append(
                StfsEntry(
                    index=len(entries),
                    name=name_bytes.decode("ascii"),
                    is_directory=bool(raw[0x28] & 0x80),
                    consecutive=bool(raw[0x28] & 0x40),
                    block_count=_u24le(raw, 0x29),
                    first_block=_u24le(raw, 0x2F),
                    path_indicator=-1 if path_indicator == 0xFFFF else path_indicator,
                    size=_u32be(raw, 0x34),
                    path="",
                )
            )
        block = _next_block(data, block, header)
        if block < 0 and _ < header.file_table_block_count - 1:
            break
    resolved: list[StfsEntry] = []
    for entry in entries:
        resolved.append(StfsEntry(**{**asdict(entry), "path": _entry_path(entries, entry.index)}))
    return tuple(resolved)


def read_stfs_entry(data: bytes, entry: StfsEntry, header: StfsHeader | None = None) -> bytes:
    header = header or parse_stfs_header(data)
    if entry.is_directory:
        raise IsADirectoryError(entry.path)
    result = bytearray()
    block = entry.first_block
    remaining = entry.size
    while remaining and block >= 0:
        address = block_offset(block, header.header_size, header.block_separation)
        if address + BLOCK_SIZE > len(data):
            raise ValueError(f"entry {entry.path!r} points beyond the end of the container")
        take = min(BLOCK_SIZE, remaining)
        result.extend(data[address : address + take])
        remaining -= take
        if entry.consecutive:
            block += 1
        else:
            block = _next_block(data, block, header)
    if remaining:
        raise ValueError(f"entry {entry.path!r} has a broken block chain")
    return bytes(result)


def extract_stfs(data: bytes, output_dir: Path, *, selected_path: str | None = None) -> tuple[Path, ...]:
    """Extract entries without allowing an entry name to escape output_dir."""
    header = parse_stfs_header(data)
    entries = list_stfs_entries(data, header)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for entry in entries:
        if entry.is_directory or (selected_path and entry.path != selected_path):
            continue
        destination = (output_dir / Path(entry.path)).resolve()
        if output_dir not in destination.parents:
            raise ValueError(f"unsafe entry path: {entry.path!r}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(read_stfs_entry(data, entry, header))
        written.append(destination)
    if selected_path and not written:
        raise FileNotFoundError(selected_path)
    return tuple(written)


def _strings(data: bytes, encoding: str) -> Iterable[ExtractedString]:
    if encoding == "utf-16-le":
        # The container includes arbitrary binary bytes, so decoding the
        # entire file as UTF-16 produces false positives. Restrict this first
        # pass to the printable ASCII subset commonly used by metadata.
        for offset in range(0, len(data) - 1, 2):
            end = offset
            while end + 1 < len(data):
                low, high = data[end], data[end + 1]
                if high != 0 or not 0x20 <= low <= 0x7E:
                    break
                end += 2
            if end - offset >= 8:
                yield ExtractedString(offset, encoding, data[offset:end].decode(encoding))
        return

    for match in _PRINTABLE.finditer(data.decode("latin-1", errors="ignore")):
        yield ExtractedString(match.start(), "ascii", match.group(0))


def inspect(path: Path, *, max_strings: int = 5000) -> ContainerReport:
    data = path.read_bytes()
    magic = data[:4].decode("latin-1", errors="replace")
    package_kind = {
        "CON ": "Xbox 360 content container",
        "LIVE": "Xbox 360 LIVE container",
        "PIRS": "Xbox 360 PIRS container",
    }.get(magic, "Unknown container")
    header = None
    entries: tuple[StfsEntry, ...] = ()
    if data[:4] in STFS_MAGICS:
        try:
            header = parse_stfs_header(data)
            entries = list_stfs_entries(data, header)
        except ValueError:
            # Keep the low-level report useful for damaged or partial files.
            # The caller can still see the magic and string evidence.
            header = None
    return ContainerReport(
        path=str(path),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        magic=magic,
        package_kind=package_kind,
        stfs_header=header,
        entries=entries,
        utf16_strings=tuple(_strings(data, "utf-16-le"))[:max_strings],
        ascii_strings=tuple(_strings(data, "ascii"))[:max_strings],
    )


def _json_report(report: ContainerReport) -> dict:
    result = asdict(report)
    result["is_container"] = report.is_container
    return result


def _json_xdbf(data: bytes, path: Path) -> dict:
    entries = parse_xdbf(data)
    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "magic": "XDBF",
        "entries": [asdict(entry) for entry in entries],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect an Xbox 360 content container")
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--list", action="store_true", help="List STFS file-table entries")
    parser.add_argument("--extract-dir", type=Path, help="Extract STFS files into this directory")
    parser.add_argument("--extract", metavar="ENTRY", help="Extract only this STFS path")
    args = parser.parse_args()

    try:
        raw = args.path.read_bytes()
        if raw[:4] == b"XDBF":
            payload = json.dumps(_json_xdbf(raw, args.path), indent=2, ensure_ascii=False)
            if args.output:
                args.output.write_text(payload + "\n", encoding="utf-8")
            if args.as_json or not args.output:
                print(payload)
            return 0
        report = inspect(args.path)
    except OSError as exc:
        parser.error(str(exc))

    if args.list:
        if not report.entries:
            parser.error("the file does not contain a readable STFS file table")
        for entry in report.entries:
            kind = "DIR " if entry.is_directory else "FILE"
            print(f"{kind} {entry.size:>10} {entry.path}")
    if args.extract_dir:
        written = extract_stfs(raw, args.extract_dir, selected_path=args.extract)
        print(f"Extracted {len(written)} file(s) to {args.extract_dir}")

    payload = json.dumps(_json_report(report), indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    if args.as_json or (not args.output and not args.list and not args.extract_dir):
        print(payload)
    else:
        print(f"{report.package_kind}: {report.path} ({report.size:,} bytes)")
        print(f"SHA-256: {report.sha256}")
        if report.stfs_header:
            print(f"Display name: {report.stfs_header.display_name or '(empty)'}")
            print(f"Title ID: 0x{report.stfs_header.title_id:08X}")
            print(f"Entries: {len(report.entries):,}")
        print(f"UTF-16 strings: {len(report.utf16_strings):,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

