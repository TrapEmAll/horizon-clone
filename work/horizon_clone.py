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


def mutate_xdbf_entry_same_size(data: bytes, entry: XdbfEntry, replacement: bytes) -> bytes:
    """Replace an XDBF payload without changing its table allocation."""
    if len(replacement) != entry.length:
        raise ValueError(
            f"replacement size {len(replacement)} does not match XDBF entry size {entry.length}"
        )
    start = entry.data_offset
    end = start + entry.length
    if start < 0 or end > len(data):
        raise ValueError("XDBF entry points beyond the file")
    result = bytearray(data)
    result[start:end] = replacement
    return bytes(result)


def repack_xdbf_entries(
    data: bytes,
    replacements: dict[int, bytes],
    remove: Iterable[int] = (),
) -> bytes:
    """Repack XDBF payloads while preserving the existing table capacity."""
    entries = list(parse_xdbf(data))
    by_index = {entry.index: entry for entry in entries}
    removals = set(remove)
    unknown = sorted((set(replacements) | removals) - set(by_index))
    if unknown:
        raise IndexError(f"unknown XDBF entry index: {unknown[0]}")
    if removals & set(replacements):
        raise ValueError("an XDBF entry cannot be both replaced and removed")

    table_length = int.from_bytes(data[8:12], "big")
    free_length = int.from_bytes(data[16:20], "big")
    table_offset = 0x18
    free_offset = table_offset + table_length * 0x12
    data_base = free_offset + free_length * 8
    retained = [entry for entry in entries if entry.index not in removals]
    if len(retained) > table_length:
        raise ValueError("XDBF entry table capacity is exhausted")

    payloads: list[bytes] = []
    for entry in retained:
        payloads.append(replacements.get(entry.index, data[entry.data_offset : entry.data_offset + entry.length]))
    used = sum(len(payload) for payload in payloads)
    capacity = len(data) - data_base
    if used > capacity:
        raise ValueError("replacement set exceeds the existing XDBF data capacity")

    result = bytearray(data)
    result[table_offset:free_offset] = b"\x00" * (free_offset - table_offset)
    result[data_base:] = b"\x00" * capacity
    cursor = 0
    for new_index, (entry, payload) in enumerate(zip(retained, payloads)):
        raw = bytearray(data[table_offset + entry.index * 0x12 : table_offset + (entry.index + 1) * 0x12])
        raw[10:14] = cursor.to_bytes(4, "big")
        raw[14:18] = len(payload).to_bytes(4, "big")
        slot = table_offset + new_index * 0x12
        result[slot : slot + 0x12] = raw
        result[data_base + cursor : data_base + cursor + len(payload)] = payload
        cursor += len(payload)
    result[12:16] = len(retained).to_bytes(4, "big")

    free_bytes = capacity - cursor
    result[free_offset : free_offset + free_length * 8] = b"\x00" * (free_length * 8)
    if free_bytes and free_length:
        result[free_offset : free_offset + 4] = cursor.to_bytes(4, "big")
        result[free_offset + 4 : free_offset + 8] = free_bytes.to_bytes(4, "big")
        result[20:24] = (1).to_bytes(4, "big")
    else:
        result[20:24] = (0).to_bytes(4, "big")
    return bytes(result)


def mutate_xdbf_achievement(
    data: bytes,
    entry_index: int,
    *,
    achievement_id: int | None = None,
    image_id: int | None = None,
    gamerscore: int | None = None,
    flags: int | None = None,
    name: str | None = None,
) -> bytes:
    """Edit the observed XDBF achievement payload fields in place."""
    entries = parse_xdbf(data)
    try:
        entry = next(item for item in entries if item.index == entry_index)
    except StopIteration as exc:
        raise IndexError(f"unknown XDBF entry index: {entry_index}") from exc
    if entry.achievement is None:
        raise ValueError("XDBF entry is not an achievement payload")
    payload = bytearray(data[entry.data_offset : entry.data_offset + entry.length])
    if achievement_id is not None:
        payload[4:8] = achievement_id.to_bytes(4, "little", signed=False)
    if image_id is not None:
        payload[8:12] = image_id.to_bytes(4, "little", signed=False)
    if gamerscore is not None:
        payload[12:16] = gamerscore.to_bytes(4, "little", signed=True)
    if flags is not None:
        payload[16:20] = flags.to_bytes(4, "little", signed=False)
    if name is not None:
        encoded = name.encode("utf-16-le")
        name_start = 0x18
        name_end = payload.find(b"\x00\x00", name_start)
        if name_end < 0:
            name_end = len(payload)
        if name_end % 2:
            name_end += 1
        capacity = name_end - name_start
        if len(encoded) > capacity:
            raise ValueError("achievement name does not fit the existing XDBF payload")
        payload[name_start:name_end] = encoded.ljust(capacity, b"\x00")
    return mutate_xdbf_entry_same_size(data, entry, bytes(payload))


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


def _hash_record_address(data: bytes, block: int, header: StfsHeader) -> int:
    """Return the physical hash-record address for a logical data block."""
    shift = 0 if header.block_separation & 1 else 1
    if block < 0xAA:
        hash_block = 0
    else:
        step = 0xAB if shift == 0 else 0xAC
        hash_block = (block // 0xAA) * step + (((block // 0x70E4) + 1) << shift)
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
        # Level 2 uses a top table of level-1 table hashes, followed by the
        # selected level-1 table's status bit to choose the level-0 half.
        level_step = 0x718F if shift == 0 else 0x723A
        top = first_hash_table + (level_step << 12) + (block // 0x70E4) * 0x18
        if top + 0x15 > len(data):
            return -1
        level1_selector = (data[top + 0x14] & 0x40) << 6
        level1_block = (1 << shift) + (block // 0x70E4) * level_step
        level1 = first_hash_table + (level1_block << 12) + level1_selector
        level1_record = level1 + (block % 0xAA) * 0x18
        if level1_record + 0x15 > len(data):
            return -1
        address += (data[level1_record + 0x14] & 0x40) << 6
    record = address + (block % 0xAA) * 0x18
    return record if record + 0x18 <= len(data) else -1


def _next_block(data: bytes, block: int, header: StfsHeader) -> int:
    record = _hash_record_address(data, block, header)
    if record < 0:
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


def mutate_stfs_entry_same_size(
    data: bytes,
    entry: StfsEntry,
    replacement: bytes,
    header: StfsHeader | None = None,
) -> bytes:
    """Replace one file's bytes in place and rebuild its STFS block hashes.

    This deliberately preserves the existing allocation and file size.  It
    updates data-block hashes and the metadata-header hash, but does not
    forge the package's RSA signature.  Callers must use an authorized
    signing provider before treating the result as console-valid.
    """
    header = header or parse_stfs_header(data)
    if entry.is_directory:
        raise IsADirectoryError(entry.path)
    if len(replacement) != entry.size:
        raise ValueError(
            f"replacement size {len(replacement)} does not match entry size {entry.size}"
        )

    result = bytearray(data)
    block = entry.first_block
    cursor = 0
    remaining = entry.size
    while remaining and block >= 0:
        address = block_offset(block, header.header_size, header.block_separation)
        if address + BLOCK_SIZE > len(result):
            raise ValueError(f"entry {entry.path!r} points beyond the end of the container")
        take = min(BLOCK_SIZE, remaining)
        result[address : address + take] = replacement[cursor : cursor + take]
        if take < BLOCK_SIZE:
            result[address + take : address + BLOCK_SIZE] = b"\x00" * (BLOCK_SIZE - take)
        record = _hash_record_address(result, block, header)
        if record < 0:
            raise ValueError(f"entry {entry.path!r} has no addressable hash record")
        result[record : record + 0x14] = hashlib.sha1(
            result[address : address + BLOCK_SIZE]
        ).digest()
        cursor += take
        remaining -= take
        block = block + 1 if entry.consecutive else _next_block(result, block, header)
    if remaining:
        raise ValueError(f"entry {entry.path!r} has a broken block chain")

    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    result[0x32C:0x340] = hashlib.sha1(result[0x344:first_hash_table]).digest()
    return bytes(result)


def mutate_stfs_metadata(
    data: bytes,
    *,
    display_name: str | None = None,
    title_id: int | None = None,
    content_type: int | None = None,
    header: StfsHeader | None = None,
) -> bytes:
    """Mutate fixed-width STFS metadata fields and rebuild the metadata hash."""
    header = header or parse_stfs_header(data)
    result = bytearray(data)
    if display_name is not None:
        encoded = display_name.encode("utf-16-be") + b"\x00\x00"
        if len(encoded) > 0x80:
            raise ValueError("display name exceeds the STFS 0x80-byte field")
        result[0x411 : 0x411 + 0x80] = encoded.ljust(0x80, b"\x00")
    if title_id is not None:
        if not 0 <= title_id <= 0xFFFFFFFF:
            raise ValueError("title ID must fit in an unsigned 32-bit field")
        result[0x360:0x364] = title_id.to_bytes(4, "big")
    if content_type is not None:
        if not 0 <= content_type <= 0xFFFFFFFF:
            raise ValueError("content type must fit in an unsigned 32-bit field")
        result[0x344:0x348] = content_type.to_bytes(4, "big")
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    result[0x32C:0x340] = hashlib.sha1(result[0x344:first_hash_table]).digest()
    return bytes(result)


def _stfs_file_table_slots(data: bytes, header: StfsHeader) -> tuple[int, ...]:
    """Return raw file-table slot offsets in the same order as parsed entries."""
    slots: list[int] = []
    block = header.file_table_block_number
    for table_index in range(header.file_table_block_count):
        address = block_offset(block, header.header_size, header.block_separation)
        if address + BLOCK_SIZE > len(data):
            raise ValueError("file table points beyond the end of the container")
        for slot in range(64):
            raw = data[address + slot * 0x40 : address + (slot + 1) * 0x40]
            name_length = raw[0x28] & 0x3F
            if name_length and all(0x20 <= value <= 0x7E for value in raw[:name_length]):
                slots.append(address + slot * 0x40)
        block = _next_block(data, block, header)
    return tuple(slots)


def repack_stfs_entries(
    data: bytes,
    replacements: dict[str, bytes],
    header: StfsHeader | None = None,
    remove: Iterable[str] = (),
) -> bytes:
    """Repack one or more entries within the package's existing block capacity.

    The operation preserves the physical package size and reserves the
    existing file-table blocks.  It refuses requests that need a larger STFS
    allocation table, leaving creation of new hash-table levels explicit.
    """
    header = header or parse_stfs_header(data)
    entries = list(list_stfs_entries(data, header))
    removals = set(remove)
    by_path = {entry.path: entry for entry in entries}
    unknown = sorted((set(replacements) | removals) - set(by_path))
    if unknown:
        raise FileNotFoundError(unknown[0])
    for path in removals:
        if by_path[path].is_directory:
            if any(item.path.startswith(path + "/") for item in entries):
                raise IsADirectoryError(f"directory is not empty: {path}")
            continue
    for path, payload in replacements.items():
        if by_path[path].is_directory:
            raise IsADirectoryError(path)
        if path in removals:
            raise ValueError(f"entry cannot be both replaced and removed: {path}")

    original_payloads = {
        entry.path: read_stfs_entry(data, entry, header)
        for entry in entries
        if not entry.is_directory
    }
    payloads = {**original_payloads, **replacements}
    for path in removals:
        payloads.pop(path, None)
    reserved = set(range(header.file_table_block_number, header.file_table_block_number + header.file_table_block_count))
    available = [block for block in range(header.allocated_block_count) if block not in reserved]
    allocations: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for entry in entries:
        if entry.is_directory or entry.path in removals:
            continue
        block_count = (len(payloads[entry.path]) + BLOCK_SIZE - 1) // BLOCK_SIZE
        selected = tuple(available[cursor : cursor + block_count])
        if len(selected) != block_count:
            raise ValueError("replacement set exceeds the existing STFS allocation capacity")
        allocations[entry.path] = selected
        cursor += block_count

    result = bytearray(data)
    for path, blocks in allocations.items():
        payload = payloads[path]
        for index, block in enumerate(blocks):
            address = block_offset(block, header.header_size, header.block_separation)
            if address + BLOCK_SIZE > len(result):
                raise ValueError("existing container does not contain the declared allocation")
            chunk = payload[index * BLOCK_SIZE : (index + 1) * BLOCK_SIZE]
            result[address : address + BLOCK_SIZE] = chunk.ljust(BLOCK_SIZE, b"\x00")

    slots = _stfs_file_table_slots(data, header)
    if len(slots) != len(entries):
        raise ValueError("file-table slot count changed while repacking")
    for entry, slot in zip(entries, slots):
        if entry.path in removals:
            result[slot : slot + 0x40] = b"\x00" * 0x40
            continue
        if entry.is_directory:
            continue
        raw = bytearray(result[slot : slot + 0x40])
        blocks = allocations[entry.path]
        raw[0x28] = (raw[0x28] | 0x40) & 0x7F
        raw[0x29:0x2C] = len(blocks).to_bytes(3, "little")
        raw[0x2F:0x32] = (blocks[0] if blocks else 0).to_bytes(3, "little")
        raw[0x34:0x38] = len(payloads[entry.path]).to_bytes(4, "big")
        result[slot : slot + 0x40] = raw

    changed_blocks = set(reserved)
    for blocks in allocations.values():
        changed_blocks.update(blocks)
    for block in changed_blocks:
        address = block_offset(block, header.header_size, header.block_separation)
        record = _hash_record_address(result, block, header)
        if record < 0 or address + BLOCK_SIZE > len(result):
            raise ValueError("unable to rebuild an STFS block hash")
        result[record : record + 0x14] = hashlib.sha1(result[address : address + BLOCK_SIZE]).digest()
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    result[0x32C:0x340] = hashlib.sha1(result[0x344:first_hash_table]).digest()
    return bytes(result)


def verify_stfs_hashes(
    data: bytes,
    entry: StfsEntry | None = None,
    header: StfsHeader | None = None,
) -> dict:
    """Verify data-block and metadata-header hashes without asserting signing validity."""
    header = header or parse_stfs_header(data)
    entries = (entry,) if entry is not None else list_stfs_entries(data, header)
    failures: list[dict] = []
    checked_blocks = 0
    for current in entries:
        if current.is_directory:
            continue
        block = current.first_block
        remaining = current.size
        while remaining and block >= 0:
            address = block_offset(block, header.header_size, header.block_separation)
            record = _hash_record_address(data, block, header)
            if address + BLOCK_SIZE > len(data) or record < 0:
                failures.append({"entry": current.path, "block": block, "reason": "out_of_range"})
                break
            expected = hashlib.sha1(data[address : address + BLOCK_SIZE]).digest()
            actual = data[record : record + 0x14]
            checked_blocks += 1
            if actual != expected:
                failures.append({"entry": current.path, "block": block, "reason": "data_hash"})
            take = min(BLOCK_SIZE, remaining)
            remaining -= take
            block = block + 1 if current.consecutive else _next_block(data, block, header)
        if remaining:
            failures.append({"entry": current.path, "block": block, "reason": "broken_chain"})

    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    header_hash_matches = hashlib.sha1(data[0x344:first_hash_table]).digest() == data[0x32C:0x340]
    return {
        "checked_blocks": checked_blocks,
        "failures": failures,
        "header_hash_matches": header_hash_matches,
        "signature_checked": False,
    }


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
    parser.add_argument("--verify-hashes", action="store_true", help="Verify STFS block and metadata hashes")
    parser.add_argument("--replace", metavar="ENTRY", help="Replace one STFS file in place")
    parser.add_argument("--replacement", type=Path, help="Raw replacement bytes for --replace")
    parser.add_argument("--repack", metavar="ENTRY", help="Replace one STFS file with a different size")
    parser.add_argument("--repack-source", type=Path, help="Raw replacement bytes for --repack")
    parser.add_argument("--remove", action="append", metavar="ENTRY", help="Remove an STFS file-table entry")
    parser.add_argument("--write", type=Path, help="Write a mutated container to this path")
    parser.add_argument("--display-name", help="Replace the fixed-width STFS display name")
    parser.add_argument("--title-id", type=lambda value: int(value, 0), help="Replace the STFS title ID")
    parser.add_argument("--content-type", type=lambda value: int(value, 0), help="Replace the STFS content type")
    parser.add_argument("--xdbf-replace", type=int, metavar="INDEX", help="Replace one XDBF entry")
    parser.add_argument("--xdbf-source", type=Path, help="Raw replacement bytes for --xdbf-replace")
    parser.add_argument("--xdbf-remove", type=int, action="append", metavar="INDEX", help="Remove an XDBF entry")
    parser.add_argument("--achievement", type=int, metavar="INDEX", help="Edit one XDBF achievement entry")
    parser.add_argument("--achievement-id", type=lambda value: int(value, 0))
    parser.add_argument("--image-id", type=lambda value: int(value, 0))
    parser.add_argument("--gamerscore", type=int)
    parser.add_argument("--achievement-flags", type=lambda value: int(value, 0))
    parser.add_argument("--achievement-name")
    args = parser.parse_args()

    try:
        raw = args.path.read_bytes()
        if raw[:4] == b"XDBF":
            achievement_requested = args.achievement is not None
            if args.xdbf_replace is not None or args.xdbf_remove or achievement_requested:
                if not args.write:
                    parser.error("XDBF mutation requires --write")
                if args.xdbf_replace is not None and not args.xdbf_source:
                    parser.error("--xdbf-replace requires --xdbf-source")
                replacements = {}
                if args.xdbf_replace is not None:
                    replacements[args.xdbf_replace] = args.xdbf_source.read_bytes()
                raw = repack_xdbf_entries(raw, replacements, remove=args.xdbf_remove or ())
                if achievement_requested:
                    raw = mutate_xdbf_achievement(
                        raw,
                        args.achievement,
                        achievement_id=args.achievement_id,
                        image_id=args.image_id,
                        gamerscore=args.gamerscore,
                        flags=args.achievement_flags,
                        name=args.achievement_name,
                    )
                args.write.write_bytes(raw)
                print(f"Wrote XDBF mutation to {args.write}")
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

    if args.verify_hashes:
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        verification = verify_stfs_hashes(raw, header=report.stfs_header)
        print(json.dumps(verification, indent=2))

    if args.replace:
        if not args.replacement or not args.write:
            parser.error("--replace requires both --replacement and --write")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        entry = next((item for item in report.entries if item.path == args.replace), None)
        if entry is None:
            parser.error(f"STFS entry not found: {args.replace}")
        try:
            replacement = args.replacement.read_bytes()
            mutated = mutate_stfs_entry_same_size(raw, entry, replacement, report.stfs_header)
            args.write.write_bytes(mutated)
        except (OSError, ValueError, IsADirectoryError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned in-place mutation to {args.write}")

    if args.repack:
        if args.replace or not args.repack_source or not args.write:
            parser.error("--repack requires --repack-source and --write, and cannot be combined with --replace")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = repack_stfs_entries(
                raw,
                {args.repack: args.repack_source.read_bytes()},
                report.stfs_header,
            )
            args.write.write_bytes(raw)
        except (OSError, ValueError, IsADirectoryError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned repacked container to {args.write}")

    if args.remove:
        if args.replace or args.repack or not args.write:
            parser.error("--remove requires --write and cannot be combined with --replace or --repack")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = repack_stfs_entries(raw, {}, remove=args.remove, header=report.stfs_header)
            args.write.write_bytes(raw)
        except (OSError, ValueError, IsADirectoryError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned removal mutation to {args.write}")

    metadata_requested = any(
        value is not None for value in (args.display_name, args.title_id, args.content_type)
    )
    if metadata_requested:
        if not args.write:
            parser.error("metadata mutation requires --write")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = mutate_stfs_metadata(
                raw,
                display_name=args.display_name,
                title_id=args.title_id,
                content_type=args.content_type,
                header=report.stfs_header,
            )
            args.write.write_bytes(raw)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned metadata mutation to {args.write}")

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

