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

from .editor_inventory import capability_report, catalog_report
from .native_surface import native_surface_report


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
    stfs_security: StfsSecurityMetadata | None
    entries: tuple[StfsEntry, ...]
    utf16_strings: tuple[ExtractedString, ...]
    ascii_strings: tuple[ExtractedString, ...]

    @property
    def is_container(self) -> bool:
        return self.magic.encode("latin-1") in STFS_MAGICS


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
    display_description: str
    publisher_name: str
    title_name: str
    transfer_flags: int
    top_hash_table_hash: str
    thumbnail_size: int
    title_thumbnail_size: int


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
class StfsThumbnails:
    thumbnail_size: int
    title_thumbnail_size: int
    thumbnail: bytes
    title_thumbnail: bytes


@dataclass(frozen=True)
class StfsLicense:
    license_id: int
    bits: int
    flags: int


@dataclass(frozen=True)
class StfsSecurityMetadata:
    signature_kind: str
    certificate_size: int | None
    owner_console_id: str | None
    owner_console_part_number: str | None
    owner_console_type: int | None
    public_exponent_hex: str | None
    public_modulus_sha256: str | None
    certificate_signature_sha256: str | None
    package_signature_sha256: str | None
    header_sha1: str
    header_sha1_matches: bool
    licenses: tuple[StfsLicense, ...]


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
    additions: dict[tuple[int, int], bytes] | None = None,
) -> bytes:
    """Repack XDBF payloads while preserving existing table/data capacity.

    ``additions`` maps caller-supplied ``(namespace, entry_id)`` pairs to
    payloads. The caller owns the title-specific meaning of those identifiers.
    """
    entries = list(parse_xdbf(data))
    additions = additions or {}
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
    if len(retained) + len(additions) > table_length:
        raise ValueError("XDBF entry table capacity is exhausted")

    payloads: list[bytes] = []
    for entry in retained:
        payloads.append(replacements.get(entry.index, data[entry.data_offset : entry.data_offset + entry.length]))
    for (namespace, entry_id), payload in additions.items():
        if not 0 <= namespace <= 0xFFFF:
            raise ValueError("XDBF addition namespace must fit in an unsigned 16-bit field")
        if not 0 <= entry_id <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("XDBF addition ID must fit in an unsigned 64-bit field")
        payloads.append(payload)
    used = sum(len(payload) for payload in payloads)
    capacity = len(data) - data_base
    if used > capacity:
        raise ValueError("replacement set exceeds the existing XDBF data capacity")

    result = bytearray(data)
    result[table_offset:free_offset] = b"\x00" * (free_offset - table_offset)
    result[data_base:] = b"\x00" * capacity
    cursor = 0
    records = [
        (bytearray(data[table_offset + entry.index * 0x12 : table_offset + (entry.index + 1) * 0x12]), payload)
        for entry, payload in zip(retained, payloads)
    ]
    additions_start = len(retained)
    for addition_index, ((namespace, entry_id), payload) in enumerate(additions.items()):
        raw = bytearray(0x12)
        raw[0:2] = namespace.to_bytes(2, "big")
        raw[2:10] = entry_id.to_bytes(8, "big")
        records.append((raw, payloads[additions_start + addition_index]))
    for new_index, (raw, payload) in enumerate(records):
        raw[10:14] = cursor.to_bytes(4, "big")
        raw[14:18] = len(payload).to_bytes(4, "big")
        slot = table_offset + new_index * 0x12
        result[slot : slot + 0x12] = raw
        result[data_base + cursor : data_base + cursor + len(payload)] = payload
        cursor += len(payload)
    result[12:16] = len(records).to_bytes(4, "big")

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


def mutate_xdbf_text(data: bytes, entry_index: int, text: str) -> bytes:
    """Replace an observed namespace-5 XDBF UTF-16BE string entry."""
    entries = parse_xdbf(data)
    try:
        entry = next(item for item in entries if item.index == entry_index)
    except StopIteration as exc:
        raise IndexError(f"unknown XDBF entry index: {entry_index}") from exc
    if entry.namespace != 5 or entry.text is None:
        raise ValueError("XDBF entry is not an observed namespace-5 string")
    replacement = text.encode("utf-16-be") + b"\x00\x00"
    return repack_xdbf_entries(data, {entry_index: replacement})


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
        display_description=_fixed_text(data, 0xD11, 0x80, "utf-16-be"),
        publisher_name=_fixed_text(data, 0x1611, 0x80, "utf-16-be"),
        title_name=_fixed_text(data, 0x1691, 0x80, "utf-16-be"),
        transfer_flags=data[0x1711] if len(data) > 0x1711 else 0,
        top_hash_table_hash=data[0x381:0x395].hex(),
        thumbnail_size=_u32be(data, 0x1712),
        title_thumbnail_size=_u32be(data, 0x1716),
    )


def parse_stfs_security_metadata(data: bytes) -> StfsSecurityMetadata:
    """Inspect public certificate/signature descriptors and license slots.

    The function reports hashes of signature and modulus bytes rather than
    treating them as verifiable with this clean-room implementation. It never
    extracts private key material or infers a console signing operation.
    """
    header = parse_stfs_header(data)
    licenses: list[StfsLicense] = []
    for index in range(16):
        offset = 0x22C + index * 0x10
        licenses.append(
            StfsLicense(
                license_id=_u64be(data, offset),
                bits=_u32be(data, offset + 8),
                flags=_u32be(data, offset + 12),
            )
        )
    digest = lambda payload: hashlib.sha256(payload).hexdigest() if payload else None
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    stored_header_sha1 = data[0x32C:0x340]
    header_sha1_matches = (
        len(stored_header_sha1) == hashlib.sha1().digest_size
        and first_hash_table <= len(data)
        and hashlib.sha1(data[0x344:first_hash_table]).digest() == stored_header_sha1
    )
    if header.magic == "CON ":
        return StfsSecurityMetadata(
            signature_kind="console-certificate",
            certificate_size=_u16be(data, 0x04),
            owner_console_id=data[0x06:0x0B].hex(),
            owner_console_part_number=_fixed_text(data, 0x0B, 0x14),
            owner_console_type=data[0x1F],
            public_exponent_hex=data[0x28:0x2C].hex(),
            public_modulus_sha256=digest(data[0x2C:0xAC]),
            certificate_signature_sha256=digest(data[0xAC:0x1AC]),
            package_signature_sha256=digest(data[0x1AC:0x22C]),
            header_sha1=stored_header_sha1.hex(),
            header_sha1_matches=header_sha1_matches,
            licenses=tuple(licenses),
        )
    return StfsSecurityMetadata(
        signature_kind="remote-package-signature",
        certificate_size=None,
        owner_console_id=None,
        owner_console_part_number=None,
        owner_console_type=None,
        public_exponent_hex=None,
        public_modulus_sha256=None,
        certificate_signature_sha256=None,
        package_signature_sha256=digest(data[0x04:0x104]),
        header_sha1=stored_header_sha1.hex(),
        header_sha1_matches=header_sha1_matches,
        licenses=tuple(licenses),
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


def _top_level(header: StfsHeader) -> int:
    if header.allocated_block_count <= 0xAA:
        return 0
    if header.allocated_block_count <= 0x70E4:
        return 1
    if header.allocated_block_count <= 0x4AF768:
        return 2
    raise ValueError("STFS allocation exceeds the supported three-level hash tree")


def _hash_table_address(
    data: bytes, block: int, header: StfsHeader, level: int
) -> int:
    """Return the selected physical address of a hash table.

    ``block`` is the first logical data block covered by the table.  STFS
    stores two copies of non-top tables and uses the parent's status bit to
    select the active copy.  This mirrors the address selection used by
    ``_hash_record_address`` while keeping table-level operations explicit.
    """
    if level not in (0, 1, 2):
        raise ValueError("hash-table level must be 0, 1, or 2")
    top_level = _top_level(header)
    if level > top_level:
        raise ValueError("hash-table level is not present in this package")
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    shift = 0 if header.block_separation & 1 else 1
    step0 = 0xAB if shift == 0 else 0xAC
    step1 = 0x718F if shift == 0 else 0x723A

    if level == 0:
        if block < 0 or block >= header.allocated_block_count:
            raise ValueError("level-0 table starts outside the allocation")
        if block < 0xAA:
            hash_block = 0
        else:
            hash_block = (block // 0xAA) * step0 + (((block // 0x70E4) + 1) << shift)
            if block // 0x70E4:
                hash_block += 1 << shift
    elif level == 1:
        hash_block = step0 if block < 0x70E4 else (1 << shift) + (block // 0x70E4) * step1
    else:
        hash_block = step1

    address = first_hash_table + (hash_block << 12)
    if level == top_level:
        return address + ((header.block_separation & 2) << 11)

    if top_level == 1 and level == 0:
        parent = _hash_table_address(data, 0, header, 1)
        selector = parent + (block // 0xAA) * 0x18 + 0x14
    elif top_level == 2 and level == 1:
        parent = _hash_table_address(data, 0, header, 2)
        selector = parent + (block // 0x70E4) * 0x18 + 0x14
    elif top_level == 2 and level == 0:
        parent = _hash_table_address(data, 0, header, 2)
        top_selector = parent + (block // 0x70E4) * 0x18 + 0x14
        if top_selector + 1 > len(data):
            raise ValueError("top hash table selector is outside the container")
        level1_block = (1 << shift) + (block // 0x70E4) * step1
        level1 = first_hash_table + (level1_block << 12)
        selector = level1 + ((data[top_selector] & 0x40) << 6) + (block // 0xAA % 0xAA) * 0x18 + 0x14
    else:
        raise ValueError("unsupported STFS hash-table relationship")
    if selector + 1 > len(data):
        raise ValueError("hash table selector is outside the container")
    return address + ((data[selector] & 0x40) << 6)


def _table_count(header: StfsHeader, level: int) -> int:
    covered = (0xAA, 0x70E4, 0x4AF768)[level]
    return (header.allocated_block_count + covered - 1) // covered


def _table_entry_count(header: StfsHeader, level: int, index: int) -> int:
    if level == 0:
        return min(0xAA, header.allocated_block_count - index * 0xAA)
    child_count = _table_count(header, level - 1)
    return min(0xAA, child_count - index * 0xAA)


def rehash_stfs_hashes(data: bytes, header: StfsHeader | None = None) -> bytes:
    """Rebuild the complete STFS hash tree without changing its allocation.

    This updates data-block hashes, every present intermediate table, the
    table count words, the top-table digest, and the metadata digest.  It does
    not create new allocation levels and does not generate the package's RSA
    signature.
    """
    header = header or parse_stfs_header(data)
    result = bytearray(data)
    top_level = _top_level(header)

    def write_hash(record: int, payload: bytes) -> None:
        if record < 0 or record + 0x14 > len(result):
            raise ValueError("hash record is outside the container")
        result[record : record + 0x14] = hashlib.sha1(payload).digest()

    # Rebuild level-0 tables and hash each selected table into its parent.
    for table_index in range(_table_count(header, 0)):
        first_block = table_index * 0xAA
        table_address = _hash_table_address(result, first_block, header, 0)
        count = _table_entry_count(header, 0, table_index)
        for offset in range(count):
            block = first_block + offset
            address = block_offset(block, header.header_size, header.block_separation)
            record = table_address + offset * 0x18
            if address + BLOCK_SIZE > len(result):
                raise ValueError("data block is outside the container")
            write_hash(record, result[address : address + BLOCK_SIZE])
        table_bytes = bytes(result[table_address : table_address + BLOCK_SIZE])
        if len(table_bytes) != BLOCK_SIZE:
            raise ValueError("level-0 hash table is outside the container")
        if top_level == 1:
            parent_address = _hash_table_address(result, 0, header, 1)
            write_hash(parent_address + table_index * 0x18, table_bytes)

    if top_level == 2:
        # Level-1 tables hash the level-0 tables.  The final word records the
        # number of data blocks covered by each level-1 table.
        for table_index in range(_table_count(header, 1)):
            first_level0 = table_index * 0xAA
            table_address = _hash_table_address(result, table_index * 0x70E4, header, 1)
            count = _table_entry_count(header, 1, table_index)
            for offset in range(count):
                level0_index = first_level0 + offset
                level0_address = _hash_table_address(result, level0_index * 0xAA, header, 0)
                write_hash(table_address + offset * 0x18, bytes(result[level0_address : level0_address + BLOCK_SIZE]))
            covered = _table_entry_count(header, 2, table_index)
            result[table_address + 0xFFC : table_address + 0x1000] = covered.to_bytes(4, "little")
            parent_address = _hash_table_address(result, 0, header, 2)
            write_hash(parent_address + table_index * 0x18, bytes(result[table_address : table_address + BLOCK_SIZE]))

    top_address = _hash_table_address(result, 0, header, top_level)
    if top_level >= 1:
        result[top_address + 0xFFC : top_address + 0x1000] = header.allocated_block_count.to_bytes(4, "little")
    result[0x381:0x395] = hashlib.sha1(result[top_address : top_address + BLOCK_SIZE]).digest()
    first_hash_table = (header.header_size + 0xFFF) & 0xFFFFF000
    result[0x32C:0x340] = hashlib.sha1(result[0x344:first_hash_table]).digest()
    return bytes(result)


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


def list_embedded_xdbf(
    data: bytes, header: StfsHeader | None = None
) -> tuple[tuple[StfsEntry, tuple[XdbfEntry, ...]], ...]:
    """Enumerate parseable XDBF payloads embedded in STFS GPD files."""
    header = header or parse_stfs_header(data)
    result: list[tuple[StfsEntry, tuple[XdbfEntry, ...]]] = []
    for entry in list_stfs_entries(data, header):
        if entry.is_directory or not entry.path.lower().endswith(".gpd"):
            continue
        try:
            entries = parse_xdbf(read_stfs_entry(data, entry, header))
        except (OSError, ValueError, IsADirectoryError):
            continue
        result.append((entry, entries))
    return tuple(result)


def list_embedded_achievements(
    data: bytes, header: StfsHeader | None = None
) -> tuple[dict[str, object], ...]:
    """Return normalized observed achievement records from embedded GPDs."""
    records: list[dict[str, object]] = []
    for entry, xdbf_entries in list_embedded_xdbf(data, header):
        for xdbf_entry in xdbf_entries:
            if xdbf_entry.achievement is None:
                continue
            records.append(
                {
                    "file": entry.path,
                    "index": xdbf_entry.index,
                    "namespace": xdbf_entry.namespace,
                    "entry_id": xdbf_entry.entry_id,
                    "achievement": xdbf_entry.achievement,
                }
            )
    return tuple(records)


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

    return rehash_stfs_hashes(bytes(result), header)


def mutate_stfs_metadata(
    data: bytes,
    *,
    display_name: str | None = None,
    title_id: int | None = None,
    content_type: int | None = None,
    display_description: str | None = None,
    publisher_name: str | None = None,
    title_name: str | None = None,
    transfer_flags: int | None = None,
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
    for value, offset in (
        (display_description, 0xD11),
        (publisher_name, 0x1611),
        (title_name, 0x1691),
    ):
        if value is None:
            continue
        encoded = value.encode("utf-16-be") + b"\x00\x00"
        if len(encoded) > 0x80:
            raise ValueError("metadata text exceeds its 0x80-byte field")
        result[offset : offset + 0x80] = encoded.ljust(0x80, b"\x00")
    if transfer_flags is not None:
        if not 0 <= transfer_flags <= 0xFF:
            raise ValueError("transfer flags must fit in one byte")
        result[0x1711] = transfer_flags
    return rehash_stfs_hashes(bytes(result), header)


def parse_stfs_thumbnails(data: bytes, header: StfsHeader | None = None) -> StfsThumbnails:
    """Read bounded STFS thumbnail payloads without interpreting image bytes."""
    header = header or parse_stfs_header(data)
    thumbnail_size = _u32be(data, 0x1712)
    title_size = _u32be(data, 0x1716)
    capacity = 0x4000
    if thumbnail_size > capacity or title_size > capacity:
        raise ValueError("STFS thumbnail size exceeds its metadata field capacity")
    thumbnail = data[0x171A : 0x171A + thumbnail_size]
    title_thumbnail = data[0x571A : 0x571A + title_size]
    if len(thumbnail) != thumbnail_size or len(title_thumbnail) != title_size:
        raise ValueError("STFS thumbnail points beyond the metadata header")
    return StfsThumbnails(thumbnail_size, title_size, thumbnail, title_thumbnail)


def mutate_stfs_thumbnails(
    data: bytes,
    *,
    thumbnail: bytes | None = None,
    title_thumbnail: bytes | None = None,
    header: StfsHeader | None = None,
) -> bytes:
    """Replace thumbnail payloads within their fixed STFS metadata capacity."""
    header = header or parse_stfs_header(data)
    result = bytearray(data)
    capacity = 0x4000
    for offset, size_offset, payload in (
        (0x171A, 0x1712, thumbnail),
        (0x571A, 0x1716, title_thumbnail),
    ):
        if payload is None:
            continue
        if len(payload) > capacity:
            raise ValueError("thumbnail exceeds the fixed STFS metadata capacity")
        result[size_offset : size_offset + 4] = len(payload).to_bytes(4, "big")
        result[offset : offset + capacity] = payload.ljust(capacity, b"\x00")
    return rehash_stfs_hashes(bytes(result), header)


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


def _stfs_file_table_blocks(data: bytes, header: StfsHeader) -> tuple[int, ...]:
    """Return the logical blocks in the file-table chain."""
    blocks: list[int] = []
    block = header.file_table_block_number
    for index in range(header.file_table_block_count):
        if block < 0:
            raise ValueError("file table chain terminates before its declared length")
        blocks.append(block)
        block = _next_block(data, block, header)
        if index + 1 < header.file_table_block_count and block < 0:
            raise ValueError("file table chain is incomplete")
    return tuple(blocks)


def _all_stfs_file_table_slots(data: bytes, header: StfsHeader) -> tuple[int, ...]:
    """Return every physical file-table slot, including empty slots."""
    slots: list[int] = []
    block = header.file_table_block_number
    for table_index in range(header.file_table_block_count):
        address = block_offset(block, header.header_size, header.block_separation)
        if address + BLOCK_SIZE > len(data):
            raise ValueError("file table points beyond the end of the container")
        slots.extend(address + slot * 0x40 for slot in range(64))
        block = _next_block(data, block, header)
    return tuple(slots)


def rename_stfs_entry(
    data: bytes,
    entry_path: str,
    new_name: str,
    header: StfsHeader | None = None,
) -> bytes:
    """Rename one STFS file or directory without changing its parent."""
    header = header or parse_stfs_header(data)
    entries = list(list_stfs_entries(data, header))
    entry = next((item for item in entries if item.path == entry_path), None)
    if entry is None:
        raise FileNotFoundError(entry_path)
    encoded_name = new_name.encode("ascii")
    if not encoded_name or len(encoded_name) > 0x28 or b"/" in encoded_name or b"\\" in encoded_name:
        raise ValueError("STFS names must be non-empty ASCII basenames of at most 40 bytes")
    parent = entry_path.rsplit("/", 1)[0] if "/" in entry_path else ""
    new_path = f"{parent}/{new_name}" if parent else new_name
    if any(item.path == new_path for item in entries if item.path != entry_path):
        raise ValueError(f"STFS entry already exists: {new_path}")
    slots = _stfs_file_table_slots(data, header)
    if entry.index >= len(slots):
        raise ValueError("STFS entry index does not resolve to a file-table slot")
    result = bytearray(data)
    slot = slots[entry.index]
    result[slot : slot + 0x28] = encoded_name.ljust(0x28, b"\x00")
    result[slot + 0x28] = (result[slot + 0x28] & 0xC0) | len(encoded_name)
    return rehash_stfs_hashes(bytes(result), header)


def add_stfs_directory(data: bytes, directory_path: str, header: StfsHeader | None = None) -> bytes:
    """Add an empty STFS directory in an available file-table slot."""
    header = header or parse_stfs_header(data)
    entries = list(list_stfs_entries(data, header))
    if not directory_path or directory_path.endswith("/"):
        raise ValueError("directory path must be a non-empty path")
    parent_path, _, name = directory_path.rpartition("/")
    encoded_name = name.encode("ascii")
    if not encoded_name or len(encoded_name) > 0x28 or b"/" in encoded_name or b"\\" in encoded_name:
        raise ValueError("STFS directory names must be non-empty ASCII basenames of at most 40 bytes")
    parent_index = 0xFFFF
    if parent_path:
        parent = next((item for item in entries if item.path == parent_path), None)
        if parent is None or not parent.is_directory:
            raise FileNotFoundError(f"parent directory does not exist: {parent_path}")
        parent_index = parent.index
    if any(item.path == directory_path for item in entries):
        raise ValueError(f"STFS entry already exists: {directory_path}")
    all_slots = _all_stfs_file_table_slots(data, header)
    used_slots = set(_stfs_file_table_slots(data, header))
    candidates = [slot for slot in all_slots if slot not in used_slots]
    if not candidates:
        raise ValueError("STFS file-table capacity is exhausted")
    slot = candidates[0]
    old_index_by_slot = {slot_address: item.index for slot_address, item in zip(_stfs_file_table_slots(data, header), entries)}
    new_index_by_slot: dict[int, int] = {}
    old_to_new: dict[int, int] = {}
    next_index = 0
    for slot_address in all_slots:
        if slot_address not in used_slots and slot_address != slot:
            continue
        new_index_by_slot[slot_address] = next_index
        if slot_address in old_index_by_slot:
            old_to_new[old_index_by_slot[slot_address]] = next_index
        next_index += 1
    result = bytearray(data)
    for slot_address in used_slots:
        old_parent = int.from_bytes(result[slot_address + 0x32 : slot_address + 0x34], "big")
        if old_parent != 0xFFFF:
            if old_parent not in old_to_new:
                raise ValueError("STFS parent index cannot be remapped")
            result[slot_address + 0x32 : slot_address + 0x34] = old_to_new[old_parent].to_bytes(2, "big")
    raw = bytearray(0x40)
    raw[: len(encoded_name)] = encoded_name
    raw[0x28] = 0x80 | len(encoded_name)
    raw[0x32:0x34] = (0xFFFF if parent_index == 0xFFFF else old_to_new[parent_index]).to_bytes(2, "big")
    result[slot : slot + 0x40] = raw
    return rehash_stfs_hashes(bytes(result), header)


def move_stfs_entry(
    data: bytes,
    entry_path: str,
    destination_directory: str,
    new_name: str | None = None,
    header: StfsHeader | None = None,
) -> bytes:
    """Move an STFS entry to an existing directory without reallocating data."""
    header = header or parse_stfs_header(data)
    entries = list(list_stfs_entries(data, header))
    entry = next((item for item in entries if item.path == entry_path), None)
    destination = next((item for item in entries if item.path == destination_directory), None)
    if entry is None:
        raise FileNotFoundError(entry_path)
    if destination is None or not destination.is_directory:
        raise FileNotFoundError(f"destination directory does not exist: {destination_directory}")
    if entry.is_directory and (destination_directory == entry_path or destination_directory.startswith(entry_path + "/")):
        raise ValueError("an STFS directory cannot be moved into itself or its descendants")
    target_name = new_name or entry.name
    encoded_name = target_name.encode("ascii")
    if not encoded_name or len(encoded_name) > 0x28 or b"/" in encoded_name or b"\\" in encoded_name:
        raise ValueError("STFS names must be non-empty ASCII basenames of at most 40 bytes")
    new_path = f"{destination_directory}/{target_name}"
    if any(item.path == new_path and item.path != entry_path for item in entries):
        raise ValueError(f"STFS entry already exists: {new_path}")
    slots = _stfs_file_table_slots(data, header)
    if entry.index >= len(slots):
        raise ValueError("STFS entry index does not resolve to a file-table slot")
    result = bytearray(data)
    slot = slots[entry.index]
    result[slot : slot + 0x28] = encoded_name.ljust(0x28, b"\x00")
    result[slot + 0x28] = (result[slot + 0x28] & 0xC0) | len(encoded_name)
    result[slot + 0x32 : slot + 0x34] = destination.index.to_bytes(2, "big")
    return rehash_stfs_hashes(bytes(result), header)


def repack_stfs_entries(
    data: bytes,
    replacements: dict[str, bytes],
    header: StfsHeader | None = None,
    remove: Iterable[str] = (),
    additions: dict[str, bytes] | None = None,
) -> bytes:
    """Repack one or more entries within the package's existing block capacity.

    The operation preserves the physical package size and reserves the
    existing file-table blocks.  It refuses requests that need a larger STFS
    allocation table, leaving creation of new hash-table levels explicit.
    """
    header = header or parse_stfs_header(data)
    entries = list(list_stfs_entries(data, header))
    removals = set(remove)
    additions = dict(additions or {})
    by_path = {entry.path: entry for entry in entries}
    unknown = sorted((set(replacements) | removals) - set(by_path))
    if unknown:
        raise FileNotFoundError(unknown[0])
    conflicts = sorted((set(additions) & set(by_path)) | (set(additions) & removals))
    if conflicts:
        raise ValueError(f"entry already exists: {conflicts[0]}")
    if any(not path or path.endswith("/") for path in additions):
        raise ValueError("added entries must be non-empty file paths")
    for path in additions:
        name = path.rsplit("/", 1)[-1]
        if not name or len(name.encode("ascii", errors="ignore")) != len(name) or len(name) > 0x28:
            raise ValueError(f"added entry name is not a supported ASCII file name: {path!r}")
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if parent and (parent not in by_path or not by_path[parent].is_directory):
            raise FileNotFoundError(f"parent directory does not exist: {parent}")
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
    payloads = {**original_payloads, **replacements, **additions}
    for path in removals:
        payloads.pop(path, None)
    reserved = set(_stfs_file_table_blocks(data, header))
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
    for path, payload in additions.items():
        block_count = (len(payload) + BLOCK_SIZE - 1) // BLOCK_SIZE
        selected = tuple(available[cursor : cursor + block_count])
        if len(selected) != block_count:
            raise ValueError("addition set exceeds the existing STFS allocation capacity")
        allocations[path] = selected
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

    all_slots = _all_stfs_file_table_slots(data, header)
    occupied = {
        slot
        for entry, slot in zip(entries, slots)
        if entry.path not in removals
    }
    free_slots = [slot for slot in all_slots if slot not in occupied]
    if len(free_slots) < len(additions):
        raise ValueError("file-table capacity is exhausted")
    entry_indices = {entry.path: entry.index for entry in entries}
    for (path, payload), slot in zip(additions.items(), free_slots):
        name = path.rsplit("/", 1)[-1].encode("ascii")
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        parent_index = 0xFFFF if not parent else entry_indices[parent]
        blocks = allocations[path]
        raw = bytearray(0x40)
        raw[: len(name)] = name
        raw[0x28] = (len(name) | 0x40) & 0x7F
        raw[0x29:0x2C] = len(blocks).to_bytes(3, "little")
        raw[0x2F:0x32] = (blocks[0] if blocks else 0).to_bytes(3, "little")
        raw[0x32:0x34] = parent_index.to_bytes(2, "big")
        raw[0x34:0x38] = len(payload).to_bytes(4, "big")
        result[slot : slot + 0x40] = raw

    return rehash_stfs_hashes(bytes(result), header)


def verify_stfs_hashes(
    data: bytes,
    entry: StfsEntry | None = None,
    header: StfsHeader | None = None,
) -> dict:
    """Verify data-block and metadata-header hashes without asserting signing validity."""
    header = header or parse_stfs_header(data)
    entries = (entry,) if entry is not None else list_stfs_entries(data, header)
    failures: list[dict] = []
    hash_table_failures: list[dict] = []
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
    top_level = _top_level(header)
    for table_index in range(_table_count(header, 0)):
        level0_address = _hash_table_address(data, table_index * 0xAA, header, 0)
        actual = hashlib.sha1(data[level0_address : level0_address + BLOCK_SIZE]).digest()
        if top_level == 1:
            parent_address = _hash_table_address(data, 0, header, 1)
            expected = data[parent_address + table_index * 0x18 : parent_address + table_index * 0x18 + 0x14]
        elif top_level == 2:
            parent_address = _hash_table_address(data, (table_index // 0xAA) * 0x70E4, header, 1)
            expected = data[parent_address + (table_index % 0xAA) * 0x18 : parent_address + (table_index % 0xAA) * 0x18 + 0x14]
        else:
            expected = actual
        if actual != expected:
            hash_table_failures.append({"level": 0, "table": table_index, "reason": "table_hash"})

    if top_level == 2:
        top_address = _hash_table_address(data, 0, header, 2)
        for table_index in range(_table_count(header, 1)):
            level1_address = _hash_table_address(data, table_index * 0x70E4, header, 1)
            actual = hashlib.sha1(data[level1_address : level1_address + BLOCK_SIZE]).digest()
            expected = data[top_address + table_index * 0x18 : top_address + table_index * 0x18 + 0x14]
            if actual != expected:
                hash_table_failures.append({"level": 1, "table": table_index, "reason": "table_hash"})
    top_address = _hash_table_address(data, 0, header, top_level)
    top_hash_matches = (
        hashlib.sha1(data[top_address : top_address + BLOCK_SIZE]).digest() == data[0x381:0x395]
    )
    return {
        "checked_blocks": checked_blocks,
        "failures": failures,
        "hash_table_failures": hash_table_failures,
        "header_hash_matches": header_hash_matches,
        "top_hash_matches": top_hash_matches,
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
    security = None
    entries: tuple[StfsEntry, ...] = ()
    if data[:4] in STFS_MAGICS:
        try:
            header = parse_stfs_header(data)
            security = parse_stfs_security_metadata(data)
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
        stfs_security=security,
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
    parser.add_argument("--capabilities", action="store_true", help="Print the evidence-qualified implementation capability ledger")
    parser.add_argument("--native-surface", action="store_true", help="Print the REA-observed native import boundary")
    parser.add_argument("--catalog", choices=("shared", "skyrim", "gears", "halo"), help="Print one REA-observed title catalog")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--list", action="store_true", help="List STFS file-table entries")
    parser.add_argument("--list-xdbf", action="store_true", help="List parsed XDBF entries from embedded GPD files")
    parser.add_argument("--list-achievements", action="store_true", help="List observed achievements from embedded GPD files")
    parser.add_argument("--achievements-output", type=Path, help="Write embedded achievement records as JSON")
    parser.add_argument("--extract-dir", type=Path, help="Extract STFS files into this directory")
    parser.add_argument("--extract", metavar="ENTRY", help="Extract only this STFS path")
    parser.add_argument("--verify-hashes", action="store_true", help="Verify STFS block and metadata hashes")
    parser.add_argument("--security", action="store_true", help="Show STFS public security and license metadata")
    parser.add_argument("--replace", metavar="ENTRY", help="Replace one STFS file in place")
    parser.add_argument("--replacement", type=Path, help="Raw replacement bytes for --replace")
    parser.add_argument("--repack", metavar="ENTRY", help="Replace one STFS file with a different size")
    parser.add_argument("--repack-source", type=Path, help="Raw replacement bytes for --repack")
    parser.add_argument("--remove", action="append", metavar="ENTRY", help="Remove an STFS file-table entry")
    parser.add_argument("--add", action="append", metavar="ENTRY", help="Add an STFS file-table entry")
    parser.add_argument("--add-source", action="append", type=Path, help="Raw bytes for --add (repeat in the same order)")
    parser.add_argument("--rename", metavar="ENTRY", help="Rename an STFS file or directory")
    parser.add_argument("--new-name", help="New ASCII basename for --rename")
    parser.add_argument("--mkdir", metavar="PATH", help="Add an empty STFS directory")
    parser.add_argument("--move", metavar="ENTRY", help="Move an STFS entry to another directory")
    parser.add_argument("--move-to", metavar="DIRECTORY", help="Destination directory for --move")
    parser.add_argument("--write", type=Path, help="Write a mutated container to this path")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite the input container with a mutation (explicit destructive opt-in)",
    )
    parser.add_argument("--backup", type=Path, help="Save the original input before --in-place mutation")
    parser.add_argument("--display-name", help="Replace the fixed-width STFS display name")
    parser.add_argument("--display-description", help="Replace the first STFS display-description locale")
    parser.add_argument("--publisher-name", help="Replace the STFS publisher name")
    parser.add_argument("--title-name", help="Replace the STFS title name")
    parser.add_argument("--transfer-flags", type=lambda value: int(value, 0), help="Replace STFS transfer flags")
    parser.add_argument("--title-id", type=lambda value: int(value, 0), help="Replace the STFS title ID")
    parser.add_argument("--content-type", type=lambda value: int(value, 0), help="Replace the STFS content type")
    parser.add_argument("--thumbnail-source", type=Path, help="Replace the STFS thumbnail payload")
    parser.add_argument("--title-thumbnail-source", type=Path, help="Replace the STFS title-thumbnail payload")
    parser.add_argument("--thumbnail-output", type=Path, help="Write the STFS thumbnail payload")
    parser.add_argument("--title-thumbnail-output", type=Path, help="Write the STFS title-thumbnail payload")
    parser.add_argument("--xdbf-replace", type=int, metavar="INDEX", help="Replace one XDBF entry")
    parser.add_argument("--xdbf-source", type=Path, help="Raw replacement bytes for --xdbf-replace")
    parser.add_argument("--xdbf-remove", type=int, action="append", metavar="INDEX", help="Remove an XDBF entry")
    parser.add_argument("--xdbf-add-namespace", type=lambda value: int(value, 0), metavar="VALUE")
    parser.add_argument("--xdbf-add-id", type=lambda value: int(value, 0), metavar="VALUE")
    parser.add_argument("--xdbf-add-source", type=Path, metavar="FILE")
    parser.add_argument("--xdbf-text", type=int, metavar="INDEX", help="Edit one observed namespace-5 XDBF string")
    parser.add_argument("--xdbf-text-value", help="Replacement value for --xdbf-text")
    parser.add_argument("--xdbf-file", metavar="ENTRY", help="STFS file containing the XDBF entry to edit")
    parser.add_argument("--achievement", type=int, metavar="INDEX", help="Edit one XDBF achievement entry")
    parser.add_argument("--achievement-id", type=lambda value: int(value, 0))
    parser.add_argument("--image-id", type=lambda value: int(value, 0))
    parser.add_argument("--gamerscore", type=int)
    parser.add_argument("--achievement-flags", type=lambda value: int(value, 0))
    parser.add_argument("--achievement-name")
    args = parser.parse_args()
    if args.capabilities:
        print(json.dumps(capability_report(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.native_surface:
        print(json.dumps(native_surface_report(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.catalog:
        print(json.dumps(catalog_report(args.catalog), indent=2, ensure_ascii=False))
        return 0
    if args.achievements_output:
        args.list_achievements = True
    if args.write and args.in_place:
        parser.error("--write and --in-place cannot be combined")
    if args.backup and not args.in_place:
        parser.error("--backup requires --in-place")
    if args.backup and args.backup.resolve() == args.path.resolve():
        parser.error("--backup must be different from the input path")
    write_target = args.path if args.in_place else args.write
    mutation_written = False

    def write_mutation(data: bytes) -> None:
        if not args.in_place:
            write_target.write_bytes(data)
            return
        if args.backup:
            args.backup.write_bytes(args.path.read_bytes())
        temporary = Path(str(args.path) + ".horizon-tmp")
        try:
            temporary.write_bytes(data)
            temporary.replace(args.path)
        finally:
            temporary.unlink(missing_ok=True)

    try:
        raw = args.path.read_bytes()
        if raw[:4] == b"XDBF":
            achievement_requested = args.achievement is not None
            xdbf_add_requested = any(
                value is not None
                for value in (args.xdbf_add_namespace, args.xdbf_add_id, args.xdbf_add_source)
            )
            text_requested = args.xdbf_text is not None or args.xdbf_text_value is not None
            if args.xdbf_replace is not None or args.xdbf_remove or achievement_requested or xdbf_add_requested or text_requested:
                if not write_target:
                    parser.error("XDBF mutation requires --write or --in-place")
                if args.xdbf_replace is not None and not args.xdbf_source:
                    parser.error("--xdbf-replace requires --xdbf-source")
                replacements = {}
                if args.xdbf_replace is not None:
                    replacements[args.xdbf_replace] = args.xdbf_source.read_bytes()
                additions = {}
                if xdbf_add_requested:
                    if args.xdbf_add_namespace is None or args.xdbf_add_id is None or not args.xdbf_add_source:
                        parser.error("XDBF addition requires --xdbf-add-namespace, --xdbf-add-id, and --xdbf-add-source")
                    additions[(args.xdbf_add_namespace, args.xdbf_add_id)] = args.xdbf_add_source.read_bytes()
                if text_requested:
                    if args.xdbf_text is None or args.xdbf_text_value is None:
                        parser.error("--xdbf-text requires --xdbf-text-value")
                    raw = mutate_xdbf_text(raw, args.xdbf_text, args.xdbf_text_value)
                raw = repack_xdbf_entries(
                    raw,
                    replacements,
                    remove=args.xdbf_remove or (),
                    additions=additions,
                )
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
                write_mutation(raw)
                print(f"Wrote XDBF mutation to {write_target}")
            payload = json.dumps(_json_xdbf(raw, args.path), indent=2, ensure_ascii=False)
            if args.output:
                args.output.write_text(payload + "\n", encoding="utf-8")
            if args.list:
                for entry in parse_xdbf(raw):
                    kind = "achievement" if entry.achievement is not None else "entry"
                    label = entry.text if entry.text is not None else ""
                    print(f"{kind} {entry.index:>6} ns={entry.namespace:>5} id=0x{entry.entry_id:X} size={entry.length:>8} {label}")
            if args.as_json or not args.output:
                if not args.list:
                    print(payload)
            return 0
        report = inspect(args.path)
    except OSError as exc:
        parser.error(str(exc))

    if args.xdbf_file is not None:
        embedded_text_requested = args.xdbf_text is not None or args.xdbf_text_value is not None
        embedded_achievement_requested = args.achievement is not None
        embedded_structural_requested = (
            args.xdbf_replace is not None
            or bool(args.xdbf_remove)
            or args.xdbf_add_namespace is not None
            or args.xdbf_add_id is not None
            or args.xdbf_add_source is not None
        )
        requested_operations = sum(
            (embedded_text_requested, embedded_achievement_requested, embedded_structural_requested)
        )
        if not write_target or requested_operations != 1:
            parser.error("--xdbf-file requires exactly one embedded XDBF edit and --write or --in-place")
        if embedded_text_requested and (args.xdbf_text is None or args.xdbf_text_value is None):
            parser.error("embedded text editing requires --xdbf-text and --xdbf-text-value")
        if not report.stfs_header:
            parser.error("--xdbf-file requires a readable STFS header")
        entry = next((item for item in report.entries if item.path == args.xdbf_file), None)
        if entry is None or entry.is_directory:
            parser.error(f"STFS XDBF file not found: {args.xdbf_file}")
        try:
            xdbf_payload = read_stfs_entry(raw, entry, report.stfs_header)
            if embedded_text_requested:
                edited_payload = mutate_xdbf_text(xdbf_payload, args.xdbf_text, args.xdbf_text_value)
                operation_name = "text"
            elif embedded_achievement_requested:
                edited_payload = mutate_xdbf_achievement(
                    xdbf_payload,
                    args.achievement,
                    achievement_id=args.achievement_id,
                    image_id=args.image_id,
                    gamerscore=args.gamerscore,
                    flags=args.achievement_flags,
                    name=args.achievement_name,
                )
                operation_name = "achievement"
            else:
                if args.xdbf_replace is not None and not args.xdbf_source:
                    parser.error("embedded --xdbf-replace requires --xdbf-source")
                if args.xdbf_replace is None and args.xdbf_source:
                    parser.error("embedded --xdbf-source requires --xdbf-replace")
                add_requested = any(
                    value is not None
                    for value in (args.xdbf_add_namespace, args.xdbf_add_id, args.xdbf_add_source)
                )
                additions = {}
                if add_requested:
                    if args.xdbf_add_namespace is None or args.xdbf_add_id is None or not args.xdbf_add_source:
                        parser.error("embedded XDBF addition requires namespace, ID, and source")
                    additions[(args.xdbf_add_namespace, args.xdbf_add_id)] = args.xdbf_add_source.read_bytes()
                replacements = {}
                if args.xdbf_replace is not None:
                    replacements[args.xdbf_replace] = args.xdbf_source.read_bytes()
                edited_payload = repack_xdbf_entries(
                    xdbf_payload,
                    replacements,
                    remove=args.xdbf_remove or (),
                    additions=additions,
                )
                operation_name = "structural"
            raw = repack_stfs_entries(raw, {entry.path: edited_payload}, report.stfs_header)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, IndexError, IsADirectoryError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned embedded XDBF {operation_name} mutation to {write_target}")

    if args.rename:
        if not args.new_name or not write_target:
            parser.error("--rename requires --new-name and --write or --in-place")
        if not report.stfs_header:
            parser.error("--rename requires a readable STFS header")
        try:
            raw = rename_stfs_entry(raw, args.rename, args.new_name, report.stfs_header)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned STFS rename to {write_target}")

    if args.mkdir:
        if not write_target:
            parser.error("--mkdir requires --write or --in-place")
        if not report.stfs_header:
            parser.error("--mkdir requires a readable STFS header")
        try:
            raw = add_stfs_directory(raw, args.mkdir, report.stfs_header)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned STFS directory addition to {write_target}")

    if args.move:
        if not args.move_to or not write_target:
            parser.error("--move requires --move-to and --write or --in-place")
        if not report.stfs_header:
            parser.error("--move requires a readable STFS header")
        try:
            raw = move_stfs_entry(raw, args.move, args.move_to, args.new_name, report.stfs_header)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned STFS move to {write_target}")

    if args.list:
        if not report.entries:
            parser.error("the file does not contain a readable STFS file table")
        for entry in report.entries:
            kind = "DIR " if entry.is_directory else "FILE"
            print(f"{kind} {entry.size:>10} {entry.path}")
    if args.list_xdbf:
        if not report.stfs_header:
            parser.error("--list-xdbf requires a readable STFS header")
        for file_entry, xdbf_entries in list_embedded_xdbf(raw, report.stfs_header):
            for xdbf_entry in xdbf_entries:
                kind = "achievement" if xdbf_entry.achievement is not None else "string" if xdbf_entry.text is not None else "entry"
                label = xdbf_entry.text or (xdbf_entry.achievement or {}).get("name") or ""
                safe_label = str(label).encode("ascii", errors="backslashreplace").decode("ascii")
                print(f"{file_entry.path} {kind} {xdbf_entry.index:>6} ns={xdbf_entry.namespace:>5} id=0x{xdbf_entry.entry_id:X} size={xdbf_entry.length:>8} {safe_label}")
    if args.list_achievements:
        if not report.stfs_header:
            parser.error("--list-achievements requires a readable STFS header")
        achievement_records = list_embedded_achievements(raw, report.stfs_header)
        for record in achievement_records:
                file_entry = record["file"]
                xdbf_index = record["index"]
                entry_id = record["entry_id"]
                achievement = record["achievement"]
                safe_name = str(achievement.get("name", "")).encode("ascii", errors="backslashreplace").decode("ascii")
                print(
                    f"{file_entry} {xdbf_index:>6} id=0x{entry_id:X} "
                    f"achievement_id={achievement['achievement_id']} image_id={achievement['image_id']} "
                    f"gamerscore={achievement['gamerscore']} flags=0x{achievement['flags']:X} {safe_name}"
                )
        if args.achievements_output:
            args.achievements_output.write_text(
                json.dumps(achievement_records, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    if args.extract_dir:
        written = extract_stfs(raw, args.extract_dir, selected_path=args.extract)
        print(f"Extracted {len(written)} file(s) to {args.extract_dir}")

    if args.verify_hashes:
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        verification = verify_stfs_hashes(raw, header=report.stfs_header)
        print(json.dumps(verification, indent=2))

    if args.security:
        if not report.stfs_security:
            parser.error("the file does not contain readable STFS security metadata")
        print(json.dumps(asdict(report.stfs_security), indent=2))

    if args.replace:
        if not args.replacement or not write_target:
            parser.error("--replace requires --replacement and --write or --in-place")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        entry = next((item for item in report.entries if item.path == args.replace), None)
        if entry is None:
            parser.error(f"STFS entry not found: {args.replace}")
        try:
            replacement = args.replacement.read_bytes()
            mutated = mutate_stfs_entry_same_size(raw, entry, replacement, report.stfs_header)
            write_mutation(mutated)
            mutation_written = True
        except (OSError, ValueError, IsADirectoryError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned in-place mutation to {write_target}")

    if args.repack:
        if args.replace or not args.repack_source or not write_target:
            parser.error("--repack requires --repack-source and --write or --in-place, and cannot be combined with --replace")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = repack_stfs_entries(
                raw,
                {args.repack: args.repack_source.read_bytes()},
                report.stfs_header,
            )
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, IsADirectoryError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned repacked container to {write_target}")

    if args.remove:
        if args.replace or args.repack or args.add or not write_target:
            parser.error("--remove requires --write or --in-place and cannot be combined with --replace, --repack, or --add")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = repack_stfs_entries(raw, {}, remove=args.remove, header=report.stfs_header)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, IsADirectoryError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned removal mutation to {write_target}")

    if args.add:
        if args.replace or args.repack or args.remove or not write_target:
            parser.error("--add requires --write or --in-place and cannot be combined with --replace, --repack, or --remove")
        if not args.add_source or len(args.add_source) != len(args.add):
            parser.error("each --add requires one corresponding --add-source")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            additions = {path: source.read_bytes() for path, source in zip(args.add, args.add_source)}
            raw = repack_stfs_entries(raw, {}, header=report.stfs_header, additions=additions)
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError, FileNotFoundError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned file addition to {write_target}")

    metadata_requested = any(
        value is not None
        for value in (
            args.display_name,
            args.display_description,
            args.publisher_name,
            args.title_name,
            args.transfer_flags,
            args.title_id,
            args.content_type,
        )
    )
    if metadata_requested:
        if not write_target:
            parser.error("metadata mutation requires --write or --in-place")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = mutate_stfs_metadata(
                raw,
                display_name=args.display_name,
                display_description=args.display_description,
                publisher_name=args.publisher_name,
                title_name=args.title_name,
                transfer_flags=args.transfer_flags,
                title_id=args.title_id,
                content_type=args.content_type,
                header=report.stfs_header,
            )
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned metadata mutation to {write_target}")

    thumbnails_requested = args.thumbnail_source is not None or args.title_thumbnail_source is not None
    thumbnail_exports_requested = args.thumbnail_output is not None or args.title_thumbnail_output is not None
    if thumbnail_exports_requested:
        if not report.stfs_header:
            parser.error("thumbnail export requires a readable STFS header")
        try:
            thumbnails = parse_stfs_thumbnails(raw, header=report.stfs_header)
            if args.thumbnail_output:
                args.thumbnail_output.write_bytes(thumbnails.thumbnail)
            if args.title_thumbnail_output:
                args.title_thumbnail_output.write_bytes(thumbnails.title_thumbnail)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print("Exported requested thumbnail payload(s)")
    if thumbnails_requested:
        if not write_target:
            parser.error("thumbnail mutation requires --write or --in-place")
        if not report.stfs_header:
            parser.error("the file does not contain a readable STFS header")
        try:
            raw = mutate_stfs_thumbnails(
                raw,
                thumbnail=args.thumbnail_source.read_bytes() if args.thumbnail_source else None,
                title_thumbnail=args.title_thumbnail_source.read_bytes() if args.title_thumbnail_source else None,
                header=parse_stfs_header(raw),
            )
            write_mutation(raw)
            mutation_written = True
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f"Wrote unsigned thumbnail mutation to {write_target}")

    if mutation_written:
        report = inspect(write_target)
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

