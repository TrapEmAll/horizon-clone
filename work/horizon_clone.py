"""Clean-room Xbox 360 content-container inspector.

This module intentionally limits itself to evidence-backed reconstruction.  It
does not copy Horizon code/resources and does not claim retail signing or
console validity for caller-requested mutations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

from .editor_inventory import capability_report, catalog_report, rea_feature_ledger
from .native_surface import managed_native_import_report, native_export_contract_report, native_installation_report, native_surface_report
from .device_surface import device_surface_report
from .device_binding import DeviceIoBinding, WindowsDeviceIoProvider
from .native_runtime import NativeRuntimeBinding, PowerShellNativeRuntimeProvider
from .native_compression import LzoBinding, PowerShellLzoProvider
from .lzo_codec import LzoCodec
from .resource_inventory import extract_managed_resource_payloads, observed_resource_surface, parse_dotnet_resources, resource_payload_metadata, resource_surface_report, verify_managed_resource_payloads
from .managed_surface import managed_artifact_report, managed_body_fidelity_report, managed_editor_family_report, managed_guarded_methods_report, managed_io_contract_report, managed_named_namespace_report, managed_reference_report, managed_schema_report, managed_surface_report
from .device_inventory import device_inventory_report, enumerate_host_device_entries
from .signing import RsaPublicKey, verify_xecrypt_sha1_pkcs1v15
from .native_loader import compatible_pe_architecture, pe_export_names
from .anti_analysis import anti_analysis_report


def _atomic_replace_bytes(path: Path, data: bytes) -> None:
    """Replace a file through a same-directory temporary artifact."""

    temporary = path.with_name(path.name + ".horizon-tmp")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_stfs_mutation(data: bytes) -> None:
    """Reject STFS bytes whose authenticated hash tree is inconsistent."""

    if data[:4] not in STFS_MAGICS:
        raise ValueError("expected CON, LIVE, or PIRS STFS bytes")
    candidate_header = parse_stfs_header(data)
    integrity = verify_stfs_hashes(data, header=candidate_header)
    if integrity["failures"]:
        raise ValueError(
            "STFS mutation has hash failures: "
            + "; ".join(json.dumps(item, sort_keys=True) for item in integrity["failures"])
        )


def profile_data_report(path: Path) -> dict[str, object]:
    """Inspect an explicit REA-authenticated ProfileData JSON envelope."""

    from .editors import EditorContext, ProfileDataEditor

    data = path.read_bytes()
    editor = ProfileDataEditor()
    if not editor.can_edit(EditorContext(filename=path.name), data):
        raise ValueError("input is not a valid profile-data envelope")
    return editor.inspect(EditorContext(filename=path.name), data)


def historical_account_report(container_path: Path, key: bytes) -> dict[str, object]:
    """Decode one Account entry with the explicit historical body codec.

    This path is intentionally separate from the class3 provider bridge: the
    codec is historical-reference evidence, while native Horizon crypto and
    console signing remain provider-boundary behavior.
    """

    from .account_format import AccountRecord, unobfuscate_account

    data = container_path.read_bytes()
    header = parse_stfs_header(data)
    entry = next((item for item in list_stfs_entries(data, header) if item.path == "Account"), None)
    if entry is None or entry.is_directory:
        raise ValueError("STFS Account entry was not found")
    encrypted = read_stfs_entry(data, entry, header)
    plaintext = unobfuscate_account(encrypted, key)
    record = AccountRecord.from_bytes(plaintext)
    return {
        "operation": "historical-account-inspect",
        "entry": entry.path,
        "encrypted_bytes": len(encrypted),
        "plaintext_bytes": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "record": {
            "live_flags": record.live_flags,
            "reserved": record.reserved,
            "gamertag": record.gamertag,
            "xuid_online": record.xuid_online,
            "cached_user_flags": record.cached_user_flags,
            "online_service_network_id": record.online_service_network_id,
            "recovering": record.recovering,
            "xbox_live_enabled": record.xbox_live_enabled,
            "password_protected": record.password_protected,
            "membership_type": record.membership_type,
            "membership_name": record.membership_name,
            "online_country_code": record.online_country_code,
            "online_country_name": record.online_country_name,
            "online_language_code": record.online_language_code,
            "online_language_name": record.online_language_name,
            "passcode_hex": record.passcode.hex(),
            "online_domain": record.online_domain,
            "online_kerberos_realm": record.online_kerberos_realm,
            "online_key_hex": record.online_key.hex(),
            "user_passport_membername": record.user_passport_membername,
            "user_passport_password": record.user_passport_password,
            "owner_passport_membername": record.owner_passport_membername,
        },
    }


def mutate_historical_account(container: bytes, key: bytes, updates: dict[str, object]) -> bytes:
    """Apply explicit Account body field updates and rebuild STFS hashes.

    This is a historical-reference mutation path. It deliberately does not
    claim Horizon's native save crypto, package signing, or console validity.
    """

    from .account_format import AccountRecord, obfuscate_account, unobfuscate_account

    header = parse_stfs_header(container)
    entry = next((item for item in list_stfs_entries(container, header) if item.path == "Account"), None)
    if entry is None or entry.is_directory:
        raise ValueError("STFS Account entry was not found")
    encrypted = read_stfs_entry(container, entry, header)
    record = AccountRecord.from_bytes(unobfuscate_account(encrypted, key))
    dataclass_fields = set(record.__dataclass_fields__)
    allowed = dataclass_fields | {
        "recovering", "xbox_live_enabled", "password_protected",
        "membership_type", "online_country_code", "online_language_code",
    }
    values = {name: getattr(record, name) for name in dataclass_fields}
    for name, value in updates.items():
        if name == "passcode_hex":
            name, value = "passcode", bytes.fromhex(str(value))
        elif name == "online_key_hex":
            name, value = "online_key", bytes.fromhex(str(value))
        if name not in allowed:
            raise ValueError(f"unsupported Account field: {name}")
        if name not in record.__dataclass_fields__:
            setattr(record, name, value)
        else:
            values[name] = value
    values["reserved"] = record.reserved
    values["cached_user_flags"] = record.cached_user_flags
    edited = AccountRecord(**values).to_bytes()
    replacement = obfuscate_account(edited, key)
    if len(replacement) != entry.size:
        raise ValueError("historical Account codec changed the entry size")
    return repack_stfs_entries(container, {entry.path: replacement}, header)


def decrypt_account_entry(
    container_path: Path,
    output_path: Path,
    class3_path: Path,
    key_helper_path: Path,
    output_capacity: int,
) -> dict[str, object]:
    """Decrypt the STFS ``Account`` entry through explicit caller providers."""

    from .account_codec import AccountCodec, CommandAccountKeyProvider
    from .native_save import NativeSaveBinding, PowerShellNativeSaveProvider

    data = container_path.read_bytes()
    header = parse_stfs_header(data)
    entry = next((item for item in list_stfs_entries(data, header) if item.path == "Account"), None)
    if entry is None or entry.is_directory:
        raise ValueError("STFS Account entry was not found")
    payload = read_stfs_entry(data, entry, header)
    provider = PowerShellNativeSaveProvider(class3_path)
    codec = AccountCodec(NativeSaveBinding(provider))
    key_provider = CommandAccountKeyProvider(key_helper_path)
    plaintext = codec.decrypt_with_key_provider(payload, key_provider, output_capacity)
    _atomic_replace_bytes(output_path, plaintext)
    return {
        "operation": "account-decrypt",
        "entry": entry.path,
        "input_bytes": len(payload),
        "output": str(output_path),
        "output_bytes": len(plaintext),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def encrypt_account_payload(
    plaintext_path: Path,
    output_path: Path,
    class3_path: Path,
    key_helper_path: Path,
    output_capacity: int,
    output_length: int,
) -> dict[str, object]:
    """Encrypt raw Account plaintext through explicit caller providers."""

    from .account_codec import AccountCodec, CommandAccountKeyProvider
    from .native_save import NativeSaveBinding, PowerShellNativeSaveProvider

    plaintext = plaintext_path.read_bytes()
    provider = PowerShellNativeSaveProvider(class3_path)
    codec = AccountCodec(NativeSaveBinding(provider))
    key_provider = CommandAccountKeyProvider(key_helper_path)
    encrypted = codec.encrypt_with_key_provider(plaintext, key_provider, output_capacity, output_length)
    _atomic_replace_bytes(output_path, encrypted)
    return {
        "operation": "account-encrypt",
        "input": str(plaintext_path),
        "input_bytes": len(plaintext),
        "output": str(output_path),
        "output_bytes": len(encrypted),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    }


def encrypt_account_in_container(
    container: bytes,
    plaintext: bytes,
    class3_path: Path,
    key_helper_path: Path,
    output_capacity: int,
    output_length: int,
) -> bytes:
    """Encrypt Account plaintext and replace the matching STFS entry."""

    from .account_codec import AccountCodec, CommandAccountKeyProvider
    from .native_save import NativeSaveBinding, PowerShellNativeSaveProvider

    header = parse_stfs_header(container)
    entry = next((item for item in list_stfs_entries(container, header) if item.path == "Account"), None)
    if entry is None or entry.is_directory:
        raise ValueError("STFS Account entry was not found")
    codec = AccountCodec(NativeSaveBinding(PowerShellNativeSaveProvider(class3_path)))
    encrypted = codec.encrypt_with_key_provider(
        plaintext,
        CommandAccountKeyProvider(key_helper_path),
        output_capacity,
        output_length,
    )
    return repack_stfs_entries(container, {entry.path: encrypted}, header)


def editor_inspect_report(path: Path) -> dict[str, object]:
    """Dispatch one explicit input through the clean-room editor registry."""

    from .editors import EditorContext, default_registry

    data = path.read_bytes()
    context = EditorContext(filename=path.name)
    plugin = default_registry().resolve(context, data)
    if plugin is None:
        raise ValueError(f"no registered editor accepts {path.name}")
    inspected = plugin.inspect(context, data)
    if isinstance(inspected, tuple):
        inspected = [asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in inspected]
    return {"editor": plugin.name, "path": str(path), "result": inspected}


def editor_edit_values(path: Path, values_path: Path) -> tuple[str, bytes]:
    """Apply a plugin-declared metadata edit and return the new bytes."""

    from .editors import EditorContext, default_registry

    data = path.read_bytes()
    try:
        values = json.loads(values_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"editor values must be UTF-8 JSON: {values_path}") from exc
    if not isinstance(values, dict):
        raise ValueError("editor values JSON must be an object")
    context = EditorContext(filename=path.name)
    plugin = default_registry().resolve(context, data)
    if plugin is None:
        raise ValueError(f"no registered editor accepts {path.name}")
    edit = getattr(plugin, "edit_values", None)
    if not callable(edit):
        raise ValueError(f"editor {plugin.name} does not declare metadata value editing")
    edited = edit(data, values)
    if not isinstance(edited, bytes):
        raise TypeError(f"editor {plugin.name} returned non-byte output")
    return plugin.name, edited


def verify_detached_signature(
    region_path: Path,
    signature_path: Path,
    label: str,
    algorithm: str,
    modulus: int,
    exponent: int = 65537,
) -> bool:
    """Verify a caller-labeled development signature without package inference."""

    from .signing import DetachedSignature, RsaPublicKey, SignedRegion, verify_region

    if not label.strip():
        raise ValueError("signature region label cannot be empty")
    if not isinstance(modulus, int) or isinstance(modulus, bool) or modulus <= 0:
        raise ValueError("public-key modulus must be a positive integer")
    return verify_region(
        SignedRegion(label, region_path.read_bytes()),
        DetachedSignature(label, algorithm, signature_path.read_bytes()),
        RsaPublicKey(modulus, exponent),
    )


def verify_embedded_signature_region(
    data: bytes,
    *,
    signed_start: int,
    signed_end: int,
    signature_offset: int,
    modulus: int,
    exponent: int = 65537,
    algorithm: str = "RSA-SHA256-PKCS1v1.5",
) -> bool:
    """Verify an explicitly selected in-container RSA signature region.

    Offsets are caller-supplied because the clean-room evidence does not
    establish Horizon/Xbox's package signed-region layout.  No offsets are
    inferred and no bytes are modified.
    """

    from .signing import verify_sha1_pkcs1v15, verify_sha256_pkcs1v15, verify_xecrypt_sha1_pkcs1v15

    if not isinstance(data, bytes):
        raise TypeError("container data must be bytes")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (signed_start, signed_end, signature_offset)):
        raise ValueError("signature offsets must be integers")
    if not 0 <= signed_start < signed_end <= len(data):
        raise ValueError("signed region is outside the container")
    if not 0 <= signature_offset < len(data):
        raise ValueError("signature offset is outside the container")
    if not isinstance(modulus, int) or isinstance(modulus, bool) or modulus <= 0:
        raise ValueError("public-key modulus must be a positive integer")
    signature_length = (modulus.bit_length() + 7) // 8
    signature_end = signature_offset + signature_length
    if signature_end > len(data):
        raise ValueError("embedded signature exceeds the container")
    if max(signed_start, signature_offset) < min(signed_end, signature_end):
        raise ValueError("signed region overlaps embedded signature")
    region = data[signed_start:signed_end]
    signature = data[signature_offset:signature_end]
    if algorithm == "RSA-SHA256-PKCS1v1.5":
        return verify_sha256_pkcs1v15(region, signature, RsaPublicKey(modulus, exponent))
    if algorithm == "RSA-SHA1-PKCS1v1.5":
        return verify_sha1_pkcs1v15(region, signature, RsaPublicKey(modulus, exponent))
    if algorithm == "RSA-SHA1-XeCrypt-PKCS1v1.5":
        return verify_xecrypt_sha1_pkcs1v15(region, signature, RsaPublicKey(modulus, exponent))
    raise ValueError(f"unsupported signature algorithm: {algorithm}")


def read_public_key_json(path: Path) -> tuple[int, int]:
    """Read the public-key JSON emitted by ``--public-key``."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"public-key JSON is not readable: {path}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("modulus_hex"), str):
        raise ValueError("public-key JSON must contain modulus_hex")
    try:
        modulus = int(value["modulus_hex"], 16)
    except ValueError as exc:
        raise ValueError("public-key modulus_hex is not hexadecimal") from exc
    exponent = value.get("exponent", 65537)
    if not isinstance(exponent, int) or isinstance(exponent, bool):
        raise ValueError("public-key exponent must be an integer")
    return modulus, exponent


def read_private_key_json(path: Path):
    """Read an explicitly supplied development RSA private key.

    The file is caller-owned and is never copied into reports or committed by
    this tool.  It is intentionally separate from the public-key JSON emitted
    for CON metadata.
    """

    from .signing import RsaPrivateKey

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"private-key JSON is not readable: {path}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("modulus_hex"), str) or not isinstance(value.get("private_exponent_hex"), str):
        raise ValueError("private-key JSON must contain modulus_hex and private_exponent_hex")
    try:
        modulus = int(value["modulus_hex"], 16)
        private_exponent = int(value["private_exponent_hex"], 16)
    except ValueError as exc:
        raise ValueError("private-key modulus_hex and private_exponent_hex must be hexadecimal") from exc
    if modulus <= 0 or private_exponent <= 0:
        raise ValueError("private-key values must be positive")
    return RsaPrivateKey(modulus, private_exponent)


def sign_detached_signature(region_path: Path, signature_path: Path, label: str, private_key_path: Path) -> dict[str, object]:
    """Sign caller-labeled bytes with an explicit development RSA key."""

    from .signing import SignedRegion, LocalRsaSha256Signer, sign_region

    if not label.strip():
        raise ValueError("signature region label cannot be empty")
    if region_path.resolve() == signature_path.resolve():
        raise ValueError("signature output must be different from the signed input")
    return sign_detached_bytes(region_path.read_bytes(), signature_path, label, private_key_path)


def sign_detached_bytes(data: bytes, signature_path: Path, label: str, private_key_path: Path) -> dict[str, object]:
    """Sign already-loaded bytes without creating an intermediate input file."""

    from .signing import SignedRegion, LocalRsaSha256Signer, sign_region

    if not isinstance(data, bytes):
        raise TypeError("signed data must be bytes")
    key = read_private_key_json(private_key_path)
    detached = sign_region(SignedRegion(label, data), LocalRsaSha256Signer(key))
    _atomic_replace_bytes(signature_path, detached.signature)
    return {"algorithm": detached.algorithm, "region_label": detached.region_label, "signature": str(signature_path), "bytes": len(detached.signature)}


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


_STFS_CONTENT_TYPE_NAMES = {
    0x00000001: "SavedGame",
    0x00000002: "Marketplace",
    0x00000003: "Publisher",
    0x00004000: "InstalledXbox360Title",
    0x00005000: "XboxTitle",
    0x00007000: "Xbox360Title",
    0x00009000: "AvatarAsset",
    0x00010000: "Profile",
    0x00020000: "GamerPicture",
    0x00030000: "ThematicSkin",
    0x00040000: "Cache",
    0x00060000: "XboxSavedGame",
    0x00070000: "XboxDownload",
    0x00080000: "GameDemo",
    0x00090000: "Video",
    0x000A0000: "GameTitle",
    0x000B0000: "Installer",
    0x000C0000: "GameTrailer",
    0x000D0000: "Arcade",
    0x000E0000: "XNA",
}


def stfs_content_type_name(content_type: int) -> str:
    """Return the authenticated XContent type label or ``Unknown``."""

    if not isinstance(content_type, int) or isinstance(content_type, bool) or content_type < 0:
        raise ValueError("content type must be a non-negative integer")
    return _STFS_CONTENT_TYPE_NAMES.get(content_type, "Unknown")


def stfs_magic_filename(header: StfsHeader, filename: str | None = None) -> str:
    """Return the canonical FATX-facing filename for an observed package.

    Profile packages are authenticated by the supplied fixture and the public
    XContent reference: their filename is the uppercase profile identifier.
    Other content types retain the caller's filename because their naming
    rules are not established by the current REA evidence.
    """

    if header.content_type == 0x00010000 and header.profile_id:
        return header.profile_id.upper()
    if filename:
        return filename
    raise ValueError("a filename is required for this unclassified content type")


def stfs_fatx_device_path(header: StfsHeader, filename: str | None = None) -> str:
    """Build the canonical ``Content\\profile\\title\\type\\file`` path."""

    return "Content\\{0}\\{1:08X}\\{2:08X}\\{3}".format(
        header.profile_id.upper(),
        header.title_id,
        header.content_type,
        stfs_magic_filename(header, filename),
    )


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
    certificate_signature_offset: int | None
    certificate_signature_length: int | None
    package_signature_offset: int
    package_signature_length: int
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


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_utc(value: int) -> str:
    """Convert an observed Windows FILETIME integer to canonical UTC ISO-8601."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("FILETIME must be a non-negative integer")
    seconds, remainder = divmod(value, 10_000_000)
    moment = _FILETIME_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 10)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def utc_to_filetime(value: str) -> int:
    """Convert a timezone-aware ISO-8601 UTC value to Windows FILETIME units."""

    if not isinstance(value, str):
        raise TypeError("UTC timestamp must be a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("UTC timestamp must be ISO-8601") from exc
    if moment.tzinfo is None:
        raise ValueError("UTC timestamp must include a timezone")
    delta = moment.astimezone(timezone.utc) - _FILETIME_EPOCH
    result = delta.days * 86400 * 10_000_000 + delta.seconds * 10_000_000 + delta.microseconds * 10
    if result < 0:
        raise ValueError("UTC timestamp predates the FILETIME epoch")
    return result


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
        elif namespace == 1 and entry_id <= 0xFFFFFFFF and len(payload) >= 0x1C:
            name_start = 0x1C
            name_end = payload.find(b"\x00\x00", name_start)
            if name_end >= 0 and (name_end - name_start) % 2:
                name_end += 1
            name = payload[name_start:name_end if name_end >= 0 else len(payload)].decode("utf-16-be", errors="replace").rstrip("\x00")
            achievement = {
                "achievement_id": int.from_bytes(payload[4:8], "big"),
                "image_id": int.from_bytes(payload[8:12], "big"),
                "gamerscore": int.from_bytes(payload[12:16], "big", signed=True),
                "flags": int.from_bytes(payload[16:18], "big"),
                "unlock_time_filetime": int.from_bytes(payload[20:28], "big"),
                "unlock_time_utc": filetime_to_utc(int.from_bytes(payload[20:28], "big")) if any(payload[20:28]) else None,
                "name": name,
            }
        result.append(XdbfEntry(index, namespace, entry_id, offset, length, start, text, achievement))
    return tuple(result)


def xdbf_payload_surface(data: bytes) -> tuple[dict[str, object], ...]:
    """Describe every XDBF payload with conservative magic metadata.

    REA/fixture evidence shows namespace-2 payloads carrying PNG images.  The
    metadata is format-level only; it does not assign title-specific meaning.
    """

    entries = parse_xdbf(data)
    result = []
    for entry in entries:
        payload = data[entry.data_offset : entry.data_offset + entry.length]
        metadata = resource_payload_metadata(payload)
        result.append({
            "index": entry.index,
            "namespace": entry.namespace,
            "entry_id": entry.entry_id,
            "offset": entry.data_offset,
            "length": entry.length,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "kind": "achievement" if entry.achievement is not None else "text" if entry.text is not None else "opaque",
            "metadata": metadata,
        })
    return tuple(result)


def xdbf_achievement_image_links(data: bytes) -> tuple[dict[str, object], ...]:
    """Link observed achievement ``image_id`` values to same-file PNG entries.

    The relationship is emitted only when the referenced namespace-2 entry is
    present in the same XDBF.  Missing references remain explicit rather than
    being matched by position or by a guessed cross-title catalog.
    """

    entries = parse_xdbf(data)
    images = {
        entry.entry_id: entry
        for entry in entries
        if entry.namespace == 2
        and resource_payload_metadata(data[entry.data_offset : entry.data_offset + entry.length]).get("kind") == "png"
    }
    links: list[dict[str, object]] = []
    for achievement in entries:
        if achievement.achievement is None:
            continue
        image_id = achievement.achievement["image_id"]
        image = images.get(image_id)
        item: dict[str, object] = {
            "achievement_entry_index": achievement.index,
            "achievement_id": achievement.achievement["achievement_id"],
            "image_id": image_id,
            "status": "linked" if image is not None else "missing",
        }
        if image is not None:
            payload = data[image.data_offset : image.data_offset + image.length]
            item.update({
                "image_entry_index": image.index,
                "image_offset": image.data_offset,
                "image_length": image.length,
                "image_sha256": hashlib.sha256(payload).hexdigest(),
                "image_metadata": resource_payload_metadata(payload),
            })
        links.append(item)
    return tuple(links)


def xdbf_achievement_image_payload(data: bytes, achievement_entry_index: int) -> bytes:
    """Return the exact same-file PNG referenced by an achievement entry."""

    entries = parse_xdbf(data)
    try:
        achievement = next(item for item in entries if item.index == achievement_entry_index)
    except StopIteration as exc:
        raise IndexError(f"unknown XDBF achievement entry index: {achievement_entry_index}") from exc
    if achievement.achievement is None:
        raise ValueError("XDBF entry is not an observed achievement payload")
    image_id = achievement.achievement["image_id"]
    for image in entries:
        if image.namespace != 2 or image.entry_id != image_id:
            continue
        payload = data[image.data_offset : image.data_offset + image.length]
        if resource_payload_metadata(payload).get("kind") != "png":
            raise ValueError(f"XDBF image entry {image.index} is not a PNG payload")
        return payload
    raise LookupError(f"achievement image_id {image_id} is missing from this XDBF")


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
    unlock_time_filetime: int | None = None,
    unlock_time_utc: str | None = None,
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
        payload[4:8] = achievement_id.to_bytes(4, "big", signed=False)
    if image_id is not None:
        payload[8:12] = image_id.to_bytes(4, "big", signed=False)
    if gamerscore is not None:
        payload[12:16] = gamerscore.to_bytes(4, "big", signed=True)
    if flags is not None:
        payload[16:18] = flags.to_bytes(2, "big", signed=False)
    if unlock_time_filetime is not None and unlock_time_utc is not None:
        raise ValueError("provide either unlock_time_filetime or unlock_time_utc, not both")
    if unlock_time_utc is not None:
        unlock_time_filetime = utc_to_filetime(unlock_time_utc)
    if unlock_time_filetime is not None:
        payload[20:28] = unlock_time_filetime.to_bytes(8, "big", signed=False)
    if name is not None:
        encoded = name.encode("utf-16-be")
        name_start = 0x1C
        name_end = payload.find(b"\x00\x00", name_start)
        if name_end >= 0 and (name_end - name_start) % 2:
            name_end += 1
        if name_end < 0:
            name_end = len(payload)
        capacity = name_end - name_start
        if len(encoded) > capacity:
            raise ValueError("achievement name does not fit the existing XDBF payload")
        payload[name_start:name_end] = encoded.ljust(capacity, b"\x00")
    return mutate_xdbf_entry_same_size(data, entry, bytes(payload))


def mutate_xdbf_achievement_flags(
    data: bytes,
    mask: int,
    *,
    mode: str = "or",
) -> bytes:
    """Apply an explicit raw flags mask to every observed achievement entry.

    The mask is deliberately exposed as a raw operation: REA authenticates
    the two-byte flags field, but does not establish the meaning of its bits.
    ``mode='or'`` sets selected bits and ``mode='and-not'`` clears them.
    """

    if not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask <= 0xFFFF:
        raise ValueError("achievement flags mask must be a 16-bit integer")
    if mode not in {"or", "and-not"}:
        raise ValueError("achievement flags mode must be 'or' or 'and-not'")
    entries = parse_xdbf(data)
    selected = [entry for entry in entries if entry.achievement is not None]
    if not selected:
        raise ValueError("XDBF contains no observed achievement payloads")
    result = data
    for entry in selected:
        current = int(entry.achievement["flags"])
        flags = current | mask if mode == "or" else current & ~mask
        result = mutate_xdbf_achievement(result, entry.index, flags=flags)
    return result


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
            certificate_signature_offset=0xAC,
            certificate_signature_length=0x100,
            package_signature_offset=0x1AC,
            package_signature_length=0x80,
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
        certificate_signature_offset=None,
        certificate_signature_length=None,
        package_signature_offset=0x04,
        package_signature_length=0x100,
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


def stfs_signature_region_report(data: bytes) -> dict[str, object]:
    """Describe stored STFS signature ranges without verifying them."""

    metadata = parse_stfs_security_metadata(data)
    regions: list[dict[str, object]] = []
    if metadata.certificate_signature_offset is not None and metadata.certificate_signature_length is not None:
        offset = metadata.certificate_signature_offset
        length = metadata.certificate_signature_length
        regions.append({
            "name": "certificate-signature",
            "offset": offset,
            "length": length,
            "sha256": hashlib.sha256(data[offset:offset + length]).hexdigest(),
        })
    offset = metadata.package_signature_offset
    length = metadata.package_signature_length
    regions.append({
        "name": "package-signature",
        "offset": offset,
        "length": length,
        "sha256": hashlib.sha256(data[offset:offset + length]).hexdigest(),
    })
    key = extract_stfs_public_key(data) if metadata.signature_kind == "console-certificate" else None
    return {
        "status": "metadata-only",
        "signature_kind": metadata.signature_kind,
        "regions": regions,
        "public_key": ({"modulus_bits": key.modulus.bit_length(), "exponent": key.exponent} if key else None),
        "limitations": [
            "The report identifies stored signature bytes only; it does not infer the signed-region digest input.",
            "Console-valid signing still requires an authorized compatible signing provider.",
        ],
    }


def verify_stfs_console_signature(data: bytes) -> dict[str, object]:
    """Verify the observed CON package-signature layout without modifying it.

    The package signature is stored at ``0x1AC`` and covers the 0x118 bytes
    beginning at ``0x22C``. XeCrypt stores the RSA signature byte-reversed;
    the layout and encoding are retained as historical-reference evidence.
    """

    metadata = parse_stfs_security_metadata(data)
    if metadata.signature_kind != "console-certificate":
        raise ValueError("STFS console-signature verification requires a CON container")
    key = extract_stfs_public_key(data)
    signature_offset = metadata.package_signature_offset
    signature_length = metadata.package_signature_length
    signed_start = signature_offset + signature_length
    signed_end = signed_start + 0x118
    if signed_end > len(data):
        raise ValueError("CON package signed region exceeds the container")
    signature = data[signature_offset:signature_offset + signature_length]
    signed_bytes = data[signed_start:signed_end]
    verified = verify_xecrypt_sha1_pkcs1v15(signed_bytes, signature, key)
    return {
        "status": "historical-reference-verification",
        "verified": verified,
        "algorithm": "RSA-SHA1-XeCrypt-PKCS1v1.5",
        "signature_offset": signature_offset,
        "signature_length": signature_length,
        "signed_start": signed_start,
        "signed_end": signed_end,
        "public_key": {"modulus_bits": key.modulus.bit_length(), "exponent": key.exponent},
        "limitations": [
            "This verifies the observed package-signature encoding and range only.",
            "A valid package signature does not establish every console policy or key authority.",
        ],
    }


def sign_stfs_console_package(data: bytes, private_key) -> bytes:
    """Sign the observed CON package region with an explicit caller key.

    The certificate's public modulus must match the supplied private key. The
    result only updates the stored package-signature bytes; it does not alter
    certificates, licenses, or file payloads, and it does not claim retail
    console authority.
    """

    from .signing import LocalRsaSha1Signer, RsaPrivateKey

    if not isinstance(data, bytes):
        raise TypeError("STFS package data must be bytes")
    if not isinstance(private_key, RsaPrivateKey):
        raise TypeError("private_key must be an RsaPrivateKey")
    metadata = parse_stfs_security_metadata(data)
    if metadata.signature_kind != "console-certificate":
        raise ValueError("CON package signing requires a CON container")
    key = extract_stfs_public_key(data)
    if private_key.modulus != key.modulus:
        raise ValueError("private-key modulus does not match the CON certificate modulus")
    signature_offset = metadata.package_signature_offset
    signature_length = metadata.package_signature_length
    signed_start = signature_offset + signature_length
    signed_end = signed_start + 0x118
    if signed_end > len(data):
        raise ValueError("CON package signed region exceeds the container")
    signature = LocalRsaSha1Signer(private_key).sign_sha1(data[signed_start:signed_end])[::-1]
    if len(signature) != signature_length:
        raise ValueError("private-key signature length does not match the CON package signature slot")
    result = bytearray(data)
    result[signature_offset:signature_offset + signature_length] = signature
    return bytes(result)


def stfs_signature_mutation_report(original: bytes, mutated: bytes) -> dict[str, object]:
    """Compare two STFS images without claiming console-signature validity.

    This is intentionally an integrity audit, not a verifier. It identifies
    whether the stored signature bytes were preserved and whether any other
    bytes changed, leaving the signed-region algorithm and signing authority
    explicit.
    """

    original_metadata = parse_stfs_security_metadata(original)
    mutated_metadata = parse_stfs_security_metadata(mutated)
    if original_metadata.signature_kind != mutated_metadata.signature_kind:
        raise ValueError("signature comparison requires matching STFS signature kinds")
    original_regions = stfs_signature_region_report(original)["regions"]
    mutated_regions = stfs_signature_region_report(mutated)["regions"]
    signature_bytes_unchanged = original_regions == mutated_regions
    region_ranges = [
        (int(item["offset"]), int(item["offset"]) + int(item["length"]))
        for item in original_regions
    ]
    changed_total = 0
    changed_outside_signature = 0
    for offset, (before, after) in enumerate(zip(original, mutated)):
        if before == after:
            continue
        changed_total += 1
        if not any(start <= offset < end for start, end in region_ranges):
            changed_outside_signature += 1
    if len(original) != len(mutated):
        changed_total += abs(len(original) - len(mutated))
        changed_outside_signature += abs(len(original) - len(mutated))
    hash_report = verify_stfs_hashes(mutated)
    return {
        "status": "metadata-only",
        "same_length": len(original) == len(mutated),
        "changed_bytes": changed_total,
        "changed_outside_signature_regions": changed_outside_signature,
        "stored_signature_bytes_unchanged": signature_bytes_unchanged,
        "hash_tree": {
            "checked_blocks": hash_report["checked_blocks"],
            "failures": hash_report["failures"],
            "hash_table_failures": hash_report["hash_table_failures"],
            "verified": not hash_report["failures"] and not hash_report["hash_table_failures"],
        },
        "original_regions": original_regions,
        "mutated_regions": mutated_regions,
        "console_validity_checked": False,
        "limitations": [
            "The signed-region digest input and signature encoding remain unresolved.",
            "Unchanged stored signature bytes do not prove that a mutation is console-valid.",
            "Console-valid signing requires an authorized compatible signing provider.",
        ],
    }


def extract_stfs_public_key(data: bytes) -> RsaPublicKey:
    """Extract the public CON certificate key without checking a signature."""

    header = parse_stfs_header(data)
    if header.magic != "CON ":
        raise ValueError("public certificate key extraction requires a CON container")
    exponent = int.from_bytes(data[0x28:0x2C], "big")
    modulus_bytes = data[0x2C:0xAC]
    if len(modulus_bytes) != 0x80 or exponent <= 1:
        raise ValueError("CON certificate does not contain a complete public key")
    modulus = int.from_bytes(modulus_bytes, "big")
    if modulus <= 0:
        raise ValueError("CON certificate contains an empty public modulus")
    return RsaPublicKey(modulus=modulus, exponent=exponent)


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
    """Enumerate parseable XDBF payloads embedded in STFS GPD/FIT files."""
    header = header or parse_stfs_header(data)
    result: list[tuple[StfsEntry, tuple[XdbfEntry, ...]]] = []
    for entry in list_stfs_entries(data, header):
        if entry.is_directory or Path(entry.path).suffix.lower() not in {".gpd", ".fit"}:
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


def list_embedded_achievement_image_links(
    data: bytes, header: StfsHeader | None = None
) -> tuple[dict[str, object], ...]:
    """Return image links for every parseable embedded GPD/FIT payload."""

    records: list[dict[str, object]] = []
    for file_entry, _xdbf_entries in list_embedded_xdbf(data, header):
        payload = read_stfs_entry(data, file_entry, header)
        for link in xdbf_achievement_image_links(payload):
            records.append({"file": file_entry.path, **link})
    return tuple(records)


def extract_embedded_achievement_images(
    data: bytes, output_dir: str | Path, header: StfsHeader | None = None
) -> dict[str, object]:
    """Extract unique linked achievement PNGs with deterministic filenames."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    written_by_hash: dict[str, Path] = {}
    for file_entry, _xdbf_entries in list_embedded_xdbf(data, header):
        payload = read_stfs_entry(data, file_entry, header)
        for link in xdbf_achievement_image_links(payload):
            if link["status"] != "linked":
                continue
            image = xdbf_achievement_image_payload(payload, int(link["achievement_entry_index"]))
            digest = hashlib.sha256(image).hexdigest()
            output_path = written_by_hash.get(digest)
            if output_path is None:
                safe_file = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(file_entry.path).stem).strip("._") or "gpd"
                output_path = destination / f"{safe_file}-{int(link['image_id']):016X}-{digest[:16]}.png"
                _atomic_replace_bytes(output_path, image)
                written_by_hash[digest] = output_path
            records.append({
                "file": file_entry.path,
                "achievement_entry_index": link["achievement_entry_index"],
                "achievement_id": link["achievement_id"],
                "image_id": link["image_id"],
                "sha256": digest,
                "output": str(output_path),
            })
    return {
        "output_dir": str(destination),
        "linked_references": len(records),
        "unique_images": len(written_by_hash),
        "images": records,
    }


def mutate_profile_achievement_flags(
    data: bytes,
    mask: int,
    *,
    mode: str = "or",
) -> bytes:
    """Apply an explicit raw achievement-flags mask across embedded GPDs."""

    header = parse_stfs_header(data)
    result = data
    changed = False
    for file_entry, xdbf_entries in list_embedded_xdbf(result, header):
        if Path(file_entry.path).suffix.lower() != ".gpd":
            continue
        if not any(item.achievement is not None for item in xdbf_entries):
            continue
        payload = read_stfs_entry(result, file_entry, header)
        edited = mutate_xdbf_achievement_flags(payload, mask, mode=mode)
        result = mutate_stfs_entry_same_size(result, file_entry, edited, header)
        changed = True
    if not changed:
        raise ValueError("STFS contains no embedded GPD achievement payloads")
    return result


def mutate_profile_xdbf_text(
    data: bytes,
    old_text: str,
    new_text: str,
) -> bytes:
    """Replace every exact observed namespace-5 text match in embedded XDBFs."""

    if not isinstance(old_text, str) or not old_text:
        raise ValueError("profile XDBF search text must be a non-empty string")
    if not isinstance(new_text, str):
        raise TypeError("profile XDBF replacement text must be a string")
    header = parse_stfs_header(data)
    result = data
    changed = False
    for file_entry, xdbf_entries in list_embedded_xdbf(result, header):
        matching = [entry for entry in xdbf_entries if entry.namespace == 5 and entry.text == old_text]
        if not matching:
            continue
        payload = read_stfs_entry(result, file_entry, header)
        edited = payload
        for entry in matching:
            edited = mutate_xdbf_text(edited, entry.index, new_text)
        result = mutate_stfs_entry_same_size(result, file_entry, edited, header)
        changed = True
    if not changed:
        raise ValueError(f"no embedded namespace-5 XDBF text matched {old_text!r}")
    return result


def summarize_profile_achievements(
    data: bytes, header: StfsHeader | None = None
) -> dict[str, object]:
    """Aggregate observed achievement fields across embedded GPDs."""

    per_file: list[dict[str, object]] = []
    total_entries = total_gamerscore = nonzero_flags = 0
    unlock_times: list[int] = []
    for file_entry, xdbf_entries in list_embedded_xdbf(data, header):
        achievements = [item.achievement for item in xdbf_entries if item.achievement is not None]
        file_score = sum(int(item.get("gamerscore", 0)) for item in achievements)
        file_flags = sum(bool(item.get("flags", 0)) for item in achievements)
        unlock_times.extend(
            int(item["unlock_time_filetime"])
            for item in achievements
            if item.get("unlock_time_filetime")
        )
        per_file.append({
            "file": file_entry.path,
            "achievement_count": len(achievements),
            "gamerscore_total": file_score,
            "nonzero_flags_count": file_flags,
        })
        total_entries += len(achievements)
        total_gamerscore += file_score
        nonzero_flags += file_flags
    gpd_count = sum(Path(item["file"]).suffix.lower() == ".gpd" for item in per_file)
    fit_count = sum(Path(item["file"]).suffix.lower() == ".fit" for item in per_file)
    earliest_unlock = min(unlock_times) if unlock_times else None
    latest_unlock = max(unlock_times) if unlock_times else None
    return {
        "gpd_count": gpd_count,
        "fit_count": fit_count,
        "xdbf_count": len(per_file),
        "achievement_entry_count": total_entries,
        "gamerscore_total": total_gamerscore,
        "nonzero_flags_count": nonzero_flags,
        "unlock_time_count": len(unlock_times),
        "earliest_unlock_time_filetime": earliest_unlock,
        "earliest_unlock_time_utc": filetime_to_utc(earliest_unlock) if earliest_unlock is not None else None,
        "latest_unlock_time_filetime": latest_unlock,
        "latest_unlock_time_utc": filetime_to_utc(latest_unlock) if latest_unlock is not None else None,
        "flag_semantics": "raw nonzero flag count; bit meanings are not inferred",
        "by_gpd": per_file,
    }


def summarize_embedded_xdbf(
    data: bytes, header: StfsHeader | None = None
) -> tuple[dict[str, object], ...]:
    """Summarize every parseable embedded GPD without interpreting game data."""

    summaries: list[dict[str, object]] = []
    for file_entry, xdbf_entries in list_embedded_xdbf(data, header):
        namespaces = Counter(item.namespace for item in xdbf_entries)
        summaries.append(
            {
                "file": file_entry.path,
                "entry_count": len(xdbf_entries),
                "namespace_counts": dict(sorted(namespaces.items())),
                "text_count": sum(item.text is not None for item in xdbf_entries),
                "achievement_count": sum(item.achievement is not None for item in xdbf_entries),
            }
        )
    return tuple(summaries)


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

    if not removals and not additions and replacements and all(
        len(payload) == by_path[path].size for path, payload in replacements.items()
    ):
        result = data
        for path, payload in replacements.items():
            current_header = parse_stfs_header(result)
            current_entry = next(item for item in list_stfs_entries(result, current_header) if item.path == path)
            result = mutate_stfs_entry_same_size(result, current_entry, payload, current_header)
        return result

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

    candidate = rehash_stfs_hashes(bytes(result), header)
    candidate_header = parse_stfs_header(candidate)
    for path, payload in {**replacements, **additions}.items():
        candidate_entry = next((item for item in list_stfs_entries(candidate, candidate_header) if item.path == path), None)
        if candidate_entry is None or read_stfs_entry(candidate, candidate_entry, candidate_header) != payload:
            raise ValueError(
                "repack allocation layout could not be authenticated for "
                f"{path!r}; use a same-size replacement or provide a supported STFS allocation layout"
            )
    return candidate


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


def device_ioctl_report(
    device_path: str,
    control_code: int,
    input_data: bytes = b"",
    output_capacity: int = 0,
    *,
    provider=None,
) -> dict[str, object]:
    """Forward one caller-selected IOCTL through an explicit device provider.

    The command is intentionally raw: REA authenticated the Windows device
    boundary, but did not establish Horizon's FATX command values or their
    safety semantics.  The default provider requests a read-only handle; a
    caller-supplied provider keeps this function testable without touching a
    physical device.
    """

    if provider is None:
        provider = WindowsDeviceIoProvider()
    binding = DeviceIoBinding(provider)
    with binding.open_session(device_path) as session:
        output = session.io_control(control_code, input_data, output_capacity)
    return {
        "device_path": device_path,
        "control_code": control_code,
        "input_length": len(input_data),
        "output_capacity": output_capacity,
        "output_length": len(output),
        "output_hex": output.hex(),
        "status": "provider-bound-read-only-handle",
        "limitations": [
            "The IOCTL is caller-selected; FATX command semantics are not inferred.",
            "The default Windows adapter requests GENERIC_READ only, but IOCTL safety remains caller responsibility.",
        ],
    }


def native_runtime_operation_report(
    dll_path: Path,
    operation: str,
    arguments: tuple[int, ...] = (),
    *,
    powershell_path: Path | None = None,
    provider=None,
) -> dict[str, object]:
    """Invoke one explicit Horizon/HVM runtime export and preserve its result."""

    allowed = {"check-runtime", "check-runtime64", "run-hvm", "get-user-string", "get-user-string64"}
    if operation not in allowed:
        raise ValueError(f"unsupported native runtime operation: {operation}")
    if operation.startswith("get-user-string") and len(arguments) != 3:
        raise ValueError(f"{operation} requires exactly three integer arguments")
    if not operation.startswith("get-user-string") and arguments:
        raise ValueError(f"{operation} does not accept arguments")
    if provider is None:
        expected_architecture = "x86_64" if operation.endswith("64") else "x86"
        image_architecture, _process_architecture = compatible_pe_architecture(dll_path)
        if image_architecture != expected_architecture:
            raise OSError(
                f"{operation} requires an {expected_architecture} runtime image, got {image_architecture}"
            )
        required_export = {
            "check-runtime": "DNG_Runtime",
            "check-runtime64": "DNG_Runtime",
            "run-hvm": "RunHVM",
            "get-user-string": "GetUserString",
            "get-user-string64": "GetUserString",
        }[operation]
        if required_export not in pe_export_names(dll_path):
            raise OSError(f"{dll_path} does not export {required_export}")
        provider = PowerShellNativeRuntimeProvider(dll_path, powershell_path=powershell_path)
    binding = NativeRuntimeBinding(provider)
    if operation == "check-runtime":
        result = binding.check_runtime()
    elif operation == "check-runtime64":
        result = binding.check_runtime64()
    elif operation == "run-hvm":
        result = binding.run_hvm()
    elif operation == "get-user-string":
        result = binding.get_user_string(*arguments)
    else:
        result = binding.get_user_string64(*arguments)
    return {
        "dll": str(dll_path),
        "operation": operation,
        "arguments": list(arguments),
        "result": result,
        "status": "provider-bound-raw-result",
        "limitations": [
            "Native argument meanings and returned handles are not inferred.",
            "The operation executes the caller-selected native DLL through the explicit provider.",
        ],
    }


def native_lzo_operation_report(
    dll_path: Path,
    operation: str,
    *,
    source: bytes = b"",
    variant: str = "lzo1x_1",
    output_capacity: int = 0,
    work_memory_size: int | None = None,
    powershell_path: Path | None = None,
    provider=None,
) -> dict[str, object]:
    """Run one explicit REA-observed LZO operation through a caller DLL."""

    if operation not in {"version-string", "version-date", "compress", "decompress"}:
        raise ValueError(f"unsupported native LZO operation: {operation}")
    if provider is None:
        provider = PowerShellLzoProvider(dll_path, powershell_path=powershell_path)
    binding = LzoBinding(provider)
    if operation == "version-string":
        result: object = binding.version_string()
        output = b""
    elif operation == "version-date":
        result = binding.version_date()
        output = b""
    else:
        if not source:
            raise ValueError(f"{operation} requires non-empty source bytes")
        if output_capacity <= 0:
            raise ValueError(f"{operation} requires a positive output capacity")
        if work_memory_size is None:
            work_memory_size = 262144 if variant == "lzo2a_999" else 65536
        if work_memory_size <= 0:
            raise ValueError("work_memory_size must be positive")
        codec = LzoCodec(binding)
        if operation == "compress":
            output = codec.compress(variant, source, output_capacity, bytes(work_memory_size))
        else:
            output = codec.decompress(variant, source, output_capacity, bytes(work_memory_size))
        result = {"output_length": len(output), "output_sha256": hashlib.sha256(output).hexdigest()}
    return {
        "dll": str(dll_path),
        "operation": operation,
        "variant": variant if operation in {"compress", "decompress"} else None,
        "source_length": len(source),
        "result": result,
        "status": "provider-bound-raw-result",
        "limitations": [
            "The native provider is caller-selected and the compression variant is explicit.",
            "LZO output is returned by digest and length; use the CLI output path for bytes.",
        ],
        "output": output,
    }


def _json_report(report: ContainerReport) -> dict:
    result = asdict(report)
    result["is_container"] = report.is_container
    if report.stfs_header is not None:
        result["stfs_header"]["content_type_name"] = stfs_content_type_name(
            report.stfs_header.content_type
        )
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
    parser.add_argument("path", type=Path, nargs="?")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--capabilities", action="store_true", help="Print the evidence-qualified implementation capability ledger")
    parser.add_argument("--rea-feature-ledger", action="store_true", help="Print the compact REA reconstruction ledger")
    parser.add_argument("--native-surface", action="store_true", help="Print the REA-observed native import boundary")
    parser.add_argument("--native-architecture", action="store_true", help="Inspect a PE native image's architecture without loading it")
    parser.add_argument("--native-exports", action="store_true", help="Inspect named PE exports without loading the image")
    parser.add_argument("--native-contract", action="store_true", help="Compare a supplied DLL with its REA-observed export contract")
    parser.add_argument("--native-runtime-operation", choices=("check-runtime", "check-runtime64", "run-hvm", "get-user-string", "get-user-string64"), help="Invoke one explicit Horizon/HVM runtime export on the positional DLL")
    parser.add_argument("--native-runtime-args", nargs=3, type=lambda value: int(value, 0), metavar=("ARG0", "ARG1", "ARG2"), help="Three raw integer arguments for a GetUserString operation")
    parser.add_argument("--native-runtime-powershell", type=Path, help="Explicit matching PowerShell host for --native-runtime-operation")
    parser.add_argument("--lzo-operation", choices=("version-string", "version-date", "compress", "decompress"), help="Invoke one explicit LZO operation")
    parser.add_argument("--lzo-dll", type=Path, help="Absolute x86 lzo.dll path for --lzo-operation")
    parser.add_argument("--lzo-powershell", type=Path, help="Explicit 32-bit PowerShell host for --lzo-operation")
    parser.add_argument("--lzo-source", type=Path, help="Input bytes for a compress/decompress LZO operation")
    parser.add_argument("--lzo-output", type=Path, help="Write compress/decompress output bytes")
    parser.add_argument("--lzo-variant", choices=("lzo1x_1", "lzo2a_999", "lzo1x", "lzo2a"), default="lzo1x_1")
    parser.add_argument("--lzo-output-capacity", type=int, default=0)
    parser.add_argument("--lzo-work-memory", type=int)
    parser.add_argument("--native-installation", type=Path, metavar="DIRECTORY", help="Inventory expected native Horizon DLLs without loading them")
    parser.add_argument("--native-import-bundle", type=Path, help="Read the complete REA managed P/Invoke inventory")
    parser.add_argument("--native-import-pattern", help="Case-insensitive regex for --native-import-bundle scope!name")
    parser.add_argument("--device-surface", action="store_true", help="Print the REA-observed device exploration surface")
    parser.add_argument("--device-inventory", action="store_true", help="Print a read-only host-visible volume inventory")
    parser.add_argument("--device-list", type=Path, metavar="DIRECTORY", help="List one host-visible device directory without mutation")
    parser.add_argument("--device-ioctl", type=lambda value: int(value, 0), metavar="CODE", help="Forward one explicit IOCTL to the positional device path")
    parser.add_argument("--device-ioctl-input-hex", default="", metavar="HEX", help="Hex input bytes for --device-ioctl")
    parser.add_argument("--device-ioctl-output-capacity", type=int, default=0, metavar="BYTES", help="Output capacity for --device-ioctl")
    parser.add_argument("--resource-surface", action="store_true", help="Print the REA-observed managed-resource surface")
    parser.add_argument("--resource-bundle", type=Path, help="Read an exported REA managed-resource inventory bundle")
    parser.add_argument("--resource-pattern", help="Case-insensitive regex for --resource-bundle resource names")
    parser.add_argument("--dotnet-resource-index", action="store_true", help="Parse a standalone .NET .resources payload without deserializing values")
    parser.add_argument("--verify-resources", type=Path, metavar="BUNDLE", help="Verify shipped managed-resource hashes against an REA bundle")
    parser.add_argument("--extract-resources", type=Path, metavar="DIR", help="Extract uniquely hash-verified embedded resources from --path using --resource-bundle")
    parser.add_argument("--managed-surface", type=Path, help="Read an exported REA managed-members bundle and print its observed surface")
    parser.add_argument("--managed-references", type=Path, help="Read an exported REA managed-artifact bundle and print declared assembly references")
    parser.add_argument("--managed-artifact", type=Path, help="Read an exported REA managed-artifact bundle and print identity and coverage")
    parser.add_argument("--reference-pattern", help="Case-insensitive regex for --managed-references assembly names")
    parser.add_argument("--surface-pattern", help="Case-insensitive regex for --managed-surface member selection")
    parser.add_argument("--managed-editor-families", type=Path, help="Group an exported REA managed-members bundle into observed editor families")
    parser.add_argument("--family-pattern", help="Case-insensitive regex for --managed-editor-families type names")
    parser.add_argument("--managed-named-namespaces", type=Path, help="Summarize stable named namespaces from an exported REA managed-members bundle")
    parser.add_argument("--namespace-pattern", help="Case-insensitive regex for --managed-named-namespaces type names")
    parser.add_argument("--managed-guarded-methods", type=Path, help="Report REA-observed methods with throw and no return opcode")
    parser.add_argument("--guarded-method-pattern", help="Case-insensitive regex for --managed-guarded-methods declaring type or method")
    parser.add_argument("--managed-body-fidelity", type=Path, help="Measure distinctness of retained REA managed method bodies")
    parser.add_argument("--body-fidelity-pattern", help="Case-insensitive regex for --managed-body-fidelity declaring type or method")
    parser.add_argument("--managed-schema", type=Path, help="Read joined type/field/method metadata from an REA bundle")
    parser.add_argument("--schema-pattern", help="Case-insensitive regex for managed-schema type names")
    parser.add_argument("--schema-bodies", action="store_true", help="Include REA-observed managed method body summaries in --managed-schema")
    parser.add_argument("--schema-method-pattern", help="Case-insensitive regex for method names in --managed-schema")
    parser.add_argument("--schema-field-accesses", action="store_true", help="Include REA-observed field-access anchors in --managed-schema")
    parser.add_argument("--managed-io-contract", type=Path, help="Read static managed Read/Write/Load/Save contracts from an REA bundle")
    parser.add_argument("--io-type-pattern", help="Case-insensitive regex for managed I/O contract type names")
    parser.add_argument("--io-method-pattern", default=r"^(get_|set_|Read|Write|Load|Save|Compress|Decompress)", help="Regex for managed I/O contract method names")
    parser.add_argument("--catalog", choices=("shared", "skyrim", "gears", "halo", "legacy", "global"), help="Print one REA-observed title catalog")
    parser.add_argument("--profile-data", action="store_true", help="Inspect an explicit ProfileData metadata envelope")
    parser.add_argument("--editor-inspect", action="store_true", help="Dispatch the input through the clean-room editor registry")
    parser.add_argument("--editor-edit-values", type=Path, metavar="JSON", help="Apply registry metadata edits from a JSON object")
    parser.add_argument("--editor-edit-output", type=Path, metavar="FILE", help="Output path for --editor-edit-values")
    parser.add_argument("--verify-detached-signature", type=Path, metavar="SIGNATURE", help="Verify a detached development signature over the input bytes")
    parser.add_argument("--sign-detached-signature", type=Path, metavar="SIGNATURE", help="Sign the input bytes with an explicit development RSA private key")
    parser.add_argument("--sign-written-output", type=Path, metavar="SIGNATURE", help="After a mutation, sign the exact bytes written by --write or --in-place")
    parser.add_argument("--sign-written-package", type=Path, metavar="OUTPUT", help="After a mutation, XeCrypt-sign the exact CON bytes written by --write or --in-place")
    parser.add_argument("--verify-embedded-signature", action="store_true", help="Verify an explicitly bounded in-container RSA signature")
    parser.add_argument("--signed-start", type=lambda value: int(value, 0), help="Start offset for --verify-embedded-signature")
    parser.add_argument("--signed-end", type=lambda value: int(value, 0), help="Exclusive end offset for --verify-embedded-signature")
    parser.add_argument("--signature-offset", type=lambda value: int(value, 0), help="Signature offset for --verify-embedded-signature")
    parser.add_argument("--signature-label", help="Caller-defined label for --verify-detached-signature")
    parser.add_argument("--signature-algorithm", choices=("RSA-SHA256-PKCS1v1.5", "RSA-SHA1-PKCS1v1.5", "RSA-SHA1-XeCrypt-PKCS1v1.5"), default="RSA-SHA256-PKCS1v1.5")
    parser.add_argument("--public-key-modulus", type=lambda value: int(value, 0), help="Public RSA modulus for detached verification")
    parser.add_argument("--public-key-exponent", type=lambda value: int(value, 0), default=65537)
    parser.add_argument("--public-key-json", type=Path, help="JSON key emitted by --public-key for detached verification")
    parser.add_argument("--private-key-json", type=Path, help="Caller-supplied development RSA private key JSON for --sign-detached-signature")
    parser.add_argument("--anti-analysis", type=Path, metavar="BUNDLE", help="Report REA-observed anti-analysis markers from an evidence bundle")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--list", action="store_true", help="List STFS file-table entries")
    parser.add_argument("--list-xdbf", action="store_true", help="List parsed XDBF entries from embedded GPD files")
    parser.add_argument("--xdbf-surface", action="store_true", help="Report XDBF payload sizes and digests without interpreting opaque entries")
    parser.add_argument("--xdbf-summary", action="store_true", help="Summarize parseable embedded GPD namespaces")
    parser.add_argument("--list-achievements", action="store_true", help="List observed achievements from embedded GPD files")
    parser.add_argument("--profile-summary", action="store_true", help="Summarize observed achievement fields across embedded GPD files")
    parser.add_argument("--achievements-output", type=Path, help="Write embedded achievement records as JSON")
    parser.add_argument("--achievement-links-output", type=Path, help="Write embedded achievement-to-image links as JSON")
    parser.add_argument("--extract-dir", type=Path, help="Extract STFS files into this directory")
    parser.add_argument("--extract-achievement-images", type=Path, metavar="DIR", help="Extract unique linked achievement PNGs")
    parser.add_argument("--extract", metavar="ENTRY", help="Extract only this STFS path")
    parser.add_argument("--verify-hashes", action="store_true", help="Verify STFS block and metadata hashes")
    parser.add_argument("--security", action="store_true", help="Show STFS public security and license metadata")
    parser.add_argument("--public-key", action="store_true", help="Show the public RSA key from a CON certificate")
    parser.add_argument("--signature-regions", action="store_true", help="Report stored STFS signature ranges and hashes")
    parser.add_argument("--verify-stfs-signature", action="store_true", help="Verify the observed CON package signature using its stored public key")
    parser.add_argument("--sign-stfs-package", type=Path, metavar="OUTPUT", help="Sign the observed CON package region with an explicit matching RSA private key")
    parser.add_argument("--fatx-path", action="store_true", help="Print the canonical FATX-facing Content path")
    parser.add_argument("--fatx-filename", help="Caller filename for non-profile FATX path reporting")
    parser.add_argument("--signature-compare", type=Path, metavar="OTHER", help="Compare STFS signature bytes and changed regions with another image")
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
    parser.add_argument("--achievement-flags-or", type=lambda value: int(value, 0), help="Set a raw 16-bit flags mask on every observed achievement in one XDBF payload")
    parser.add_argument("--achievement-flags-and-not", type=lambda value: int(value, 0), help="Clear a raw 16-bit flags mask on every observed achievement in one XDBF payload")
    parser.add_argument("--profile-achievement-flags-or", type=lambda value: int(value, 0), help="Set a raw 16-bit flags mask across every observed achievement in embedded GPDs")
    parser.add_argument("--profile-achievement-flags-and-not", type=lambda value: int(value, 0), help="Clear a raw 16-bit flags mask across every observed achievement in embedded GPDs")
    parser.add_argument("--profile-xdbf-text", metavar="TEXT", help="Replace an exact namespace-5 XDBF string across embedded GPD/FIT files")
    parser.add_argument("--profile-xdbf-text-value", help="Replacement value for --profile-xdbf-text")
    parser.add_argument("--achievement-unlock-filetime", type=lambda value: int(value, 0), help="Replace the observed 64-bit big-endian achievement unlock FILETIME")
    parser.add_argument("--achievement-unlock-utc", help="Replace the achievement unlock time with a timezone-aware ISO-8601 UTC value")
    parser.add_argument("--achievement-name")
    parser.add_argument("--account-decrypt", type=Path, metavar="OUTPUT", help="Decrypt the STFS Account entry to a raw output file through explicit providers")
    parser.add_argument("--account-encrypt", type=Path, metavar="PLAINTEXT", help="Encrypt raw Account plaintext through explicit providers")
    parser.add_argument("--account-encrypt-container", type=Path, metavar="PLAINTEXT", help="Encrypt plaintext and replace the STFS Account entry")
    parser.add_argument("--account-encrypt-output", type=Path, metavar="OUTPUT", help="Raw output path for --account-encrypt")
    parser.add_argument("--account-class3-dll", type=Path, help="Absolute x86 class3.dll path for --account-decrypt")
    parser.add_argument("--account-key-helper", type=Path, help="Absolute caller-owned key-vault helper for --account-decrypt")
    parser.add_argument("--account-output-capacity", type=int, help="Decrypted Account output buffer capacity")
    parser.add_argument("--account-encrypt-capacity", type=int, help="Caller-sized encrypted Account output buffer capacity")
    parser.add_argument("--account-encrypt-length", type=int, help="Caller-known encrypted Account output length")
    parser.add_argument("--historical-account-inspect", action="store_true", help="Inspect the authenticated Account body with a caller-supplied historical-reference key")
    parser.add_argument("--historical-account-key-hex", help="Exactly 16-byte key for --historical-account-inspect; never persisted")
    parser.add_argument("--historical-account-edit", type=Path, metavar="JSON", help="Apply explicit historical Account field updates from JSON")
    args = parser.parse_args()
    if args.rea_feature_ledger:
        print(json.dumps(rea_feature_ledger(), indent=2, ensure_ascii=False))
        return 0
    if args.lzo_operation:
        if not args.lzo_dll:
            parser.error("--lzo-operation requires --lzo-dll")
        source = b""
        if args.lzo_source:
            try:
                source = args.lzo_source.read_bytes()
            except OSError as exc:
                parser.error(str(exc))
        try:
            report = native_lzo_operation_report(
                args.lzo_dll,
                args.lzo_operation,
                source=source,
                variant=args.lzo_variant,
                output_capacity=args.lzo_output_capacity,
                work_memory_size=args.lzo_work_memory,
                powershell_path=args.lzo_powershell,
            )
            output = report.pop("output")
            if args.lzo_output and output:
                _atomic_replace_bytes(args.lzo_output, output)
                report["output_path"] = str(args.lzo_output)
            print(json.dumps(report, indent=2, ensure_ascii=False))
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0
    if args.capabilities:
        print(json.dumps(capability_report(), indent=2, ensure_ascii=False))
        if args.path is None:
            return 0
    if args.account_decrypt:
        if not args.account_class3_dll or not args.account_key_helper or args.account_output_capacity is None:
            parser.error("--account-decrypt requires --account-class3-dll, --account-key-helper, and --account-output-capacity")
        try:
            print(json.dumps(decrypt_account_entry(
                args.path,
                args.account_decrypt,
                args.account_class3_dll,
                args.account_key_helper,
                args.account_output_capacity,
            ), indent=2))
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0
    if args.historical_account_inspect:
        if not args.historical_account_key_hex:
            parser.error("--historical-account-inspect requires --historical-account-key-hex")
        try:
            key = bytes.fromhex(args.historical_account_key_hex)
            print(json.dumps(historical_account_report(args.path, key), indent=2, ensure_ascii=False))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0
    if args.account_encrypt:
        if not args.account_encrypt_output or not args.account_class3_dll or not args.account_key_helper:
            parser.error("--account-encrypt requires --account-encrypt-output, --account-class3-dll, and --account-key-helper")
        if args.account_encrypt_capacity is None or args.account_encrypt_length is None:
            parser.error("--account-encrypt requires --account-encrypt-capacity and --account-encrypt-length")
        try:
            print(json.dumps(encrypt_account_payload(
                args.account_encrypt,
                args.account_encrypt_output,
                args.account_class3_dll,
                args.account_key_helper,
                args.account_encrypt_capacity,
                args.account_encrypt_length,
            ), indent=2))
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0
    if args.native_surface:
        print(json.dumps(native_surface_report(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.native_architecture:
        try:
            image, process = compatible_pe_architecture(args.path)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"path": str(args.path), "image_architecture": image, "process_architecture": process}, indent=2))
        return 0
    if args.native_exports:
        try:
            exports = pe_export_names(args.path)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"path": str(args.path), "exports": list(exports), "export_count": len(exports)}, indent=2))
        return 0
    if args.native_contract:
        try:
            print(json.dumps(native_export_contract_report(args.path), indent=2, ensure_ascii=False))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0
    if args.native_runtime_operation:
        try:
            report = native_runtime_operation_report(
                args.path,
                args.native_runtime_operation,
                tuple(args.native_runtime_args or ()),
                powershell_path=args.native_runtime_powershell,
            )
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.native_installation:
        try:
            print(json.dumps(native_installation_report(args.native_installation), indent=2, ensure_ascii=False))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0
    if args.native_import_bundle:
        try:
            print(json.dumps(managed_native_import_report(args.native_import_bundle, args.native_import_pattern), indent=2, ensure_ascii=False))
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.device_surface:
        print(json.dumps(device_surface_report(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.device_inventory:
        print(json.dumps(device_inventory_report(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.device_list:
        try:
            entries = enumerate_host_device_entries(args.device_list)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"root": str(args.device_list), "entries": [asdict(item) for item in entries]}, indent=2))
        return 0
    if args.device_ioctl is not None:
        if args.device_ioctl_output_capacity < 0:
            parser.error("--device-ioctl-output-capacity must be non-negative")
        try:
            input_data = bytes.fromhex(args.device_ioctl_input_hex)
            report = device_ioctl_report(
                str(args.path),
                args.device_ioctl,
                input_data,
                args.device_ioctl_output_capacity,
            )
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.resource_surface:
        print(json.dumps(observed_resource_surface(), indent=2, ensure_ascii=False))
        if len(__import__("sys").argv) == 3:
            return 0
    if args.extract_resources:
        if not args.resource_bundle:
            parser.error("--extract-resources requires --resource-bundle")
        try:
            report = extract_managed_resource_payloads(args.path, args.resource_bundle, args.extract_resources, args.resource_pattern)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.resource_bundle:
        try:
            report = resource_surface_report(args.resource_bundle, args.resource_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.dotnet_resource_index:
        try:
            report = parse_dotnet_resources(args.path.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.verify_resources:
        try:
            report = verify_managed_resource_payloads(args.path, args.verify_resources, args.resource_pattern)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_surface:
        try:
            report = managed_surface_report(args.managed_surface, args.surface_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_references:
        try:
            print(json.dumps(managed_reference_report(args.managed_references, args.reference_pattern), indent=2, ensure_ascii=False))
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.managed_artifact:
        try:
            print(json.dumps(managed_artifact_report(args.managed_artifact), indent=2, ensure_ascii=False))
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.managed_editor_families:
        try:
            report = managed_editor_family_report(args.managed_editor_families, args.family_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_named_namespaces:
        try:
            report = managed_named_namespace_report(args.managed_named_namespaces, args.namespace_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_guarded_methods:
        try:
            report = managed_guarded_methods_report(args.managed_guarded_methods, args.guarded_method_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_schema:
        try:
            report = managed_schema_report(args.managed_schema, args.schema_pattern, args.schema_bodies, args.schema_method_pattern, args.schema_field_accesses)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.managed_io_contract:
        try:
            report = managed_io_contract_report(args.managed_io_contract, args.io_type_pattern, args.io_method_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.catalog:
        print(json.dumps(catalog_report(args.catalog), indent=2, ensure_ascii=False))
        return 0
    if args.profile_data:
        try:
            report = profile_data_report(args.path)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    if args.editor_inspect:
        try:
            report = editor_inspect_report(args.path)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        return 0
    if args.editor_edit_values:
        if not args.editor_edit_output:
            parser.error("--editor-edit-values requires --editor-edit-output")
        if args.editor_edit_output.resolve() == args.path.resolve():
            parser.error("--editor-edit-output must be different from the input path")
        try:
            editor_name, edited = editor_edit_values(args.path, args.editor_edit_values)
            _atomic_replace_bytes(args.editor_edit_output, edited)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(str(exc))
        print(json.dumps({"editor": editor_name, "input": str(args.path), "output": str(args.editor_edit_output), "bytes": len(edited)}, indent=2))
        return 0
    if args.sign_detached_signature:
        if not args.signature_label or not args.private_key_json:
            parser.error("--sign-detached-signature requires --signature-label and --private-key-json")
        if args.signature_algorithm != "RSA-SHA256-PKCS1v1.5":
            parser.error("--sign-detached-signature currently supports RSA-SHA256-PKCS1v1.5 only")
        try:
            result = sign_detached_signature(args.path, args.sign_detached_signature, args.signature_label, args.private_key_json)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(str(exc))
        print(json.dumps(result, indent=2))
        return 0
    if args.verify_detached_signature:
        if not args.signature_label or (args.public_key_modulus is None and not args.public_key_json):
            parser.error("--verify-detached-signature requires --signature-label and a public key")
        if args.public_key_modulus is not None and args.public_key_json:
            parser.error("choose one of --public-key-modulus or --public-key-json")
        try:
            modulus, exponent = (
                read_public_key_json(args.public_key_json)
                if args.public_key_json
                else (args.public_key_modulus, args.public_key_exponent)
            )
            verified = verify_detached_signature(
                args.path,
                args.verify_detached_signature,
                args.signature_label,
                args.signature_algorithm,
                modulus,
                exponent,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"verified": verified, "algorithm": args.signature_algorithm, "region_label": args.signature_label}, indent=2))
        return 0 if verified else 1
    if args.verify_embedded_signature:
        if args.signed_start is None or args.signed_end is None or args.signature_offset is None:
            parser.error("--verify-embedded-signature requires --signed-start, --signed-end, and --signature-offset")
        if args.public_key_modulus is None and not args.public_key_json:
            parser.error("--verify-embedded-signature requires a public key")
        if args.public_key_modulus is not None and args.public_key_json:
            parser.error("choose one of --public-key-modulus or --public-key-json")
        try:
            modulus, exponent = (
                read_public_key_json(args.public_key_json)
                if args.public_key_json
                else (args.public_key_modulus, args.public_key_exponent)
            )
            verified = verify_embedded_signature_region(
                args.path.read_bytes(),
                signed_start=args.signed_start,
                signed_end=args.signed_end,
                signature_offset=args.signature_offset,
                modulus=modulus,
                exponent=exponent,
                algorithm=args.signature_algorithm,
            )
        except (OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"verified": verified, "algorithm": args.signature_algorithm, "signed_start": args.signed_start, "signed_end": args.signed_end, "signature_offset": args.signature_offset}, indent=2))
        return 0 if verified else 1
    if args.anti_analysis:
        try:
            print(json.dumps(anti_analysis_report(args.anti_analysis), indent=2, ensure_ascii=False))
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.signature_compare:
        try:
            report = stfs_signature_mutation_report(args.path.read_bytes(), args.signature_compare.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, indent=2))
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
    if args.sign_written_output:
        if not write_target:
            parser.error("--sign-written-output requires --write or --in-place")
        if not args.signature_label or not args.private_key_json:
            parser.error("--sign-written-output requires --signature-label and --private-key-json")
        if args.signature_algorithm != "RSA-SHA256-PKCS1v1.5":
            parser.error("--sign-written-output currently supports RSA-SHA256-PKCS1v1.5 only")
        if args.sign_written_output.resolve() == write_target.resolve():
            parser.error("--sign-written-output must be different from the written container")
    if args.sign_written_package:
        if not write_target:
            parser.error("--sign-written-package requires --write or --in-place")
        if not args.private_key_json:
            parser.error("--sign-written-package requires --private-key-json")
        if args.sign_written_package.resolve() == write_target.resolve():
            parser.error("--sign-written-package must be different from the written container")
    mutation_written = False

    def write_mutation(data: bytes) -> None:
        if data[:4] in STFS_MAGICS:
            validate_stfs_mutation(data)
        if not args.in_place:
            _atomic_replace_bytes(write_target, data)
        else:
            if args.backup:
                _atomic_replace_bytes(args.backup, args.path.read_bytes())
            _atomic_replace_bytes(args.path, data)
        if args.sign_written_output:
            result = sign_detached_signature(write_target, args.sign_written_output, args.signature_label, args.private_key_json)
            print(json.dumps({"written_signature": result}, indent=2))
        if args.sign_written_package:
            signed = sign_stfs_console_package(
                write_target.read_bytes(),
                read_private_key_json(args.private_key_json),
            )
            _atomic_replace_bytes(args.sign_written_package, signed)
            verification = verify_stfs_console_signature(signed)
            print(json.dumps({
                "written_package": str(args.sign_written_package),
                "bytes": len(signed),
                "signature_verified": verification["verified"],
                "algorithm": verification["algorithm"],
                "console_authority_established": False,
            }, indent=2))

    if args.managed_body_fidelity:
        try:
            body_report = managed_body_fidelity_report(args.managed_body_fidelity, args.body_fidelity_pattern)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(body_report, indent=2, ensure_ascii=False))
        return 0

    try:
        raw = args.path.read_bytes()
        if args.historical_account_edit:
            if not args.historical_account_key_hex:
                parser.error("--historical-account-edit requires --historical-account-key-hex")
            if not write_target:
                parser.error("--historical-account-edit requires --write or --in-place")
            try:
                updates = json.loads(args.historical_account_edit.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                parser.error(f"invalid historical Account edit JSON: {exc}")
            if not isinstance(updates, dict):
                parser.error("historical Account edit JSON must contain an object")
            try:
                raw = mutate_historical_account(
                    raw,
                    bytes.fromhex(args.historical_account_key_hex),
                    updates,
                )
                write_mutation(raw)
            except (OSError, ValueError) as exc:
                parser.error(str(exc))
            print(f"Wrote unsigned historical Account mutation to {write_target}")
            return 0
        profile_flags_requested = args.profile_achievement_flags_or is not None or args.profile_achievement_flags_and_not is not None
        if args.profile_achievement_flags_or is not None and args.profile_achievement_flags_and_not is not None:
            parser.error("choose one of --profile-achievement-flags-or or --profile-achievement-flags-and-not")
        if profile_flags_requested:
            if raw[:4] not in STFS_MAGICS:
                parser.error("profile achievement flag editing requires an STFS container")
            if not write_target:
                parser.error("profile achievement flag editing requires --write or --in-place")
            raw = mutate_profile_achievement_flags(
                raw,
                args.profile_achievement_flags_or if args.profile_achievement_flags_or is not None else args.profile_achievement_flags_and_not,
                mode="or" if args.profile_achievement_flags_or is not None else "and-not",
            )
            write_mutation(raw)
            mutation_written = True
            print(f"Wrote profile achievement flag mutation to {write_target}")
        if args.profile_xdbf_text is not None or args.profile_xdbf_text_value is not None:
            if args.profile_xdbf_text is None or args.profile_xdbf_text_value is None:
                parser.error("--profile-xdbf-text requires --profile-xdbf-text-value")
            if raw[:4] not in STFS_MAGICS:
                parser.error("profile XDBF text editing requires an STFS container")
            if not write_target:
                parser.error("profile XDBF text editing requires --write or --in-place")
            raw = mutate_profile_xdbf_text(raw, args.profile_xdbf_text, args.profile_xdbf_text_value)
            write_mutation(raw)
            mutation_written = True
            print(f"Wrote profile XDBF text mutation to {write_target}")
        if raw[:4] == b"XDBF":
            achievement_requested = args.achievement is not None
            bulk_flags_requested = args.achievement_flags_or is not None or args.achievement_flags_and_not is not None
            if args.achievement_flags_or is not None and args.achievement_flags_and_not is not None:
                parser.error("choose one of --achievement-flags-or or --achievement-flags-and-not")
            xdbf_add_requested = any(
                value is not None
                for value in (args.xdbf_add_namespace, args.xdbf_add_id, args.xdbf_add_source)
            )
            text_requested = args.xdbf_text is not None or args.xdbf_text_value is not None
            if args.xdbf_replace is not None or args.xdbf_remove or achievement_requested or bulk_flags_requested or xdbf_add_requested or text_requested:
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
                    if bulk_flags_requested:
                        parser.error("single-achievement editing cannot be combined with bulk flag editing")
                    raw = mutate_xdbf_achievement(
                        raw,
                        args.achievement,
                        achievement_id=args.achievement_id,
                        image_id=args.image_id,
                        gamerscore=args.gamerscore,
                        flags=args.achievement_flags,
                        unlock_time_filetime=args.achievement_unlock_filetime,
                        unlock_time_utc=args.achievement_unlock_utc,
                        name=args.achievement_name,
                    )
                if bulk_flags_requested:
                    raw = mutate_xdbf_achievement_flags(
                        raw,
                        args.achievement_flags_or if args.achievement_flags_or is not None else args.achievement_flags_and_not,
                        mode="or" if args.achievement_flags_or is not None else "and-not",
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
            if args.xdbf_surface:
                print(json.dumps(xdbf_payload_surface(raw), indent=2, ensure_ascii=False))
            if args.as_json or not args.output:
                if not args.list and not args.xdbf_surface:
                    print(payload)
            return 0

        report = inspect(args.path)
    except OSError as exc:
        parser.error(str(exc))

    if args.xdbf_file is not None:
        embedded_text_requested = args.xdbf_text is not None or args.xdbf_text_value is not None
        embedded_achievement_requested = args.achievement is not None or args.achievement_flags_or is not None or args.achievement_flags_and_not is not None
        if args.achievement_flags_or is not None and args.achievement_flags_and_not is not None:
            parser.error("choose one of --achievement-flags-or or --achievement-flags-and-not")
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
                if args.achievement is not None:
                    if args.achievement_flags_or is not None or args.achievement_flags_and_not is not None:
                        parser.error("single-achievement editing cannot be combined with bulk flag editing")
                    edited_payload = mutate_xdbf_achievement(
                        xdbf_payload,
                        args.achievement,
                        achievement_id=args.achievement_id,
                        image_id=args.image_id,
                        gamerscore=args.gamerscore,
                        flags=args.achievement_flags,
                        unlock_time_filetime=args.achievement_unlock_filetime,
                        unlock_time_utc=args.achievement_unlock_utc,
                        name=args.achievement_name,
                    )
                    operation_name = "achievement"
                else:
                    edited_payload = mutate_xdbf_achievement_flags(
                        xdbf_payload,
                        args.achievement_flags_or if args.achievement_flags_or is not None else args.achievement_flags_and_not,
                        mode="or" if args.achievement_flags_or is not None else "and-not",
                    )
                    operation_name = "achievement-flags"
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

    if args.account_encrypt_container:
        if not write_target:
            parser.error("--account-encrypt-container requires --write or --in-place")
        if not args.account_class3_dll or not args.account_key_helper:
            parser.error("--account-encrypt-container requires --account-class3-dll and --account-key-helper")
        if args.account_encrypt_capacity is None or args.account_encrypt_length is None:
            parser.error("--account-encrypt-container requires --account-encrypt-capacity and --account-encrypt-length")
        try:
            mutated = encrypt_account_in_container(
                args.path.read_bytes(),
                args.account_encrypt_container.read_bytes(),
                args.account_class3_dll,
                args.account_key_helper,
                args.account_encrypt_capacity,
                args.account_encrypt_length,
            )
            write_mutation(mutated)
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0

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
    if args.xdbf_summary:
        if not report.stfs_header:
            parser.error("--xdbf-summary requires a readable STFS header")
        print(json.dumps(list(summarize_embedded_xdbf(raw, report.stfs_header)), indent=2, ensure_ascii=False))
        return 0
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
    if args.achievement_links_output:
        if not report.stfs_header:
            parser.error("--achievement-links-output requires a readable STFS header")
        links = list_embedded_achievement_image_links(raw, report.stfs_header)
        args.achievement_links_output.write_text(
            json.dumps(list(links), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({
            "path": str(args.achievement_links_output),
            "count": len(links),
            "linked": sum(item["status"] == "linked" for item in links),
            "missing": sum(item["status"] == "missing" for item in links),
        }, indent=2))
    if args.extract_achievement_images:
        if not report.stfs_header:
            parser.error("--extract-achievement-images requires a readable STFS header")
        extraction = extract_embedded_achievement_images(raw, args.extract_achievement_images, report.stfs_header)
        print(json.dumps({key: value for key, value in extraction.items() if key != "images"}, indent=2))
    if args.profile_summary:
        if not report.stfs_header:
            parser.error("--profile-summary requires a readable STFS header")
        print(json.dumps(summarize_profile_achievements(raw, report.stfs_header), indent=2, ensure_ascii=False))
        return 0
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

    if args.public_key:
        try:
            key = extract_stfs_public_key(raw)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps({"exponent": key.exponent, "modulus_hex": f"{key.modulus:0256x}"}, indent=2))
        return 0

    if args.signature_regions:
        try:
            print(json.dumps(stfs_signature_region_report(raw), indent=2))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0

    if args.verify_stfs_signature:
        try:
            signature_report = verify_stfs_console_signature(raw)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(signature_report, indent=2))
        return 0 if signature_report["verified"] else 1

    if args.sign_stfs_package:
        if not args.private_key_json:
            parser.error("--sign-stfs-package requires --private-key-json")
        if args.sign_stfs_package.resolve() == args.path.resolve():
            parser.error("--sign-stfs-package must be different from the input path")
        try:
            private_key = read_private_key_json(args.private_key_json)
            signed = sign_stfs_console_package(raw, private_key)
            _atomic_replace_bytes(args.sign_stfs_package, signed)
            verification = verify_stfs_console_signature(signed)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(str(exc))
        print(json.dumps({
            "output": str(args.sign_stfs_package),
            "bytes": len(signed),
            "signature_verified": verification["verified"],
            "algorithm": verification["algorithm"],
            "console_authority_established": False,
        }, indent=2))
        return 0 if verification["verified"] else 1

    if args.fatx_path:
        try:
            header = parse_stfs_header(raw)
            print(json.dumps({
                "content_type": f"0x{header.content_type:08X}",
                "content_type_name": stfs_content_type_name(header.content_type),
                "title_id": f"0x{header.title_id:08X}",
                "profile_id": header.profile_id.upper(),
                "magic_filename": stfs_magic_filename(header, args.fatx_filename),
                "fatx_path": stfs_fatx_device_path(header, args.fatx_filename),
            }, indent=2))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0

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

