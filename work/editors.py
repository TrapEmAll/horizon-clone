"""Clean-room game-editor dispatch layer.

The registry separates shared STFS/XDBF handling from title-specific editors.
Plugins receive bytes and metadata and must return deterministic, explicit
results; no target code is loaded or executed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Protocol

from .horizon_clone import (
    XdbfEntry,
    mutate_xdbf_achievement,
    mutate_xdbf_entry_same_size,
    mutate_xdbf_text,
    parse_xdbf,
    repack_xdbf_entries,
)
from .managed_surface import managed_surface_report_from_bundle
from .halo_catalog import validate_halo_metadata_values


@dataclass(frozen=True)
class EditorContext:
    title_id: int | None = None
    filename: str = ""
    magic: bytes = b""


class EditorPlugin(Protocol):
    name: str

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        ...

    def inspect(self, context: EditorContext, data: bytes) -> Any:
        ...


@dataclass(frozen=True)
class XdbfEditor:
    name: str = "XDBF/GPD editor"

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        return data[:4] == b"XDBF"

    def inspect(self, context: EditorContext, data: bytes) -> tuple[XdbfEntry, ...]:
        return parse_xdbf(data)

    def replace_entry(self, data: bytes, entry_index: int, replacement: bytes) -> bytes:
        """Replace an XDBF payload without changing its allocation."""
        entry = next((item for item in parse_xdbf(data) if item.index == entry_index), None)
        if entry is None:
            raise IndexError(f"unknown XDBF entry index: {entry_index}")
        return mutate_xdbf_entry_same_size(data, entry, replacement)

    def repack(
        self,
        data: bytes,
        replacements: dict[int, bytes],
        remove: tuple[int, ...] = (),
        additions: dict[tuple[int, int], bytes] | None = None,
    ) -> bytes:
        """Repack XDBF payloads within existing table/data capacity."""
        return repack_xdbf_entries(data, replacements, remove=remove, additions=additions)

    def edit_achievement(self, data: bytes, entry_index: int, **changes: object) -> bytes:
        """Edit the observed achievement fields through the editor boundary."""
        return mutate_xdbf_achievement(data, entry_index, **changes)

    def edit_text(self, data: bytes, entry_index: int, text: str) -> bytes:
        """Edit an observed namespace-5 UTF-16BE string through the editor boundary."""
        return mutate_xdbf_text(data, entry_index, text)


@dataclass(frozen=True)
class ManagedSurfaceEditor:
    """Inspect an exported REA managed-members bundle without executing it."""

    name: str = "REA managed surface"

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        if not data.lstrip().startswith(b"{"):
            return False
        try:
            import json

            bundle = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return any(
            isinstance(record, dict) and record.get("operation") == "inspect_managed_members"
            for record in bundle.get("records", [])
        )

    def inspect(self, context: EditorContext, data: bytes) -> dict[str, Any]:
        import json

        try:
            bundle = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("managed surface input must be UTF-8 JSON") from exc
        return managed_surface_report_from_bundle(bundle)


@dataclass(frozen=True)
class AccountEditor:
    """Handle the opaque STFS Account payload without guessing its schema."""

    name: str = "Opaque Account editor"

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        return context.filename.replace("\\", "/").rsplit("/", 1)[-1].casefold() == "account"

    def inspect(self, context: EditorContext, data: bytes) -> dict[str, object]:
        if not isinstance(data, bytes):
            raise TypeError("Account editor input must be bytes")
        return {
            "status": "opaque",
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mutation": "same-size-only",
            "limitations": [
                "REA did not expose an Account serializer, field offsets, or Account-specific call edge.",
                "The payload is not interpreted as ProfileData; it is only byte-addressable.",
            ],
        }

    def replace_same_size(self, data: bytes, replacement: bytes) -> bytes:
        if len(data) != len(replacement):
            raise ValueError("opaque Account replacement must preserve byte length")
        return bytes(replacement)


@dataclass(frozen=True)
class HaloMetadataEditor:
    """Validate an explicit JSON Halo metadata envelope without binary I/O."""

    name: str = "Halo metadata editor"

    def _decode(self, data: bytes) -> dict[str, Any]:
        import json

        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Halo metadata input must be UTF-8 JSON") from exc
        if not isinstance(value, dict) or value.get("editor") != "halo-metadata":
            raise ValueError("expected an explicit halo-metadata envelope")
        if not isinstance(value.get("type_name"), str) or not isinstance(value.get("values"), dict):
            raise ValueError("Halo metadata requires type_name and object values")
        return value

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        if not data.lstrip().startswith(b"{"):
            return False
        try:
            self._decode(data)
        except ValueError:
            return False
        return True

    def inspect(self, context: EditorContext, data: bytes) -> dict[str, object]:
        value = self._decode(data)
        normalized = validate_halo_metadata_values(value["type_name"], value["values"])
        return {
            "status": "metadata-only",
            "type_name": value["type_name"],
            "values": normalized,
            "limitations": [
                "No save offsets or binary serialization are inferred.",
                "class:N references remain opaque managed identities.",
            ],
        }

    def edit_values(self, data: bytes, values: dict[str, object]) -> bytes:
        import json

        envelope = self._decode(data)
        envelope["values"] = validate_halo_metadata_values(envelope["type_name"], values)
        return (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")


class EditorRegistry:
    def __init__(self) -> None:
        self._plugins: list[EditorPlugin] = []

    def register(self, plugin: EditorPlugin) -> None:
        if any(existing.name == plugin.name for existing in self._plugins):
            raise ValueError(f"editor already registered: {plugin.name}")
        self._plugins.append(plugin)

    def resolve(self, context: EditorContext, data: bytes) -> EditorPlugin | None:
        for plugin in self._plugins:
            if plugin.can_edit(context, data):
                return plugin
        return None

    def names(self) -> tuple[str, ...]:
        return tuple(plugin.name for plugin in self._plugins)


def default_registry() -> EditorRegistry:
    registry = EditorRegistry()
    registry.register(XdbfEditor())
    registry.register(ManagedSurfaceEditor())
    registry.register(AccountEditor())
    registry.register(HaloMetadataEditor())
    return registry

