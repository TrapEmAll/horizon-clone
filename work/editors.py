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
from .profile_model import ProfileData


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
class ProfileDataEditor:
    """Validate the authenticated ``Horizon.ProfileData`` metadata contract."""

    name: str = "ProfileData metadata editor"

    @staticmethod
    def _decode(data: bytes) -> tuple[dict[str, Any], ProfileData]:
        import json

        try:
            envelope = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("ProfileData input must be UTF-8 JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("editor") != "profile-data":
            raise ValueError("expected an explicit profile-data envelope")
        values = envelope.get("values")
        if not isinstance(values, dict):
            raise ValueError("ProfileData requires an object-valued values member")
        allowed = {"from_device", "xuid", "gamertag", "gamer_picture", "profile_id", "favorite"}
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ValueError(f"unknown ProfileData members: {', '.join(unknown)}")
        try:
            profile = ProfileData.from_dict(values)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid ProfileData values: {exc}") from exc
        return envelope, profile

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        if not data.lstrip().startswith(b"{"):
            return False
        try:
            self._decode(data)
        except ValueError:
            return False
        return True

    def inspect(self, context: EditorContext, data: bytes) -> dict[str, object]:
        _envelope, profile = self._decode(data)
        return {
            "status": "metadata-only",
            "values": profile.to_dict(),
            "resource_getters": ["get_GoWJ_Thumb_New", "get_GrayDot"],
            "limitations": [
                "The six ProfileData fields are authenticated managed metadata.",
                "The opaque Account binary layout and serializer remain unresolved.",
                "Resource getter return type class:957 remains unresolved.",
            ],
        }

    def edit_values(self, data: bytes, values: dict[str, object]) -> bytes:
        import json

        envelope, _profile = self._decode(data)
        try:
            envelope["values"] = ProfileData.from_dict(values).to_dict()
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid ProfileData values: {exc}") from exc
        return (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")


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


@dataclass(frozen=True)
class ConstantCatalogEditor:
    """Validate explicit envelopes for REA-authenticated Constant tables."""

    name: str = "Authenticated Constant catalog editor"

    @staticmethod
    def _known(catalog: str) -> dict[str, int]:
        if catalog.startswith("skyrim:"):
            from .skyrim_catalog import enum_member_values

            return dict(enum_member_values(catalog.split(":", 1)[1]))
        if catalog == "gears:EntryID":
            from .gears_catalog import gears_entry_id_values

            return gears_entry_id_values()
        if catalog.startswith("shared:"):
            from .horizon_catalog import catalog_member_values

            return dict(catalog_member_values(catalog.split(":", 1)[1]))
        if catalog.startswith("global:"):
            from .global_catalog import global_catalog_report

            values = global_catalog_report()["values"]
            try:
                return dict(values[catalog.split(":", 1)[1]])
            except KeyError as exc:
                raise KeyError(f"unknown authenticated global catalog: {catalog}") from exc
        raise KeyError(f"unknown authenticated Constant catalog: {catalog}")

    @classmethod
    def _decode(cls, data: bytes) -> tuple[dict[str, Any], dict[str, int]]:
        import json

        try:
            envelope = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Constant catalog input must be UTF-8 JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("editor") != "constant-catalog":
            raise ValueError("expected an explicit constant-catalog envelope")
        catalog = envelope.get("catalog")
        values = envelope.get("values")
        if not isinstance(catalog, str) or not isinstance(values, dict):
            raise ValueError("Constant catalog requires catalog and object values")
        return envelope, cls._known(catalog)

    @classmethod
    def _validate(cls, values: dict[str, object], known: dict[str, int]) -> dict[str, int]:
        unknown = sorted(set(values) - set(known))
        if unknown:
            raise ValueError(f"unknown Constant members: {', '.join(unknown)}")
        result: dict[str, int] = {}
        for name, value in values.items():
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"Constant member {name} must be an integer")
            if value != known[name]:
                raise ValueError(f"Constant member {name} must equal authenticated value {known[name]}")
            result[name] = value
        return result

    def can_edit(self, context: EditorContext, data: bytes) -> bool:
        if not data.lstrip().startswith(b"{"):
            return False
        try:
            self._decode(data)
        except (KeyError, TypeError, ValueError):
            return False
        return True

    def inspect(self, context: EditorContext, data: bytes) -> dict[str, object]:
        envelope, known = self._decode(data)
        return {
            "status": "metadata-only",
            "catalog": envelope["catalog"],
            "values": self._validate(envelope["values"], known),
            "limitations": ["No binary save offsets or serialization are inferred."],
        }

    def edit_values(self, data: bytes, values: dict[str, object]) -> bytes:
        import json

        envelope, known = self._decode(data)
        envelope["values"] = self._validate(values, known)
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
    registry.register(ProfileDataEditor())
    registry.register(HaloMetadataEditor())
    registry.register(ConstantCatalogEditor())
    return registry

