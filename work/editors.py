"""Clean-room game-editor dispatch layer.

The registry separates shared STFS/XDBF handling from title-specific editors.
Plugins receive bytes and metadata and must return deterministic, explicit
results; no target code is loaded or executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .horizon_clone import (
    XdbfEntry,
    mutate_xdbf_achievement,
    mutate_xdbf_entry_same_size,
    mutate_xdbf_text,
    parse_xdbf,
    repack_xdbf_entries,
)


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
    return registry

