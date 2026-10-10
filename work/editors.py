"""Clean-room game-editor dispatch layer.

The registry separates shared STFS/XDBF handling from title-specific editors.
Plugins receive bytes and metadata and must return deterministic, explicit
results; no target code is loaded or executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .horizon_clone import XdbfEntry, parse_xdbf


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

