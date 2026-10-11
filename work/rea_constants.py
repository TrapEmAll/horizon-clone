"""Generic authenticated Constant catalogs extracted by REA.

The source file is a checked-in projection of REA managed-member evidence.
This module exposes its exact integer Constant rows without assigning save
offsets, registration, or title-specific serializer behavior.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class ObservedConstantCatalog:
    namespace: str
    name: str
    values: tuple[tuple[str, int], ...]

    @property
    def key(self) -> str:
        return f"{self.namespace}:{self.name}" if self.namespace else self.name


@lru_cache(maxsize=1)
def observed_constant_catalogs() -> tuple[ObservedConstantCatalog, ...]:
    path = Path(__file__).with_name("managed-constants.json")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to load REA Constant projection: {path}") from exc
    if not isinstance(rows, list):
        raise RuntimeError("REA Constant projection must contain an array")

    catalogs: list[ObservedConstantCatalog] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            continue
        namespace = row.get("namespace") if isinstance(row.get("namespace"), str) else ""
        fields = row.get("fields")
        if not isinstance(fields, list):
            continue
        values: list[tuple[str, int]] = []
        for field in fields:
            if not isinstance(field, dict):
                continue
            name, value = field.get("name"), field.get("value")
            if isinstance(name, str) and isinstance(value, int) and not isinstance(value, bool):
                values.append((name, value))
        catalogs.append(ObservedConstantCatalog(namespace, row["name"], tuple(values)))
    return tuple(catalogs)


def constant_catalog_values(key: str) -> Mapping[str, int]:
    """Return one exact REA catalog, addressed as ``namespace:name``."""

    for catalog in observed_constant_catalogs():
        if catalog.key == key:
            return dict(catalog.values)
    raise KeyError(f"unknown REA Constant catalog: {key}")


def rea_constant_catalog_report() -> dict[str, object]:
    catalogs = observed_constant_catalogs()
    return {
        "status": "metadata-only",
        "authority": "shipped-artifact",
        "source": "REA managed-constants.json projection",
        "counts": {
            "catalogs": len(catalogs),
            "catalogs_with_values": sum(bool(item.values) for item in catalogs),
            "values": sum(len(item.values) for item in catalogs),
        },
        "catalogs": [
            {
                "key": item.key,
                "namespace": item.namespace,
                "name": item.name,
                "members": [name for name, _ in item.values],
                "values": dict(item.values),
            }
            for item in catalogs
        ],
        "limitations": [
            "Constant metadata does not establish editor registration, save offsets, serializers, or console validity.",
            "Obfuscated and duplicate names remain artifact-local and are not merged or renamed.",
        ],
    }

