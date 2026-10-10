"""Observed shared Horizon catalog names.

These labels come from REA managed metadata inspection. Numeric enum values and
package offsets were not exposed by that observation and are intentionally not
invented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ObservedCatalog:
    name: str
    members: tuple[str, ...]
    values_observed: bool = False


_CATALOGS: Mapping[str, tuple[str, ...]] = {
    "ProfileLoadout": ("All_Loadouts",),
    "SaveEntryCategory": (
        "Audio",
        "Graphics",
        "Controls",
        "Unknown0",
        "Game",
        "Campaign",
        "Campaign_Level",
        "Unknown1",
        "Unknown2",
        "Unknown3",
        "Unknown4",
    ),
}


def observed_catalogs() -> tuple[ObservedCatalog, ...]:
    return tuple(
        ObservedCatalog(name=name, members=tuple(members))
        for name, members in _CATALOGS.items()
    )


def catalog_member_names(name: str) -> tuple[str, ...]:
    try:
        return tuple(_CATALOGS[name])
    except KeyError as exc:
        raise KeyError(f"unknown observed Horizon catalog: {name}") from exc

