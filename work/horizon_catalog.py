"""Observed shared Horizon catalog names.

These labels come from REA managed metadata inspection. Numeric values are
included only for the Constant rows recovered by the authenticated metadata
extractor; package offsets remain intentionally unresolved.
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

_CONSTANT_VALUES: Mapping[str, Mapping[str, int]] = {
    "SaveEntryCategory": {
        "Audio": 0,
        "Graphics": 1,
        "Controls": 2,
        "Unknown0": 3,
        "Game": 4,
        "Campaign": 5,
        "Campaign_Level": 6,
        "Unknown1": 7,
        "Unknown2": 8,
        "Unknown3": 9,
        "Unknown4": 10,
    },
}


def observed_catalogs() -> tuple[ObservedCatalog, ...]:
    return tuple(
        ObservedCatalog(
            name=name,
            members=tuple(members),
            values_observed=name in _CONSTANT_VALUES,
        )
        for name, members in _CATALOGS.items()
    )


def catalog_member_names(name: str) -> tuple[str, ...]:
    try:
        return tuple(_CATALOGS[name])
    except KeyError as exc:
        raise KeyError(f"unknown observed Horizon catalog: {name}") from exc


def catalog_member_values(name: str) -> Mapping[str, int]:
    """Return authenticated Constant values for a shared catalog."""

    try:
        return dict(_CONSTANT_VALUES[name])
    except KeyError as exc:
        if name in _CATALOGS:
            return {}
        raise KeyError(f"unknown observed Horizon catalog: {name}") from exc

