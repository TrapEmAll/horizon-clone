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
    "SignOption": (
        "Ep1_68th_Annual_Deerfest",
        "Ep2_Have_You_Seen_This_Main",
        "Ep2_Skeleton_of_Columbian_Mammoth",
        "Ep2_Moonshine_Cave",
        "Ep2_The_Great_Old_One",
        "Ep2_Tree_Dates_From_1846",
        "Ep3_Bright_Falls_Coal_Mine_Mountain",
        "Ep3_Gray_Peak_Gorge",
        "Ep3_Cauldron_Lake",
        "Ep4_Sundial",
        "Ep4_The_Creators_Dilemma",
        "Ep4_Welcome_To_Cauldron_Lake_Lodge",
        "Ep4_Statue_Suspended",
        "Ep4_Gods_of_Asgard",
        "Ep5_Hubert_and_Amos_Statue",
        "Ep5_Fan_Note",
        "Ep5_Church_Events",
        "Ep5_Randall_Memorial_Bridge",
        "Ep5_Power_Plant_Warning",
        "Ep5_Flood_Gate_Warning",
        "Ep5_Dam_Notice",
        "Ep6_Majestic_Motel_Outside",
        "Ep6_Majestic_Motel_Inside",
        "Ep6_Larsens_Trespass_Warning",
        "Ep6_Junk_Pile_Sign",
    ),
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
    "ProfileLoadout": {"All_Loadouts": 455},
    "SignOption": {
        name: value
        for value, name in enumerate(
            (
                "Ep1_68th_Annual_Deerfest",
                "Ep2_Have_You_Seen_This_Main",
                "Ep2_Skeleton_of_Columbian_Mammoth",
                "Ep2_Moonshine_Cave",
                "Ep2_The_Great_Old_One",
                "Ep2_Tree_Dates_From_1846",
                "Ep3_Bright_Falls_Coal_Mine_Mountain",
                "Ep3_Gray_Peak_Gorge",
                "Ep3_Cauldron_Lake",
                "Ep4_Sundial",
                "Ep4_The_Creators_Dilemma",
                "Ep4_Welcome_To_Cauldron_Lake_Lodge",
                "Ep4_Statue_Suspended",
                "Ep4_Gods_of_Asgard",
                "Ep5_Hubert_and_Amos_Statue",
                "Ep5_Fan_Note",
                "Ep5_Church_Events",
                "Ep5_Randall_Memorial_Bridge",
                "Ep5_Power_Plant_Warning",
                "Ep5_Flood_Gate_Warning",
                "Ep5_Dam_Notice",
                "Ep6_Majestic_Motel_Outside",
                "Ep6_Majestic_Motel_Inside",
                "Ep6_Larsens_Trespass_Warning",
                "Ep6_Junk_Pile_Sign",
            ),
            start=1,
        )
    },
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

