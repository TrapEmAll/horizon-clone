"""Observed managed-member contracts from Horizon's public metadata surface."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ObservedField:
    declaring_type: str
    name: str
    field_type: str


_PROFILE_DATA_FIELDS = (
    ObservedField("Horizon.ProfileData", "FromDevice", "bool"),
    ObservedField("Horizon.ProfileData", "XUID", "u8"),
    ObservedField("Horizon.ProfileData", "Gamertag", "string"),
    ObservedField("Horizon.ProfileData", "Gamerpicture", "u1[]"),
    ObservedField("Horizon.ProfileData", "ProfileId", "u8"),
    ObservedField("Horizon.ProfileData", "Favorite", "bool"),
)


def observed_profile_data_fields() -> tuple[ObservedField, ...]:
    return _PROFILE_DATA_FIELDS


def observed_fields(declaring_type: str) -> tuple[ObservedField, ...]:
    fields = tuple(item for item in _PROFILE_DATA_FIELDS if item.declaring_type == declaring_type)
    if not fields:
        raise KeyError(f"unknown observed declaring type: {declaring_type}")
    return fields

