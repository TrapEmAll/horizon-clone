"""Observed managed-member contracts from Horizon's public metadata surface."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ObservedField:
    declaring_type: str
    name: str
    field_type: str


@dataclass(frozen=True)
class ObservedMethod:
    declaring_type: str
    name: str
    parameter_types: tuple[str, ...]
    return_type: str


_PROFILE_DATA_FIELDS = (
    ObservedField("Horizon.ProfileData", "FromDevice", "bool"),
    ObservedField("Horizon.ProfileData", "XUID", "u8"),
    ObservedField("Horizon.ProfileData", "Gamertag", "string"),
    ObservedField("Horizon.ProfileData", "Gamerpicture", "u1[]"),
    ObservedField("Horizon.ProfileData", "ProfileId", "u8"),
    ObservedField("Horizon.ProfileData", "Favorite", "bool"),
)


_PROFILE_DATA_METHODS = (
    ObservedMethod("Horizon.ProfileData", "get_GoWJ_Thumb_New", (), "class:957"),
    ObservedMethod("Horizon.ProfileData", "get_GrayDot", (), "class:957"),
)


def observed_profile_data_fields() -> tuple[ObservedField, ...]:
    return _PROFILE_DATA_FIELDS


def observed_profile_data_methods() -> tuple[ObservedMethod, ...]:
    """Return the two REA-observed ProfileData resource getters.

    ``class:957`` is retained as REA's unresolved managed type identity; it is
    not treated as a decoded bitmap or as an Account-file field.
    """
    return _PROFILE_DATA_METHODS


def observed_fields(declaring_type: str) -> tuple[ObservedField, ...]:
    fields = tuple(item for item in _PROFILE_DATA_FIELDS if item.declaring_type == declaring_type)
    if not fields:
        raise KeyError(f"unknown observed declaring type: {declaring_type}")
    return fields

