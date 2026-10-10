"""REA-observed global-namespace managed type surface.

Horizon places several title catalogs in the empty CLR namespace. Names alone
are not unique there, so this module preserves each observed metadata row as a
separate record instead of collapsing same-named types or inventing enum
values. It is a structural catalog, not a save-file editor.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ObservedGlobalType:
    name: str
    field_count: int
    method_count: int = 0
    value_field_observed: bool = True


_GLOBAL_TYPES = (
    ObservedGlobalType("FormID", 4100),
    ObservedGlobalType("Helmet", 65),
    ObservedGlobalType("Helmet", 87),
    ObservedGlobalType("Torso", 82),
    ObservedGlobalType("LeftShoulder", 19),
    ObservedGlobalType("LeftShoulder", 82),
    ObservedGlobalType("RightShoulder", 19),
    ObservedGlobalType("RightShoulder", 82),
    ObservedGlobalType("EmblemForeground", 118),
    ObservedGlobalType("EmblemBackground", 59),
    ObservedGlobalType("ManuscriptPage", 107),
    ObservedGlobalType("CoffeeThermosOption", 101),
    ObservedGlobalType("CategoryEntry", 3, 8),
    ObservedGlobalType("EntryOption", 4, 10),
    ObservedGlobalType("InterfaceDefinitionGoof", 2, 6),
    ObservedGlobalType("InterfaceDefinitionSily", 6, 14),
    ObservedGlobalType("MegaloCollection", 2, 6),
    ObservedGlobalType("MegaloObject", 8, 18),
    ObservedGlobalType("MenuLocationEntry", 4, 7),
    ObservedGlobalType("SilyValue", 4, 12),
    ObservedGlobalType("ArmorEffect", 8),
    ObservedGlobalType("AssaultRifle", 4),
    ObservedGlobalType("Chest", 19),
    ObservedGlobalType("ChestsOption", 31),
    ObservedGlobalType("COGCharacter", 31),
    ObservedGlobalType("FirefightVoice", 13),
    ObservedGlobalType("Forearms", 27),
    ObservedGlobalType("KneeGuards", 5),
    ObservedGlobalType("Legs", 26),
    ObservedGlobalType("LocusCharacter", 23),
    ObservedGlobalType("PrimaryWeapon", 34),
    ObservedGlobalType("PrimaryWeapon", 38),
    ObservedGlobalType("SecondaryWeapon", 12),
    ObservedGlobalType("Weapon", 11),
    ObservedGlobalType("Weapon", 38),
)

_OBSERVED_CONSTANT_VALUES = {
    "GeneralContentTypes": {
        "Games": 0,
        "Gamer_Profiles": 1,
        "Demos": 2,
        "Videos": 3,
        "Themes": 4,
        "Gamer_Pictures": 5,
        "Avatar_Items": 6,
        "Title_Updates": 7,
        "System_Items": 8,
    },
    "DifficultyOption": {"Easy": 0, "Normal": 1, "Hard": 2},
    "XOnlineLanguage": {
        "Null": 0, "English": 1, "Japanese": 2, "German": 3,
        "French": 4, "Spanish": 5, "Italian": 6, "Korean": 7,
        "Chinese": 8, "Portuguese": 9, "Chinese2": 10, "Polish": 11,
        "Russian": 12, "Danish": 13, "Finnish": 14, "Norwegian": 15,
        "Dutch": 16, "Swedish": 17, "Czech": 18, "Greek": 19,
        "Hungarian": 20,
    },
    "XOnlineTierType": {
        "XOnlineTierInvalid": 0,
        "XOnlineTierSilver": 3,
        "XOnlineTierGold": 6,
        "XOnlineTierFamilyGold": 9,
    },
    "XOnlinePassCodeTypes": {
        "XOnlinePassCodeNone": 0,
        "XOnlinePassCodeDpadUp": 1,
        "XOnlinePassCodeDpadDown": 2,
        "XOnlinePassCodeDpadLeft": 3,
        "XOnlinePassCodeDpadRight": 4,
        "XOnlinePassCodeGamepadX": 5,
        "XOnlinePassCodeGamepadY": 6,
        "XOnlinePassCodeGamepadLeftTrigger": 9,
        "XOnlinePassCodeGamepadRightTrigger": 10,
        "XOnlinePassCodeGamepadLeftShoulder": 11,
        "XOnlinePassCodeGamepadRightShoulder": 12,
    },
    "XGearSlot": {
        "Null": 0,
        "Hat": 10,
        "Shirt": 11,
        "Boots": 12,
        "Pants": 13,
    },
}


def observed_global_types() -> tuple[ObservedGlobalType, ...]:
    """Return the authenticated subset without deduplicating metadata rows."""

    return _GLOBAL_TYPES


def global_catalog_report() -> dict[str, object]:
    """Return structural global-namespace coverage and explicit limits."""

    return {
        "status": "catalog-only",
        "namespace": "",
        "observed_namespace_type_count": 632,
        "observed_namespace_field_count": 8549,
        "observed_namespace_method_count": 2225,
        "reported_rows": [asdict(item) for item in _GLOBAL_TYPES],
        "values_observed": True,
        "values": {name: dict(values) for name, values in _OBSERVED_CONSTANT_VALUES.items()},
        "save_layouts_observed": False,
        "limitations": [
            "The report is a selected title-facing subset of the 632 global-namespace rows.",
            "Same-named rows are distinct and must not be merged without a fixture.",
            "Only the explicitly listed Constant rows have authenticated numeric values; other labels do not establish values or save offsets.",
        ],
    }

