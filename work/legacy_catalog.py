"""REA-observed catalogs for additional Horizon title-editor families.

Only managed type names and field counts are authenticated here.  REA did not
expose enum values, save offsets, or editor behavior for these types.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class LegacyCatalog:
    name: str
    namespace: str
    types: tuple[tuple[str, int], ...]

    @property
    def type_count(self) -> int:
        return len(self.types)

    @property
    def field_count(self) -> int:
        return sum(count for _, count in self.types)


_CATALOGS = (
    LegacyCatalog("Dragon Ball Xenoverse", "Bandai", (("DBXVAttributes", 7),)),
    LegacyCatalog("Code Veronica X", "Capcom", (("CodeVeronicaXCharacters", 5),)),
    LegacyCatalog("Devil May Cry", "DevilMayCry", (("MissionDifficulty", 8),)),
    LegacyCatalog(
        "Ninja Gaiden 3",
        "NinjaGaiden",
        (("NinjaGaiden3SkillRyu", 46), ("NinjaGaiden3SkillsAyane", 21)),
    ),
    LegacyCatalog("State of Decay", "StateofDecay", (("StateofDecayGameMode", 4),)),
    LegacyCatalog("Castle Crashers", "TheBehemoth", (("CastleCrashersCharacters", 32),)),
    LegacyCatalog(
        "Saints Row",
        "Volition",
        (("MultipliersTypes", 9), ("SRGOOHPowersEnum", 9), ("SRIVPowersEnum", 9)),
    ),
)


_FIELD_NAMES = {
    ("Bandai", "DBXVAttributes"): ("value__", "MaxHealth", "MaxKi", "BasicAttacks", "StrikeSupers", "KiBlastSupers", "MaxStamina"),
    ("Capcom", "CodeVeronicaXCharacters"): ("value__", "Claire", "Chris", "Steve", "Wesker"),
    ("DevilMayCry", "MissionDifficulty"): ("value__", "Human", "DevilHunter", "Nephilim", "SonOfSparda", "DanteMustDie", "HeavenOrHell", "HellAndHell"),
    ("NinjaGaiden", "NinjaGaiden3SkillRyu"): ("value__", "ExtraHealth1", "ExtraHealth2", "ExtraHealth3", "ExtraHealth4", "ExtraHealth5", "CounterAttack", "FourRings", "GuillotineThrow", "CicadaSurge", "Meditation", "FlyingSwallow", "WindPath", "FalconsEye", "DragonSword1", "DragonSword2", "DragonSword3", "FalconsTalons1", "FalconsTalons2", "FalconsTalons3", "EclipseScythe1", "EclipseScythe2", "EclipseScythe3", "DualKatana1", "DualKatana2", "DualKatana3", "LunarStaff1", "LunarStaff2", "LunarStaff3", "KusariGama1", "KusariGama2", "KusariGama3", "Inferno1", "Inferno2", "Inferno3", "TrueInferno", "WindBlades1", "WindBlades2", "WindBlades3", "PiercingVoid1", "PiercingVoid2", "PiercingVoid3", "LegendaryBlackFalcon", "TraditionalDarkBlue", "DragonMuscleSuit", "FiendHayabusa"),
    ("NinjaGaiden", "NinjaGaiden3SkillsAyane"): ("value__", "ExtraHealth1", "ExtraHealth2", "ExtraHealth3", "ExtraHealth4", "ExtraHealth5", "CounterAttack", "GuillotineThrow", "FlyingSwallow", "WindPath", "Meditation", "FumaKodachi1", "FumaKodachi2", "FumaKodachi3", "RagingMountainGod1", "RagingMountainGod2", "RagingMountainGod3", "NocturnalButterFly", "PhantomButterFly", "BlossomOfMiyama", "RagingGodNineOfViolet"),
    ("StateofDecay", "StateofDecayGameMode"): ("value__", "Default", "Breakdown", "Lifeline"),
    ("TheBehemoth", "CastleCrashersCharacters"): ("value__", "Green_Knight", "Red_Knight", "Blue_Knight", "Orange_Knight", "Gray_Knight", "Barbarian", "Thief", "Fencer", "Beekeeper", "Gear_Knight", "Alien_Hominid", "The_King", "Brute", "Druic_Knight", "Saracen", "Royal_Guard", "Black_Knight", "Peasant", "Bear_Shaman", "Necromancer", "Periwinkle_Knight", "Civilian", "Unmasked_Gray_Knight", "Fire_Demon", "Skeleton", "Eskimo", "Ninja", "Wizard_Mage", "Pink_Knight", "Black_Smith", "Hatty_Hattington"),
    ("Volition", "MultipliersTypes"): ("value__", "NotorietyDecayRate", "SmallArmsDamageRate", "ExplosiveDamageRate", "FireDamageRate", "SprintBonus", "XPMultiplier", "MeleeStrength", "HourlyCacheTransferRate"),
    ("Volition", "SRGOOHPowersEnum"): ("value__", "Summons", "Stomp", "Aura", "Blast", "ForceShield", "SuperSprint", "Flight", "DeathFromAbove"),
    ("Volition", "SRIVPowersEnum"): ("value__", "Telekinesis", "Stomp", "Buff", "Blast", "ForceShield", "SuperSprint", "SuperJump", "DeathFromAbove"),
}


def observed_legacy_catalogs() -> tuple[LegacyCatalog, ...]:
    return _CATALOGS


def legacy_field_names(namespace: str, type_name: str) -> tuple[str, ...]:
    try:
        return _FIELD_NAMES[(namespace, type_name)]
    except KeyError as exc:
        raise KeyError(f"unknown observed legacy type: {namespace}.{type_name}") from exc


def legacy_catalog_report() -> dict[str, object]:
    return {
        "status": "catalog-only",
        "catalogs": [
            {
                **asdict(item),
                "types": [
                    {
                        "name": name,
                        "field_count": count,
                        "field_names": list(legacy_field_names(item.namespace, name)),
                        "named_member_count": count - 1,
                        "value_field_observed": "value__" in legacy_field_names(item.namespace, name),
                        "backing_type": "i4",
                    }
                    for name, count in item.types
                ],
                "type_count": item.type_count,
                "field_count": item.field_count,
            }
            for item in _CATALOGS
        ],
        "unresolved": ["enum values", "save offsets", "binary layouts", "editor mutation behavior"],
    }

