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


def observed_legacy_catalogs() -> tuple[LegacyCatalog, ...]:
    return _CATALOGS


def legacy_catalog_report() -> dict[str, object]:
    return {
        "status": "catalog-only",
        "catalogs": [
            {
                **asdict(item),
                "types": [{"name": name, "field_count": count} for name, count in item.types],
                "type_count": item.type_count,
                "field_count": item.field_count,
            }
            for item in _CATALOGS
        ],
        "unresolved": ["enum values", "save offsets", "binary layouts", "editor mutation behavior"],
    }

