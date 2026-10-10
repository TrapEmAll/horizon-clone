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
)


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
        "values_observed": False,
        "save_layouts_observed": False,
        "limitations": [
            "The report is a selected title-facing subset of the 632 global-namespace rows.",
            "Same-named rows are distinct and must not be merged without a fixture.",
            "Metadata enum labels do not establish numeric values or save offsets.",
        ],
    }

