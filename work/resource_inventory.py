"""REA-observed embedded resource surface for Horizon.exe.

These are authenticated artifact-level counts only. The module does not copy
or execute shipped resources and does not infer which resource belongs to a
specific UI feature.
"""

from __future__ import annotations


def observed_resource_surface() -> dict[str, int]:
    return {
        "resource_count": 205,
        "total_bytes": 4_017_795,
        "distinct_payload_hashes": 30,
        "embedded_resource_count": 205,
    }

