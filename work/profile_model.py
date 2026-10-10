"""Evidence-backed profile metadata model.

The property names mirror the observed Horizon.ProfileData metadata surface,
but the model is independent and intentionally does not guess the opaque
binary layout of the Account file.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ProfileData:
    from_device: bool = False
    xuid: int = 0
    gamertag: str = ""
    gamer_picture: bytes = b""
    profile_id: bytes = b""
    favorite: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["gamer_picture"] = self.gamer_picture.hex()
        result["profile_id"] = self.profile_id.hex()
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProfileData":
        return cls(
            from_device=bool(value.get("from_device", False)),
            xuid=int(value.get("xuid", 0)),
            gamertag=str(value.get("gamertag", "")),
            gamer_picture=bytes.fromhex(str(value.get("gamer_picture", ""))),
            profile_id=bytes.fromhex(str(value.get("profile_id", ""))),
            favorite=bool(value.get("favorite", False)),
        )

