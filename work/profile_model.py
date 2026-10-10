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
    profile_id: int = 0
    favorite: bool = False

    def __post_init__(self) -> None:
        for name in ("xuid", "profile_id"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{name} must be an unsigned 64-bit integer")
        if not isinstance(self.gamer_picture, bytes):
            raise TypeError("gamer_picture must be bytes")
        if not isinstance(self.gamertag, str):
            raise TypeError("gamertag must be a string")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["gamer_picture"] = self.gamer_picture.hex()
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProfileData":
        return cls(
            from_device=bool(value.get("from_device", False)),
            xuid=int(value.get("xuid", 0)),
            gamertag=str(value.get("gamertag", "")),
            gamer_picture=bytes.fromhex(str(value.get("gamer_picture", ""))),
            profile_id=int(value.get("profile_id", 0)),
            favorite=bool(value.get("favorite", False)),
        )

