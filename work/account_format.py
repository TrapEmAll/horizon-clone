"""Historical-reference Account obfuscation and the authenticated 380-byte body.

REA authenticated the supplied 404-byte Account boundary but did not expose
the Account type or serializer.  The field layout and XeKeys RC4/HMAC
construction here are isolated from the native class3 bridge and are labeled
as historical-reference evidence.  Callers must provide the 16-byte key
explicitly; no key material is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets


ACCOUNT_PLAIN_LENGTH = 380
ACCOUNT_ENCRYPTED_LENGTH = 404


def _rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Account obfuscation key must be non-empty")
    state = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[cursor] = state[cursor], state[index]
    left = right = 0
    result = bytearray()
    for value in data:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        result.append(value ^ state[(state[left] + state[right]) & 0xFF])
    return bytes(result)


def _hmac16(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Account obfuscation key must be exactly 16 bytes")
    return hmac.new(key, data, hashlib.sha1).digest()[:16]


def unobfuscate_account(data: bytes, key: bytes) -> bytes:
    """Authenticate and decode a 404-byte Account payload."""

    if not isinstance(data, bytes):
        raise TypeError("Account data must be bytes")
    if len(data) != ACCOUNT_ENCRYPTED_LENGTH:
        raise ValueError(f"Account data must be {ACCOUNT_ENCRYPTED_LENGTH} bytes")
    header, encrypted_body = data[:16], data[16:]
    body = _rc4(encrypted_body, _hmac16(key, header))
    if not hmac.compare_digest(_hmac16(key, body), header):
        raise ValueError("Account HMAC validation failed")
    plain = body[8:]
    if len(plain) != ACCOUNT_PLAIN_LENGTH:
        raise ValueError("Account plaintext has an invalid length")
    return plain


def obfuscate_account(plain: bytes, key: bytes, *, confounder: bytes | None = None) -> bytes:
    """Encode a 380-byte Account body with a caller-supplied key."""

    if not isinstance(plain, bytes):
        raise TypeError("Account plaintext must be bytes")
    if len(plain) != ACCOUNT_PLAIN_LENGTH:
        raise ValueError(f"Account plaintext must be {ACCOUNT_PLAIN_LENGTH} bytes")
    if confounder is None:
        confounder = secrets.token_bytes(8)
    if not isinstance(confounder, bytes) or len(confounder) != 8:
        raise ValueError("Account confounder must be exactly 8 bytes")
    body = confounder + plain
    header = _hmac16(key, body)
    return header + _rc4(body, _hmac16(key, header))


def _read_ascii(data: bytes, start: int, length: int) -> str:
    return data[start : start + length].split(bytes([0]), 1)[0].decode("ascii", errors="replace")


def _write_ascii(value: str, length: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Account text fields must be strings")
    encoded = value.encode("ascii")
    if len(encoded) > length:
        raise ValueError(f"Account text field exceeds {length} bytes")
    return encoded.ljust(length, bytes([0]))


@dataclass
class AccountRecord:
    """The historical 380-byte Account body, with fixed-width fields."""

    reserved: int = 0
    live_flags: int = 0
    gamertag: str = ""
    xuid_online: int = 0
    cached_user_flags: int = 0
    online_service_network_id: int = 0
    passcode: bytes = bytes([0]) * 4
    online_domain: str = ""
    online_kerberos_realm: str = ""
    online_key: bytes = bytes([0]) * 16
    user_passport_membername: str = ""
    user_passport_password: str = ""
    owner_passport_membername: str = ""

    @classmethod
    def from_bytes(cls, data: bytes) -> "AccountRecord":
        if not isinstance(data, bytes) or len(data) != ACCOUNT_PLAIN_LENGTH:
            raise ValueError(f"Account plaintext must be {ACCOUNT_PLAIN_LENGTH} bytes")
        gamertag = data[8:40].decode("utf-16-be", errors="replace").rstrip(chr(0))
        return cls(
            int.from_bytes(data[0:4], "big"),
            int.from_bytes(data[4:8], "big"),
            gamertag,
            int.from_bytes(data[40:48], "big"),
            int.from_bytes(data[48:52], "big"),
            int.from_bytes(data[52:56], "big"),
            data[56:60],
            _read_ascii(data, 60, 20),
            _read_ascii(data, 80, 24),
            data[104:120],
            _read_ascii(data, 120, 114),
            _read_ascii(data, 234, 32),
            _read_ascii(data, 266, 114),
        )

    def to_bytes(self) -> bytes:
        if not isinstance(self.gamertag, str) or len(self.gamertag) > 16:
            raise ValueError("Account gamertag must fit 16 UTF-16 code units")
        if not isinstance(self.passcode, bytes) or len(self.passcode) != 4:
            raise ValueError("Account passcode must be exactly 4 bytes")
        if not isinstance(self.online_key, bytes) or len(self.online_key) != 16:
            raise ValueError("Account online key must be exactly 16 bytes")
        for name, value in (("live_flags", self.live_flags), ("reserved", self.reserved), ("xuid_online", self.xuid_online), ("cached_user_flags", self.cached_user_flags), ("online_service_network_id", self.online_service_network_id)):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << (64 if name == "xuid_online" else 32)):
                raise ValueError(f"Account {name} is out of range")
        result = bytearray()
        result.extend(self.reserved.to_bytes(4, "big"))
        result.extend(self.live_flags.to_bytes(4, "big"))
        result.extend(self.gamertag.encode("utf-16-be").ljust(32, bytes([0])))
        result.extend(self.xuid_online.to_bytes(8, "big"))
        result.extend(self.cached_user_flags.to_bytes(4, "big"))
        result.extend(self.online_service_network_id.to_bytes(4, "big"))
        result.extend(self.passcode)
        result.extend(_write_ascii(self.online_domain, 20))
        result.extend(_write_ascii(self.online_kerberos_realm, 24))
        result.extend(self.online_key)
        result.extend(_write_ascii(self.user_passport_membername, 114))
        result.extend(_write_ascii(self.user_passport_password, 32))
        result.extend(_write_ascii(self.owner_passport_membername, 114))
        return bytes(result)

