"""Explicit Account-payload bridge for an authorized class3 save provider.

REA establishes the native call shapes but not the key format or decrypted
Account serialization.  This module connects the opaque STFS Account payload
to that provider boundary without loading ``class3.dll`` or persisting keys.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Protocol

from .native_save import NativeSaveBinding, UInt32Ref


class AccountKeyProvider(Protocol):
    """Caller-owned key service; implementations must not persist keys here."""

    def get_account_key(self, operation: str, payload_sha256: str) -> bytes:
        """Return an authorized key for one opaque Account operation."""


class AccountKeyProviderUnavailable(RuntimeError):
    """Raised when an Account operation has no explicit key provider."""


@dataclass(frozen=True)
class AccountCodec:
    binding: NativeSaveBinding

    def decrypt_with_key_provider(self, payload: bytes, provider: AccountKeyProvider, output_capacity: int) -> bytes:
        """Decrypt using a caller-owned provider selected for this payload."""

        key = _provider_key(provider, "decrypt", payload)
        return self.decrypt(payload, key, output_capacity)

    def encrypt_with_key_provider(
        self,
        plaintext: bytes,
        provider: AccountKeyProvider,
        output_capacity: int,
        output_length: int | None = None,
    ) -> bytes:
        """Encrypt using a caller-owned provider selected for this plaintext."""

        key = _provider_key(provider, "encrypt", plaintext)
        return self.encrypt(plaintext, key, output_capacity, output_length)

    def decrypt(self, payload: bytes, key: bytes, output_capacity: int) -> bytes:
        _validate_payload(payload)
        _validate_capacity(output_capacity)
        output = bytearray(output_capacity)
        length = UInt32Ref(output_capacity)
        self.binding.decrypt(payload, length, output, len(payload), key)
        if length.value > len(output):
            raise ValueError("save provider returned a length beyond the output buffer")
        return bytes(output[: length.value])

    def encrypt(self, plaintext: bytes, key: bytes, output_capacity: int, output_length: int | None = None) -> bytes:
        """Return encrypted bytes when the caller supplies their known length.

        ``RtsSaveEncrypt`` has no output-length reference and REA did not
        establish that its integer return value is a byte count.  Callers
        must therefore pass the serialized output length explicitly.
        """

        _status, output = self.encrypt_raw(plaintext, key, output_capacity)
        if output_length is None:
            raise ValueError("encrypted output length is unresolved; use encrypt_raw and slice with the caller-known length")
        if not isinstance(output_length, int) or isinstance(output_length, bool) or not 0 <= output_length <= output_capacity:
            raise ValueError("output_length must fit the supplied output capacity")
        return output[:output_length]

    def encrypt_raw(self, plaintext: bytes, key: bytes, output_capacity: int) -> tuple[int, bytes]:
        """Return the native status and the complete caller-sized output buffer."""

        _validate_payload(plaintext)
        _validate_capacity(output_capacity)
        output = bytearray(output_capacity)
        result = self.binding.encrypt(plaintext, output, len(plaintext), key)
        if not isinstance(result, int) or isinstance(result, bool) or not -0x80000000 <= result <= 0x7FFFFFFF:
            raise ValueError("save provider returned an invalid status")
        return result, bytes(output)


def _validate_payload(payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise TypeError("Account payload must be bytes")


def _provider_key(provider: AccountKeyProvider, operation: str, payload: bytes) -> bytes:
    if provider is None or not callable(getattr(provider, "get_account_key", None)):
        raise AccountKeyProviderUnavailable("Account operations require an explicit key provider")
    key = provider.get_account_key(operation, hashlib.sha256(payload).hexdigest())
    if not isinstance(key, bytes) or not key:
        raise ValueError("Account key provider must return non-empty bytes")
    return key


def _validate_capacity(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("output_capacity must be a non-negative integer")

