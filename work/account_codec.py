"""Explicit Account-payload bridge for an authorized class3 save provider.

REA establishes the native call shapes but not the key format or decrypted
Account serialization.  This module connects the opaque STFS Account payload
to that provider boundary without loading ``class3.dll`` or persisting keys.
"""

from __future__ import annotations

from dataclasses import dataclass

from .native_save import NativeSaveBinding, UInt32Ref


@dataclass(frozen=True)
class AccountCodec:
    binding: NativeSaveBinding

    def decrypt(self, payload: bytes, key: bytes, output_capacity: int) -> bytes:
        _validate_payload(payload)
        _validate_capacity(output_capacity)
        output = bytearray(output_capacity)
        length = UInt32Ref(output_capacity)
        self.binding.decrypt(payload, length, output, len(payload), key)
        if length.value > len(output):
            raise ValueError("save provider returned a length beyond the output buffer")
        return bytes(output[: length.value])

    def encrypt(self, plaintext: bytes, key: bytes, output_capacity: int) -> bytes:
        _validate_payload(plaintext)
        _validate_capacity(output_capacity)
        output = bytearray(output_capacity)
        result = self.binding.encrypt(plaintext, output, len(plaintext), key)
        # The native declaration has no output-length reference.  Providers
        # must return the number of valid bytes, which avoids guessing a
        # serialized Account size.
        if not isinstance(result, int) or isinstance(result, bool) or not 0 <= result <= len(output):
            raise ValueError("save provider returned an invalid encrypted length")
        return bytes(output[:result])


def _validate_payload(payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise TypeError("Account payload must be bytes")


def _validate_capacity(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("output_capacity must be a non-negative integer")

