"""Small, provider-oriented RSA primitives for authorized test environments.

This module deliberately does not know or contain Xbox retail keys.  Package
format code supplies the exact signed bytes and an authorized provider supplies
the key material.  The implementation is useful for deterministic test
vectors and for integrating a separately managed development signing service.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol


SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


@dataclass(frozen=True)
class RsaPublicKey:
    modulus: int
    exponent: int = 65537


@dataclass(frozen=True)
class RsaPrivateKey:
    modulus: int
    private_exponent: int


class SigningProvider(Protocol):
    """Authorized provider boundary; implementations must keep secrets local."""

    def sign_sha256(self, message: bytes) -> bytes:
        ...


@dataclass(frozen=True)
class LocalRsaSha256Signer:
    key: RsaPrivateKey

    def sign_sha256(self, message: bytes) -> bytes:
        digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
        size = (self.key.modulus.bit_length() + 7) // 8
        if len(digest_info) + 11 > size:
            raise ValueError("RSA modulus is too short for SHA-256 PKCS#1 v1.5")
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
        return pow(int.from_bytes(encoded, "big"), self.key.private_exponent, self.key.modulus).to_bytes(size, "big")


def verify_sha256_pkcs1v15(message: bytes, signature: bytes, key: RsaPublicKey) -> bool:
    """Verify a detached SHA-256 RSA PKCS#1 v1.5 signature."""
    size = (key.modulus.bit_length() + 7) // 8
    if len(signature) != size or key.modulus <= 0 or key.exponent <= 1:
        return False
    encoded = pow(int.from_bytes(signature, "big"), key.exponent, key.modulus).to_bytes(size, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return encoded == expected


def sign_with_provider(message: bytes, provider: SigningProvider) -> bytes:
    """Sign bytes through an explicitly supplied authorized provider."""
    signature = provider.sign_sha256(message)
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("signing provider returned no signature bytes")
    return signature

