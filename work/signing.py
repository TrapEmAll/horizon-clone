"""Small, provider-oriented RSA primitives for authorized test environments.

This module deliberately does not know or contain Xbox retail keys.  Package
format code supplies the exact signed bytes and an authorized provider supplies
the key material.  The implementation is useful for deterministic test
vectors and for integrating a separately managed development signing service.
"""

from __future__ import annotations

import hashlib
import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
SHA1_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3021300906052b0e03021a05000414"
)


@dataclass(frozen=True)
class RsaPublicKey:
    modulus: int
    exponent: int = 65537


@dataclass(frozen=True)
class RsaPrivateKey:
    modulus: int
    private_exponent: int


@dataclass(frozen=True)
class SignedRegion:
    """Caller-labeled bytes presented to an authorized signing provider."""

    label: str
    data: bytes


@dataclass(frozen=True)
class DetachedSignature:
    """A detached development signature and the algorithm used to make it."""

    region_label: str
    algorithm: str
    signature: bytes


class SigningProvider(Protocol):
    """Authorized provider boundary; implementations must keep secrets local."""

    def sign_sha256(self, message: bytes) -> bytes:
        ...


@dataclass(frozen=True)
class LocalRsaSha256Signer:
    key: RsaPrivateKey

    def sign_sha256(self, message: bytes) -> bytes:
        _validate_message(message)
        _validate_private_key(self.key)
        digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
        size = (self.key.modulus.bit_length() + 7) // 8
        if len(digest_info) + 11 > size:
            raise ValueError("RSA modulus is too short for SHA-256 PKCS#1 v1.5")
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
        return pow(int.from_bytes(encoded, "big"), self.key.private_exponent, self.key.modulus).to_bytes(size, "big")


@dataclass(frozen=True)
class LocalRsaSha1Signer:
    """Sign SHA-1 PKCS#1 v1.5 bytes with an explicitly supplied key."""

    key: RsaPrivateKey

    def sign_sha1(self, message: bytes) -> bytes:
        _validate_message(message)
        _validate_private_key(self.key)
        digest_info = SHA1_DIGEST_INFO_PREFIX + hashlib.sha1(message).digest()
        size = (self.key.modulus.bit_length() + 7) // 8
        if len(digest_info) + 11 > size:
            raise ValueError("RSA modulus is too short for SHA-1 PKCS#1 v1.5")
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
        return pow(int.from_bytes(encoded, "big"), self.key.private_exponent, self.key.modulus).to_bytes(size, "big")


class CommandSha1SigningProvider:
    """Call an authorized external signing/key-vault helper without persisting keys."""

    def __init__(self, executable: str | Path, timeout: float = 30.0) -> None:
        path = Path(executable)
        if not path.is_absolute():
            raise ValueError("signing helper path must be absolute")
        if not path.is_file():
            raise FileNotFoundError(path)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("signing helper timeout must be positive")
        self.executable = path
        self.timeout = timeout

    def sign_sha1(self, message: bytes) -> bytes:
        if not isinstance(message, bytes):
            raise TypeError("signing message must be bytes")
        completed = subprocess.run(
            [str(self.executable)],
            input=json.dumps({
                "algorithm": "RSA-SHA1-PKCS1v1.5",
                "message_base64": base64.b64encode(message).decode("ascii"),
            }),
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode:
            raise OSError("signing helper failed")
        try:
            result = json.loads(completed.stdout)
            signature = base64.b64decode(result["signature_base64"], validate=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            raise ValueError("signing helper returned malformed signature JSON") from exc
        if not signature:
            raise ValueError("signing helper returned an empty signature")
        return signature


def verify_sha256_pkcs1v15(message: bytes, signature: bytes, key: RsaPublicKey) -> bool:
    """Verify a detached SHA-256 RSA PKCS#1 v1.5 signature."""
    _validate_message(message)
    return _verify_pkcs1v15(message, signature, key, hashlib.sha256, SHA256_DIGEST_INFO_PREFIX)


def verify_sha1_pkcs1v15(message: bytes, signature: bytes, key: RsaPublicKey) -> bool:
    """Verify a detached SHA-1 RSA PKCS#1 v1.5 signature."""
    _validate_message(message)
    return _verify_pkcs1v15(message, signature, key, hashlib.sha1, SHA1_DIGEST_INFO_PREFIX)


def verify_xecrypt_sha1_pkcs1v15(message: bytes, signature: bytes, key: RsaPublicKey) -> bool:
    """Verify the byte-reversed SHA-1 PKCS#1 encoding used by XeCrypt."""

    _validate_message(message)
    _validate_signature(signature)
    return verify_sha1_pkcs1v15(message, signature[::-1], key)


def _verify_pkcs1v15(message: bytes, signature: bytes, key: RsaPublicKey, digest_algorithm: object, digest_info_prefix: bytes) -> bool:
    _validate_signature(signature)
    if not isinstance(key, RsaPublicKey):
        raise TypeError("key must be an RsaPublicKey")
    if (
        not isinstance(key.modulus, int)
        or isinstance(key.modulus, bool)
        or not isinstance(key.exponent, int)
        or isinstance(key.exponent, bool)
    ):
        return False
    digest = digest_algorithm(message).digest()
    size = (key.modulus.bit_length() + 7) // 8
    minimum_size = len(digest_info_prefix) + len(digest) + 11
    if (
        len(signature) != size
        or key.modulus <= 0
        or key.exponent <= 1
        or size < minimum_size
        or int.from_bytes(signature, "big") >= key.modulus
    ):
        return False
    encoded = pow(int.from_bytes(signature, "big"), key.exponent, key.modulus).to_bytes(size, "big")
    digest_info = digest_info_prefix + digest
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return encoded == expected


def _validate_message(message: bytes) -> None:
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")


def _validate_signature(signature: bytes) -> None:
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")


def _validate_private_key(key: RsaPrivateKey) -> None:
    if not isinstance(key, RsaPrivateKey):
        raise TypeError("key must be an RsaPrivateKey")
    if (
        not isinstance(key.modulus, int)
        or isinstance(key.modulus, bool)
        or not isinstance(key.private_exponent, int)
        or isinstance(key.private_exponent, bool)
    ):
        raise TypeError("RSA private key values must be integers")
    if key.modulus <= 1 or key.private_exponent <= 0:
        raise ValueError("RSA private key values are out of range")


def sign_with_provider(message: bytes, provider: SigningProvider) -> bytes:
    """Sign bytes through an explicitly supplied authorized provider."""
    signature = provider.sign_sha256(message)
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("signing provider returned no signature bytes")
    return signature


def sign_region(region: SignedRegion, provider: SigningProvider) -> DetachedSignature:
    """Sign explicitly supplied bytes without inferring a package layout."""
    if not region.label.strip():
        raise ValueError("signed region label cannot be empty")
    return DetachedSignature(
        region_label=region.label,
        algorithm="RSA-SHA256-PKCS1v1.5",
        signature=sign_with_provider(region.data, provider),
    )


def verify_region(
    region: SignedRegion,
    detached: DetachedSignature,
    key: RsaPublicKey,
) -> bool:
    """Verify a detached signature only when its caller label matches."""
    if detached.region_label != region.label:
        return False
    if detached.algorithm == "RSA-SHA256-PKCS1v1.5":
        return verify_sha256_pkcs1v15(region.data, detached.signature, key)
    if detached.algorithm == "RSA-SHA1-PKCS1v1.5":
        return verify_sha1_pkcs1v15(region.data, detached.signature, key)
    return False

