"""Cryptographic module for AuthKeeper.

This module provides secure key derivation using Argon2id and
authenticated encryption using AES-256-GCM.
"""

import os
import secrets
from dataclasses import dataclass
from typing import Final

from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Argon2id parameters (OWASP recommendations for high-security)
ARGON2_TIME_COST: Final[int] = 3  # Number of iterations
ARGON2_MEMORY_COST: Final[int] = 65536  # 64 MB in KB
ARGON2_PARALLELISM: Final[int] = 4  # Number of parallel threads
ARGON2_HASH_LEN: Final[int] = 32  # 256-bit key
ARGON2_SALT_LEN: Final[int] = 16  # 128-bit salt

# AES-GCM parameters
AES_KEY_SIZE: Final[int] = 32  # 256-bit key
AES_NONCE_SIZE: Final[int] = 12  # 96-bit nonce (recommended for GCM)


@dataclass(frozen=True, slots=True)
class DerivedKey:
    """Container for a derived encryption key and its salt.

    Attributes:
        key: The 256-bit derived encryption key.
        salt: The random salt used during key derivation.
    """

    key: bytes
    salt: bytes


class KeyDerivation:
    """Secure key derivation using Argon2id.

    Argon2id is the winner of the Password Hashing Competition and
    provides protection against both GPU-based and side-channel attacks.
    """

    def __init__(
        self,
        time_cost: int = ARGON2_TIME_COST,
        memory_cost: int = ARGON2_MEMORY_COST,
        parallelism: int = ARGON2_PARALLELISM,
        hash_len: int = ARGON2_HASH_LEN,
        salt_len: int = ARGON2_SALT_LEN,
    ) -> None:
        """Initialize key derivation with Argon2id parameters.

        Args:
            time_cost: Number of iterations (higher = slower, more secure).
            memory_cost: Memory usage in KB (higher = more GPU-resistant).
            parallelism: Number of parallel threads.
            hash_len: Length of derived key in bytes.
            salt_len: Length of random salt in bytes.
        """
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len

    def derive_key(self, password: str, salt: bytes | None = None) -> DerivedKey:
        """Derive a cryptographic key from a password.

        Args:
            password: The master password to derive the key from.
            salt: Optional salt bytes. If None, a random salt is generated.

        Returns:
            DerivedKey containing the derived key and salt used.
        """
        if salt is None:
            salt = secrets.token_bytes(self.salt_len)

        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            type=Type.ID,  # Argon2id variant
        )

        return DerivedKey(key=key, salt=salt)


class MasterPasswordHasher:
    """Secure master password hashing for verification.

    Uses Argon2id with standard parameters for password storage.
    """

    def __init__(self) -> None:
        """Initialize the password hasher with secure defaults."""
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            salt_len=ARGON2_SALT_LEN,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        """Hash a password for storage.

        Args:
            password: The password to hash.

        Returns:
            Argon2id hash string suitable for storage.
        """
        return self._hasher.hash(password)

    def verify_password(self, stored_hash: str, password: str) -> bool:
        """Verify a password against a stored hash.

        Args:
            stored_hash: The stored Argon2id hash string.
            password: The password to verify.

        Returns:
            True if the password matches, False otherwise.
        """
        try:
            self._hasher.verify(stored_hash, password)
            return True
        except Exception:
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """Check if a hash needs to be rehashed with updated parameters.

        Args:
            stored_hash: The stored hash to check.

        Returns:
            True if the hash should be regenerated with current parameters.
        """
        return self._hasher.check_needs_rehash(stored_hash)


@dataclass(frozen=True, slots=True)
class EncryptedData:
    """Container for encrypted data.

    Attributes:
        nonce: The unique nonce used for encryption.
        ciphertext: The encrypted data with authentication tag.
    """

    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize to bytes for storage.

        Returns:
            Concatenated nonce and ciphertext.
        """
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """Deserialize from bytes.

        Args:
            data: The serialized encrypted data.

        Returns:
            EncryptedData instance.

        Raises:
            ValueError: If data is too short.
        """
        if len(data) < AES_NONCE_SIZE:
            raise ValueError("Encrypted data too short")
        return cls(nonce=data[:AES_NONCE_SIZE], ciphertext=data[AES_NONCE_SIZE:])


class EncryptionEngine:
    """AES-256-GCM authenticated encryption engine.

    Provides confidentiality and integrity for sensitive data.
    Each encryption operation uses a unique random nonce.
    """

    def __init__(self, key: bytes) -> None:
        """Initialize the encryption engine with a key.

        Args:
            key: 256-bit (32 bytes) encryption key.

        Raises:
            ValueError: If key is not 32 bytes.
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> EncryptedData:
        """Encrypt data with authenticated encryption.

        Args:
            plaintext: The data to encrypt.
            associated_data: Optional additional authenticated data (not encrypted,
                but verified during decryption).

        Returns:
            EncryptedData containing nonce and ciphertext.
        """
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return EncryptedData(nonce=nonce, ciphertext=ciphertext)

    def decrypt(self, encrypted: EncryptedData, associated_data: bytes | None = None) -> bytes:
        """Decrypt authenticated encrypted data.

        Args:
            encrypted: The EncryptedData to decrypt.
            associated_data: Optional additional authenticated data (must match
                what was provided during encryption).

        Returns:
            The decrypted plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
                (data corrupted or tampered with).
        """
        return self._cipher.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data)


def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Args:
        length: Number of random bytes to generate.

    Returns:
        Random bytes suitable for cryptographic use.
    """
    return secrets.token_bytes(length)


def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of byte strings.

    Prevents timing attacks when comparing secrets.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if the byte strings are equal.
    """
    return secrets.compare_digest(a, b)
