"""Tests for the crypto module."""

import pytest

from authkeeper.core.crypto import (
    DerivedKey,
    EncryptedData,
    EncryptionEngine,
    KeyDerivation,
    MasterPasswordHasher,
    secure_compare,
    secure_random_bytes,
)


class TestKeyDerivation:
    """Tests for KeyDerivation class."""

    def test_derive_key_produces_32_byte_key(self) -> None:
        """Test that key derivation produces a 32-byte key."""
        kd = KeyDerivation()
        result = kd.derive_key("test_password")

        assert len(result.key) == 32
        assert len(result.salt) == 16

    def test_derive_key_with_same_salt_produces_same_key(self) -> None:
        """Test deterministic key derivation with same salt."""
        kd = KeyDerivation()
        result1 = kd.derive_key("test_password")
        result2 = kd.derive_key("test_password", salt=result1.salt)

        assert result1.key == result2.key
        assert result1.salt == result2.salt

    def test_derive_key_with_different_passwords_produces_different_keys(self) -> None:
        """Test different passwords produce different keys."""
        kd = KeyDerivation()
        result1 = kd.derive_key("password1")
        result2 = kd.derive_key("password2", salt=result1.salt)

        assert result1.key != result2.key

    def test_derive_key_generates_random_salt_each_time(self) -> None:
        """Test that each derivation gets a unique salt."""
        kd = KeyDerivation()
        result1 = kd.derive_key("test_password")
        result2 = kd.derive_key("test_password")

        assert result1.salt != result2.salt
        assert result1.key != result2.key


class TestMasterPasswordHasher:
    """Tests for MasterPasswordHasher class."""

    def test_hash_password_produces_hash_string(self) -> None:
        """Test password hashing produces a hash string."""
        hasher = MasterPasswordHasher()
        hash_str = hasher.hash_password("test_password")

        assert isinstance(hash_str, str)
        assert hash_str.startswith("$argon2id$")

    def test_verify_password_with_correct_password(self) -> None:
        """Test password verification succeeds with correct password."""
        hasher = MasterPasswordHasher()
        hash_str = hasher.hash_password("test_password")

        assert hasher.verify_password(hash_str, "test_password") is True

    def test_verify_password_with_wrong_password(self) -> None:
        """Test password verification fails with wrong password."""
        hasher = MasterPasswordHasher()
        hash_str = hasher.hash_password("test_password")

        assert hasher.verify_password(hash_str, "wrong_password") is False

    def test_hash_password_produces_different_hashes(self) -> None:
        """Test that same password produces different hashes (due to salt)."""
        hasher = MasterPasswordHasher()
        hash1 = hasher.hash_password("test_password")
        hash2 = hasher.hash_password("test_password")

        assert hash1 != hash2


class TestEncryptionEngine:
    """Tests for EncryptionEngine class."""

    def test_encrypt_and_decrypt_roundtrip(self) -> None:
        """Test encryption and decryption roundtrip."""
        key = secure_random_bytes(32)
        engine = EncryptionEngine(key)

        plaintext = b"Hello, World!"
        encrypted = engine.encrypt(plaintext)
        decrypted = engine.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext_each_time(self) -> None:
        """Test that encryption with random nonce produces different ciphertext."""
        key = secure_random_bytes(32)
        engine = EncryptionEngine(key)

        plaintext = b"Hello, World!"
        encrypted1 = engine.encrypt(plaintext)
        encrypted2 = engine.encrypt(plaintext)

        assert encrypted1.nonce != encrypted2.nonce
        assert encrypted1.ciphertext != encrypted2.ciphertext

    def test_decrypt_with_wrong_key_fails(self) -> None:
        """Test that decryption with wrong key fails."""
        key1 = secure_random_bytes(32)
        key2 = secure_random_bytes(32)

        engine1 = EncryptionEngine(key1)
        engine2 = EncryptionEngine(key2)

        plaintext = b"Hello, World!"
        encrypted = engine1.encrypt(plaintext)

        with pytest.raises(Exception):  # InvalidTag from cryptography
            engine2.decrypt(encrypted)

    def test_encrypt_with_associated_data(self) -> None:
        """Test encryption with additional authenticated data."""
        key = secure_random_bytes(32)
        engine = EncryptionEngine(key)

        plaintext = b"Secret Data"
        aad = b"Additional Context"

        encrypted = engine.encrypt(plaintext, associated_data=aad)
        decrypted = engine.decrypt(encrypted, associated_data=aad)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_associated_data_fails(self) -> None:
        """Test that decryption with wrong AAD fails."""
        key = secure_random_bytes(32)
        engine = EncryptionEngine(key)

        plaintext = b"Secret Data"

        encrypted = engine.encrypt(plaintext, associated_data=b"correct")

        with pytest.raises(Exception):
            engine.decrypt(encrypted, associated_data=b"wrong")

    def test_invalid_key_size_raises_error(self) -> None:
        """Test that invalid key size raises ValueError."""
        with pytest.raises(ValueError):
            EncryptionEngine(b"too_short")

        with pytest.raises(ValueError):
            EncryptionEngine(b"x" * 64)  # Too long


class TestEncryptedData:
    """Tests for EncryptedData class."""

    def test_to_bytes_and_from_bytes_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        nonce = secure_random_bytes(12)
        ciphertext = b"encrypted_data_here"

        original = EncryptedData(nonce=nonce, ciphertext=ciphertext)
        serialized = original.to_bytes()
        restored = EncryptedData.from_bytes(serialized)

        assert restored.nonce == original.nonce
        assert restored.ciphertext == original.ciphertext

    def test_from_bytes_with_short_data_raises_error(self) -> None:
        """Test that short data raises ValueError."""
        with pytest.raises(ValueError):
            EncryptedData.from_bytes(b"short")


class TestSecureUtilities:
    """Tests for secure utility functions."""

    def test_secure_random_bytes_produces_requested_length(self) -> None:
        """Test that secure_random_bytes produces correct length."""
        for length in [16, 32, 64, 128]:
            result = secure_random_bytes(length)
            assert len(result) == length

    def test_secure_random_bytes_produces_different_values(self) -> None:
        """Test that secure_random_bytes produces different values."""
        result1 = secure_random_bytes(32)
        result2 = secure_random_bytes(32)
        assert result1 != result2

    def test_secure_compare_with_equal_values(self) -> None:
        """Test secure_compare returns True for equal values."""
        a = b"secret_value"
        b = b"secret_value"
        assert secure_compare(a, b) is True

    def test_secure_compare_with_different_values(self) -> None:
        """Test secure_compare returns False for different values."""
        a = b"secret_value"
        b = b"other_value"
        assert secure_compare(a, b) is False

    def test_secure_compare_with_different_lengths(self) -> None:
        """Test secure_compare returns False for different lengths."""
        a = b"short"
        b = b"longer_value"
        assert secure_compare(a, b) is False
