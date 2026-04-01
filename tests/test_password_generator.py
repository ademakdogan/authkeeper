"""Tests for the password generator module."""

import pytest

from authkeeper.services.password_generator import (
    CharacterSet,
    PassphraseConfig,
    PasswordConfig,
    PasswordGenerator,
    generate_passphrase,
    generate_password,
)


class TestPasswordConfig:
    """Tests for PasswordConfig."""

    def test_default_config(self) -> None:
        """Test default password configuration."""
        config = PasswordConfig()

        assert config.length == 16
        assert config.exclude_ambiguous is True
        assert config.require_all_sets is True

    def test_invalid_length_too_short(self) -> None:
        """Test that too short length raises error."""
        with pytest.raises(ValueError):
            PasswordConfig(length=4)

    def test_invalid_length_too_long(self) -> None:
        """Test that too long length raises error."""
        with pytest.raises(ValueError):
            PasswordConfig(length=200)


class TestCharacterSet:
    """Tests for CharacterSet flags."""

    def test_all_returns_all_sets(self) -> None:
        """Test CharacterSet.all() includes all sets."""
        all_sets = CharacterSet.all()

        assert CharacterSet.LOWERCASE in all_sets
        assert CharacterSet.UPPERCASE in all_sets
        assert CharacterSet.DIGITS in all_sets
        assert CharacterSet.SYMBOLS in all_sets

    def test_default_excludes_symbols(self) -> None:
        """Test CharacterSet.default() excludes symbols."""
        default = CharacterSet.default()

        assert CharacterSet.LOWERCASE in default
        assert CharacterSet.UPPERCASE in default
        assert CharacterSet.DIGITS in default
        assert CharacterSet.SYMBOLS not in default


class TestPasswordGenerator:
    """Tests for PasswordGenerator class."""

    def test_generate_default_password(self) -> None:
        """Test generating password with defaults."""
        gen = PasswordGenerator()
        password = gen.generate()

        assert len(password) == 16
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)

    def test_generate_password_with_custom_length(self) -> None:
        """Test generating password with custom length."""
        gen = PasswordGenerator()
        config = PasswordConfig(length=24)
        password = gen.generate(config)

        assert len(password) == 24

    def test_generate_password_with_symbols(self) -> None:
        """Test generating password with symbols."""
        gen = PasswordGenerator()
        config = PasswordConfig(
            length=20,
            character_sets=CharacterSet.all(),
        )
        password = gen.generate(config)

        assert len(password) == 20
        # With require_all_sets=True, should have symbol
        assert any(not c.isalnum() for c in password)

    def test_generate_password_excludes_ambiguous(self) -> None:
        """Test that ambiguous characters are excluded."""
        gen = PasswordGenerator()
        config = PasswordConfig(
            length=100,
            exclude_ambiguous=True,
        )

        # Generate multiple passwords to increase confidence
        for _ in range(10):
            password = gen.generate(config)
            for ambiguous in "0O1lI|":
                assert ambiguous not in password

    def test_generate_password_includes_ambiguous_when_disabled(self) -> None:
        """Test that ambiguous chars included when exclude disabled."""
        gen = PasswordGenerator()
        config = PasswordConfig(
            length=100,
            exclude_ambiguous=False,
        )

        # Generate many passwords; at least one should have ambiguous
        passwords = [gen.generate(config) for _ in range(50)]
        all_chars = "".join(passwords)

        # At least one ambiguous char should appear in 50 100-char passwords
        has_ambiguous = any(c in all_chars for c in "0O1lI")
        assert has_ambiguous

    def test_generate_produces_unique_passwords(self) -> None:
        """Test that generated passwords are unique."""
        gen = PasswordGenerator()
        passwords = [gen.generate() for _ in range(100)]

        # All should be unique
        assert len(set(passwords)) == 100


class TestPassphraseGenerator:
    """Tests for passphrase generation."""

    def test_generate_default_passphrase(self) -> None:
        """Test generating passphrase with defaults."""
        gen = PasswordGenerator()
        passphrase = gen.generate_passphrase()

        parts = passphrase.split("-")
        # Default is 4 words + 1 number = 5 parts
        assert len(parts) == 5
        # Last part should be a number
        assert parts[-1].isdigit()

    def test_generate_passphrase_custom_word_count(self) -> None:
        """Test generating passphrase with custom word count."""
        gen = PasswordGenerator()
        config = PassphraseConfig(word_count=6, include_number=False)
        passphrase = gen.generate_passphrase(config)

        parts = passphrase.split("-")
        assert len(parts) == 6

    def test_generate_passphrase_custom_separator(self) -> None:
        """Test generating passphrase with custom separator."""
        gen = PasswordGenerator()
        config = PassphraseConfig(separator="_")
        passphrase = gen.generate_passphrase(config)

        assert "_" in passphrase
        assert "-" not in passphrase

    def test_generate_passphrase_no_capitalize(self) -> None:
        """Test generating passphrase without capitalization."""
        gen = PasswordGenerator()
        config = PassphraseConfig(capitalize=False, include_number=False)
        passphrase = gen.generate_passphrase(config)

        words = passphrase.split("-")
        for word in words:
            assert word.islower()


class TestEntropyCalculation:
    """Tests for entropy calculation."""

    def test_calculate_entropy_default(self) -> None:
        """Test entropy calculation for default config."""
        gen = PasswordGenerator()
        config = PasswordConfig()
        entropy = gen.calculate_entropy(config)

        # 16 chars from ~58 char set ≈ 93 bits
        assert 80 < entropy < 120

    def test_calculate_entropy_increases_with_length(self) -> None:
        """Test that entropy increases with password length."""
        gen = PasswordGenerator()
        config_short = PasswordConfig(length=8)
        config_long = PasswordConfig(length=32)

        entropy_short = gen.calculate_entropy(config_short)
        entropy_long = gen.calculate_entropy(config_long)

        assert entropy_long > entropy_short

    def test_calculate_entropy_increases_with_charset(self) -> None:
        """Test that entropy increases with larger charset."""
        gen = PasswordGenerator()
        config_no_symbols = PasswordConfig(
            length=16, character_sets=CharacterSet.default()
        )
        config_with_symbols = PasswordConfig(
            length=16, character_sets=CharacterSet.all()
        )

        entropy_no_symbols = gen.calculate_entropy(config_no_symbols)
        entropy_with_symbols = gen.calculate_entropy(config_with_symbols)

        assert entropy_with_symbols > entropy_no_symbols


class TestStrengthRating:
    """Tests for strength rating."""

    def test_strength_rating_weak(self) -> None:
        """Test weak password rating."""
        gen = PasswordGenerator()
        config = PasswordConfig(length=8, character_sets=CharacterSet.LOWERCASE)
        rating = gen.strength_rating(config)

        assert rating == "Weak"

    def test_strength_rating_excellent(self) -> None:
        """Test excellent password rating."""
        gen = PasswordGenerator()
        config = PasswordConfig(length=32, character_sets=CharacterSet.all())
        rating = gen.strength_rating(config)

        assert rating == "Excellent"


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_generate_password_convenience(self) -> None:
        """Test generate_password convenience function."""
        password = generate_password(length=20, include_symbols=True)

        assert len(password) == 20

    def test_generate_passphrase_convenience(self) -> None:
        """Test generate_passphrase convenience function."""
        passphrase = generate_passphrase(word_count=5, separator=".")

        assert "." in passphrase
        parts = passphrase.split(".")
        assert len(parts) >= 5
