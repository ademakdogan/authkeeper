"""Password generator for AuthKeeper.

Provides cryptographically secure password generation with
configurable character sets, length, and passphrase support.
"""

import secrets
import string
from dataclasses import dataclass
from enum import Flag, auto
from typing import Final


# Character sets
LOWERCASE: Final[str] = string.ascii_lowercase
UPPERCASE: Final[str] = string.ascii_uppercase
DIGITS: Final[str] = string.digits
SYMBOLS: Final[str] = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS: Final[str] = "0O1lI|"


class CharacterSet(Flag):
    """Flags for password character sets."""

    LOWERCASE = auto()
    UPPERCASE = auto()
    DIGITS = auto()
    SYMBOLS = auto()

    @classmethod
    def all(cls) -> "CharacterSet":
        """Return all character sets combined."""
        return cls.LOWERCASE | cls.UPPERCASE | cls.DIGITS | cls.SYMBOLS

    @classmethod
    def default(cls) -> "CharacterSet":
        """Return default character sets (letters and digits)."""
        return cls.LOWERCASE | cls.UPPERCASE | cls.DIGITS


@dataclass(frozen=True, slots=True)
class PasswordConfig:
    """Configuration for password generation.

    Attributes:
        length: Password length (8-128 characters).
        character_sets: Which character sets to include.
        exclude_ambiguous: Whether to exclude ambiguous characters (0O1lI|).
        require_all_sets: Ensure at least one character from each enabled set.
    """

    length: int = 16
    character_sets: CharacterSet = CharacterSet.default()
    exclude_ambiguous: bool = True
    require_all_sets: bool = True

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not 8 <= self.length <= 128:
            raise ValueError("Password length must be between 8 and 128")
        if self.character_sets == 0:
            raise ValueError("At least one character set must be enabled")


@dataclass(frozen=True, slots=True)
class PassphraseConfig:
    """Configuration for passphrase generation.

    Attributes:
        word_count: Number of words in the passphrase (4-10).
        separator: Character to separate words.
        capitalize: Whether to capitalize each word.
        include_number: Whether to include a random number.
    """

    word_count: int = 4
    separator: str = "-"
    capitalize: bool = True
    include_number: bool = True

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not 4 <= self.word_count <= 10:
            raise ValueError("Word count must be between 4 and 10")


# EFF's Short Wordlist for Diceware passphrases (sample - full list would be 1296 words)
WORDLIST: Final[tuple[str, ...]] = (
    "acid", "acorn", "acre", "acts", "afar", "affix", "aged", "agent", "agile", "aging",
    "agony", "ahead", "aide", "aids", "aim", "ajar", "alarm", "album", "alert", "alike",
    "alive", "alley", "allot", "allow", "alloy", "alone", "alpha", "also", "alter", "amber",
    "amid", "ample", "angel", "anger", "angle", "angry", "ankle", "apart", "apple", "apply",
    "apron", "arena", "argue", "arise", "armor", "army", "aroma", "array", "arrow", "art",
    "ashen", "aside", "asset", "atom", "attic", "audio", "avert", "avoid", "awake", "award",
    "away", "awful", "axis", "bacon", "badge", "badly", "baker", "balmy", "banjo", "barge",
    "baron", "basic", "basin", "batch", "bath", "beach", "beam", "beast", "beat", "beige",
    "bench", "berry", "bike", "bird", "birth", "blade", "blame", "blank", "blast", "blaze",
    "bleak", "blend", "bless", "blimp", "blind", "bliss", "block", "bloke", "blond", "blood",
    "bloom", "blues", "blunt", "board", "boast", "body", "bogus", "bolt", "bond", "bonus",
    "book", "booth", "boots", "boss", "botch", "both", "boxer", "brace", "brain", "brake",
    "brand", "brass", "brave", "bread", "break", "breed", "brick", "bride", "brief", "bring",
    "brink", "brisk", "broad", "broil", "broke", "brook", "broom", "broth", "brown", "brunt",
    "brush", "brute", "buddy", "budge", "buggy", "build", "built", "bulge", "bulk", "bully",
    "bunch", "bunny", "burn", "burst", "bury", "bush", "busy", "buyer", "buzz", "cabin",
    "cable", "cache", "cadet", "cage", "cake", "calm", "camel", "camp", "canal", "candy",
    "cane", "cape", "card", "cargo", "carol", "carry", "carve", "case", "cash", "cause",
    "cease", "cedar", "chain", "chair", "champ", "chant", "chaos", "charm", "chase", "cheap",
    "check", "cheek", "cheer", "chess", "chest", "chick", "chief", "child", "chill", "chimp",
    "china", "chip", "choke", "chord", "chore", "chunk", "churn", "cider", "cigar", "cinch",
    "cite", "city", "civic", "civil", "clad", "claim", "clamp", "clap", "clasp", "class",
    "claw", "clay", "clean", "clear", "clerk", "click", "cliff", "climb", "cling", "cloak",
    "clock", "clone", "close", "cloth", "cloud", "clout", "clown", "club", "cluck", "clue",
    "clump", "clung", "coach", "coast", "coat", "cobra", "cocoa", "coil", "coin", "coke",
    "cola", "cold", "colon", "color", "comet", "comic", "comma", "cone", "coral", "cord",
    "core", "corn", "couch", "cough", "could", "count", "court", "cover", "cozy", "crack",
    "craft", "cramp", "crane", "crank", "crash", "crate", "crawl", "crazy", "cream", "creek",
    "creep", "creme", "crepe", "crest", "crick", "cried", "crimp", "crisp", "croak", "crock",
    "crook", "crop", "cross", "crowd", "crown", "crude", "cruel", "crush", "crust", "crypt",
    "cubic", "curry", "curse", "curve", "cycle", "cynic", "daddy", "daily", "dairy", "daisy",
    "dance", "dandy", "dare", "dark", "dash", "data", "date", "dawn", "deal", "dean",
)


class PasswordGenerator:
    """Cryptographically secure password generator.

    Generates random passwords using secrets module for
    cryptographic randomness.

    Example:
        >>> gen = PasswordGenerator()
        >>> password = gen.generate()
        >>> print(password)  # e.g., "K7#mP2xQ9vL5nR3w"
        >>> passphrase = gen.generate_passphrase()
        >>> print(passphrase)  # e.g., "Coral-Brick-Dance-Tiger-42"
    """

    def generate(self, config: PasswordConfig | None = None) -> str:
        """Generate a random password.

        Args:
            config: Password configuration. Uses defaults if None.

        Returns:
            Generated password string.
        """
        config = config or PasswordConfig()
        charset = self._build_charset(config)

        if config.require_all_sets:
            return self._generate_with_requirements(config, charset)
        else:
            return "".join(secrets.choice(charset) for _ in range(config.length))

    def _build_charset(self, config: PasswordConfig) -> str:
        """Build the character set based on configuration."""
        chars = ""

        if CharacterSet.LOWERCASE in config.character_sets:
            chars += LOWERCASE
        if CharacterSet.UPPERCASE in config.character_sets:
            chars += UPPERCASE
        if CharacterSet.DIGITS in config.character_sets:
            chars += DIGITS
        if CharacterSet.SYMBOLS in config.character_sets:
            chars += SYMBOLS

        if config.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)

        return chars

    def _generate_with_requirements(self, config: PasswordConfig, charset: str) -> str:
        """Generate password ensuring at least one char from each enabled set."""
        required_chars: list[str] = []

        # Get one character from each required set
        if CharacterSet.LOWERCASE in config.character_sets:
            chars = LOWERCASE
            if config.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in AMBIGUOUS)
            required_chars.append(secrets.choice(chars))

        if CharacterSet.UPPERCASE in config.character_sets:
            chars = UPPERCASE
            if config.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in AMBIGUOUS)
            required_chars.append(secrets.choice(chars))

        if CharacterSet.DIGITS in config.character_sets:
            chars = DIGITS
            if config.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in AMBIGUOUS)
            required_chars.append(secrets.choice(chars))

        if CharacterSet.SYMBOLS in config.character_sets:
            required_chars.append(secrets.choice(SYMBOLS))

        # Fill remaining length with random characters
        remaining = config.length - len(required_chars)
        all_chars = required_chars + [secrets.choice(charset) for _ in range(remaining)]

        # Shuffle to randomize positions
        result = list(all_chars)
        secrets.SystemRandom().shuffle(result)

        return "".join(result)

    def generate_passphrase(self, config: PassphraseConfig | None = None) -> str:
        """Generate a random passphrase using dictionary words.

        Args:
            config: Passphrase configuration. Uses defaults if None.

        Returns:
            Generated passphrase string.
        """
        config = config or PassphraseConfig()

        # Select random words
        words = [secrets.choice(WORDLIST) for _ in range(config.word_count)]

        # Capitalize if requested
        if config.capitalize:
            words = [word.capitalize() for word in words]

        # Build passphrase
        passphrase = config.separator.join(words)

        # Add number if requested
        if config.include_number:
            number = secrets.randbelow(100)
            passphrase += f"{config.separator}{number}"

        return passphrase

    def calculate_entropy(self, config: PasswordConfig) -> float:
        """Calculate the entropy (bits) of passwords with given config.

        Args:
            config: Password configuration.

        Returns:
            Entropy in bits.
        """
        import math

        charset = self._build_charset(config)
        charset_size = len(charset)

        if charset_size == 0:
            return 0.0

        return config.length * math.log2(charset_size)

    def strength_rating(self, config: PasswordConfig) -> str:
        """Get a human-readable strength rating for the configuration.

        Args:
            config: Password configuration.

        Returns:
            Strength rating: "Weak", "Fair", "Strong", "Very Strong", or "Excellent".
        """
        entropy = self.calculate_entropy(config)

        if entropy < 40:
            return "Weak"
        elif entropy < 60:
            return "Fair"
        elif entropy < 80:
            return "Strong"
        elif entropy < 100:
            return "Very Strong"
        else:
            return "Excellent"


# Convenience functions
def generate_password(
    length: int = 16,
    include_symbols: bool = False,
    exclude_ambiguous: bool = True,
) -> str:
    """Generate a random password with common defaults.

    Args:
        length: Password length.
        include_symbols: Whether to include symbols.
        exclude_ambiguous: Whether to exclude ambiguous characters.

    Returns:
        Generated password.
    """
    character_sets = CharacterSet.default()
    if include_symbols:
        character_sets |= CharacterSet.SYMBOLS

    config = PasswordConfig(
        length=length,
        character_sets=character_sets,
        exclude_ambiguous=exclude_ambiguous,
    )

    return PasswordGenerator().generate(config)


def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    """Generate a random passphrase with common defaults.

    Args:
        word_count: Number of words.
        separator: Word separator.

    Returns:
        Generated passphrase.
    """
    config = PassphraseConfig(word_count=word_count, separator=separator)
    return PasswordGenerator().generate_passphrase(config)
