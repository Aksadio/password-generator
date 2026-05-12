"""
Password Generator - Core Module
Generates secure, random passwords based on user-defined criteria.
"""

import secrets
import string
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PasswordConfig:
    """Configuration for password generation."""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_special: bool = True
    special_chars: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    exclude_chars: str = ""
    exclude_ambiguous: bool = False
    min_uppercase: int = 0
    min_lowercase: int = 0
    min_digits: int = 0
    min_special: int = 0

    # Ambiguous characters that look similar (0/O/o, 1/l/I, etc.)
    AMBIGUOUS_CHARS: str = field(default="0O1lI|", init=False, repr=False)

    def __post_init__(self):
        self._validate()

    def _validate(self):
        if self.length < 4:
            raise ValueError("Password length must be at least 4 characters.")
        if self.length > 512:
            raise ValueError("Password length cannot exceed 512 characters.")
        if not any([self.use_uppercase, self.use_lowercase, self.use_digits, self.use_special]):
            raise ValueError("At least one character type must be selected.")

        min_required = self.min_uppercase + self.min_lowercase + self.min_digits + self.min_special
        if min_required > self.length:
            raise ValueError(
                f"Sum of minimum character requirements ({min_required}) "
                f"exceeds password length ({self.length})."
            )

    def build_charset(self) -> str:
        """Build the character set based on configuration."""
        charset = ""
        if self.use_uppercase:
            charset += string.ascii_uppercase
        if self.use_lowercase:
            charset += string.ascii_lowercase
        if self.use_digits:
            charset += string.digits
        if self.use_special:
            charset += self.special_chars

        # Remove excluded characters
        for ch in self.exclude_chars:
            charset = charset.replace(ch, "")

        # Remove ambiguous characters if requested
        if self.exclude_ambiguous:
            for ch in self.AMBIGUOUS_CHARS:
                charset = charset.replace(ch, "")

        if not charset:
            raise ValueError(
                "Character set is empty after applying exclusions. "
                "Adjust your exclusion settings."
            )
        return charset


@dataclass
class PasswordResult:
    """Result of a password generation operation."""
    password: str
    strength: str
    entropy_bits: float
    length: int
    char_types_used: list[str]

    def __str__(self):
        return self.password


class PasswordGenerator:
    """
    Secure password generator using Python's `secrets` module.

    The `secrets` module is cryptographically secure and suitable
    for generating passwords, tokens, and similar secrets.
    """

    STRENGTH_THRESHOLDS = {
        "Very Weak":  (0, 28),
        "Weak":       (28, 36),
        "Fair":       (36, 60),
        "Strong":     (60, 80),
        "Very Strong": (80, float("inf")),
    }

    def generate(self, config: Optional[PasswordConfig] = None) -> PasswordResult:
        """
        Generate a single password based on the provided configuration.

        Args:
            config: PasswordConfig instance. Uses defaults if None.

        Returns:
            PasswordResult with the password and metadata.
        """
        if config is None:
            config = PasswordConfig()

        charset = config.build_charset()
        password = self._generate_with_minimums(config, charset)

        return PasswordResult(
            password=password,
            strength=self._evaluate_strength(password, charset),
            entropy_bits=self._calculate_entropy(len(password), len(charset)),
            length=len(password),
            char_types_used=self._get_char_types(password),
        )

    def generate_batch(
        self,
        count: int,
        config: Optional[PasswordConfig] = None
    ) -> list[PasswordResult]:
        """
        Generate multiple passwords with the same configuration.

        Args:
            count: Number of passwords to generate (1–100).
            config: PasswordConfig instance. Uses defaults if None.

        Returns:
            List of PasswordResult instances.
        """
        if not 1 <= count <= 100:
            raise ValueError("Batch count must be between 1 and 100.")
        return [self.generate(config) for _ in range(count)]

    def generate_passphrase(
        self,
        word_count: int = 4,
        separator: str = "-",
        word_list: Optional[list[str]] = None,
        capitalize: bool = True,
        append_number: bool = True,
    ) -> str:
        """
        Generate a memorable passphrase using random words.

        Args:
            word_count: Number of words (3–10).
            separator: Character(s) between words.
            word_list: Custom word list. Falls back to built-in list if None.
            capitalize: Whether to capitalize each word.
            append_number: Whether to append a random 2-digit number.

        Returns:
            Passphrase string.
        """
        if not 3 <= word_count <= 10:
            raise ValueError("Word count must be between 3 and 10.")

        words_pool = word_list or self._builtin_word_list()
        chosen = [secrets.choice(words_pool) for _ in range(word_count)]

        if capitalize:
            chosen = [w.capitalize() for w in chosen]

        phrase = separator.join(chosen)
        if append_number:
            phrase += separator + str(secrets.randbelow(90) + 10)

        return phrase

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_with_minimums(self, config: PasswordConfig, charset: str) -> str:
        """Generate a password that satisfies minimum character requirements."""
        guaranteed: list[str] = []

        def _pick_from(chars: str, n: int) -> list[str]:
            available = "".join(c for c in chars if c in charset)
            if not available and n > 0:
                raise ValueError(
                    f"Cannot satisfy minimum requirement: "
                    f"no characters available after exclusions in set: {chars!r}"
                )
            return [secrets.choice(available) for _ in range(n)]

        if config.min_uppercase:
            guaranteed.extend(_pick_from(string.ascii_uppercase, config.min_uppercase))
        if config.min_lowercase:
            guaranteed.extend(_pick_from(string.ascii_lowercase, config.min_lowercase))
        if config.min_digits:
            guaranteed.extend(_pick_from(string.digits, config.min_digits))
        if config.min_special:
            guaranteed.extend(_pick_from(config.special_chars, config.min_special))

        remaining_len = config.length - len(guaranteed)
        remaining = [secrets.choice(charset) for _ in range(remaining_len)]

        combined = guaranteed + remaining
        # Shuffle to avoid predictable placement of guaranteed chars
        # Using secrets.SystemRandom for a cryptographically secure shuffle
        rng = secrets.SystemRandom()
        rng.shuffle(combined)
        return "".join(combined)

    def _calculate_entropy(self, length: int, charset_size: int) -> float:
        """Calculate password entropy in bits: H = L * log2(N)."""
        import math
        if charset_size <= 1:
            return 0.0
        return length * math.log2(charset_size)

    def _evaluate_strength(self, password: str, charset: str) -> str:
        """Evaluate password strength based on entropy."""
        entropy = self._calculate_entropy(len(password), len(charset))
        for label, (low, high) in self.STRENGTH_THRESHOLDS.items():
            if low <= entropy < high:
                return label
        return "Very Strong"

    def _get_char_types(self, password: str) -> list[str]:
        """Identify which character types are present in the password."""
        types = []
        if re.search(r"[A-Z]", password):
            types.append("uppercase")
        if re.search(r"[a-z]", password):
            types.append("lowercase")
        if re.search(r"\d", password):
            types.append("digits")
        if re.search(r"[^A-Za-z0-9]", password):
            types.append("special")
        return types

    @staticmethod
    def _builtin_word_list() -> list[str]:
        """A compact built-in word list for passphrase generation."""
        return [
            "apple", "brave", "cloud", "delta", "eagle", "flame",
            "green", "honey", "ivory", "jewel", "kite", "lemon",
            "maple", "noble", "ocean", "pearl", "quill", "river",
            "stone", "tiger", "ultra", "vivid", "water", "xenon",
            "yacht", "zebra", "amber", "blaze", "crisp", "dawn",
            "frost", "glide", "hazel", "inbox", "jolly", "karma",
            "lunar", "magic", "north", "orbit", "prism", "quiet",
            "rocky", "swift", "thorn", "upper", "vault", "windy",
            "pixel", "radar", "sigma", "topaz", "ultra", "vigor",
        ]
