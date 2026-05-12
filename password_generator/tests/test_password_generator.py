"""
Tests for the Password Generator module.
Run with: pytest tests/ -v
"""

import re
import pytest
from password_generator import PasswordConfig, PasswordGenerator, PasswordResult


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def generator():
    return PasswordGenerator()


@pytest.fixture
def default_config():
    return PasswordConfig()


# ── PasswordConfig validation ─────────────────────────────────────────────────

class TestPasswordConfig:

    def test_defaults_are_valid(self):
        cfg = PasswordConfig()
        assert cfg.length == 16
        assert cfg.use_uppercase is True
        assert cfg.use_lowercase is True
        assert cfg.use_digits is True
        assert cfg.use_special is True

    def test_length_too_short(self):
        with pytest.raises(ValueError, match="at least 4"):
            PasswordConfig(length=3)

    def test_length_too_long(self):
        with pytest.raises(ValueError, match="exceed 512"):
            PasswordConfig(length=513)

    def test_no_char_types_selected(self):
        with pytest.raises(ValueError, match="At least one"):
            PasswordConfig(
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_special=False,
            )

    def test_minimum_requirements_exceed_length(self):
        with pytest.raises(ValueError, match="exceeds password length"):
            PasswordConfig(length=8, min_uppercase=5, min_lowercase=5)

    def test_minimum_requirements_equal_length_ok(self):
        # Should not raise
        cfg = PasswordConfig(length=8, min_uppercase=4, min_lowercase=4)
        assert cfg is not None

    def test_build_charset_all_types(self):
        cfg = PasswordConfig()
        charset = cfg.build_charset()
        assert any(c.isupper() for c in charset)
        assert any(c.islower() for c in charset)
        assert any(c.isdigit() for c in charset)

    def test_build_charset_no_upper(self):
        cfg = PasswordConfig(use_uppercase=False)
        charset = cfg.build_charset()
        assert not any(c.isupper() for c in charset)

    def test_build_charset_excludes_chars(self):
        cfg = PasswordConfig(exclude_chars="aeiou")
        charset = cfg.build_charset()
        for ch in "aeiou":
            assert ch not in charset

    def test_build_charset_no_ambiguous(self):
        cfg = PasswordConfig(exclude_ambiguous=True)
        charset = cfg.build_charset()
        for ch in "0O1lI|":
            assert ch not in charset

    def test_build_charset_empty_after_exclusions(self):
        import string
        all_chars = (
            string.ascii_uppercase + string.ascii_lowercase +
            string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
        )
        with pytest.raises(ValueError, match="empty after applying"):
            cfg = PasswordConfig(exclude_chars=all_chars)
            cfg.build_charset()


# ── PasswordGenerator.generate ────────────────────────────────────────────────

class TestGenerate:

    def test_returns_password_result(self, generator):
        result = generator.generate()
        assert isinstance(result, PasswordResult)

    def test_default_length(self, generator):
        result = generator.generate()
        assert result.length == 16

    def test_custom_length(self, generator):
        for length in [4, 8, 20, 64, 128]:
            cfg = PasswordConfig(length=length)
            result = generator.generate(cfg)
            assert result.length == length

    def test_password_string_contains_only_allowed_chars(self, generator):
        cfg = PasswordConfig(use_special=False)
        charset = cfg.build_charset()
        result = generator.generate(cfg)
        assert all(c in charset for c in result.password)

    def test_no_uppercase(self, generator):
        cfg = PasswordConfig(use_uppercase=False)
        result = generator.generate(cfg)
        assert not any(c.isupper() for c in result.password)

    def test_no_lowercase(self, generator):
        cfg = PasswordConfig(use_lowercase=False)
        result = generator.generate(cfg)
        assert not any(c.islower() for c in result.password)

    def test_no_digits(self, generator):
        cfg = PasswordConfig(use_digits=False)
        result = generator.generate(cfg)
        assert not any(c.isdigit() for c in result.password)

    def test_no_special(self, generator):
        cfg = PasswordConfig(use_special=False)
        result = generator.generate(cfg)
        assert not re.search(r"[^A-Za-z0-9]", result.password)

    def test_min_uppercase_satisfied(self, generator):
        cfg = PasswordConfig(length=20, min_uppercase=5)
        for _ in range(10):
            result = generator.generate(cfg)
            count = sum(1 for c in result.password if c.isupper())
            assert count >= 5

    def test_min_lowercase_satisfied(self, generator):
        cfg = PasswordConfig(length=20, min_lowercase=5)
        for _ in range(10):
            result = generator.generate(cfg)
            count = sum(1 for c in result.password if c.islower())
            assert count >= 5

    def test_min_digits_satisfied(self, generator):
        cfg = PasswordConfig(length=20, min_digits=4)
        for _ in range(10):
            result = generator.generate(cfg)
            count = sum(1 for c in result.password if c.isdigit())
            assert count >= 4

    def test_min_special_satisfied(self, generator):
        cfg = PasswordConfig(length=20, min_special=3)
        for _ in range(10):
            result = generator.generate(cfg)
            count = sum(1 for c in result.password if not c.isalnum())
            assert count >= 3

    def test_uniqueness(self, generator):
        """Passwords should not all be identical (extremely unlikely with secrets)."""
        passwords = {generator.generate().password for _ in range(20)}
        assert len(passwords) > 1

    def test_strength_field_present(self, generator):
        result = generator.generate()
        assert result.strength in [
            "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
        ]

    def test_entropy_positive(self, generator):
        result = generator.generate()
        assert result.entropy_bits > 0

    def test_very_strong_entropy_for_long_password(self, generator):
        cfg = PasswordConfig(length=32)
        result = generator.generate(cfg)
        assert result.strength in ["Strong", "Very Strong"]

    def test_char_types_reported(self, generator):
        cfg = PasswordConfig(length=50)  # high chance all types appear
        result = generator.generate(cfg)
        assert len(result.char_types_used) > 0

    def test_str_returns_password(self, generator):
        result = generator.generate()
        assert str(result) == result.password


# ── PasswordGenerator.generate_batch ─────────────────────────────────────────

class TestGenerateBatch:

    def test_returns_correct_count(self, generator):
        results = generator.generate_batch(5)
        assert len(results) == 5

    def test_all_results_are_password_result(self, generator):
        results = generator.generate_batch(3)
        assert all(isinstance(r, PasswordResult) for r in results)

    def test_count_too_low(self, generator):
        with pytest.raises(ValueError):
            generator.generate_batch(0)

    def test_count_too_high(self, generator):
        with pytest.raises(ValueError):
            generator.generate_batch(101)

    def test_batch_1(self, generator):
        results = generator.generate_batch(1)
        assert len(results) == 1

    def test_batch_100(self, generator):
        results = generator.generate_batch(100)
        assert len(results) == 100


# ── PasswordGenerator.generate_passphrase ─────────────────────────────────────

class TestGeneratePassphrase:

    def test_default_passphrase(self, generator):
        phrase = generator.generate_passphrase()
        parts = phrase.split("-")
        # 4 words + 1 number
        assert len(parts) == 5

    def test_word_count(self, generator):
        for n in range(3, 11):
            phrase = generator.generate_passphrase(word_count=n, append_number=False)
            parts = phrase.split("-")
            assert len(parts) == n

    def test_separator(self, generator):
        phrase = generator.generate_passphrase(separator="_", append_number=False)
        assert "_" in phrase
        assert "-" not in phrase

    def test_capitalized(self, generator):
        phrase = generator.generate_passphrase(capitalize=True, append_number=False)
        words = phrase.split("-")
        assert all(w[0].isupper() for w in words)

    def test_no_capitalize(self, generator):
        phrase = generator.generate_passphrase(capitalize=False, append_number=False)
        words = phrase.split("-")
        assert all(w[0].islower() for w in words)

    def test_append_number(self, generator):
        phrase = generator.generate_passphrase(append_number=True)
        last_part = phrase.split("-")[-1]
        assert last_part.isdigit()
        assert 10 <= int(last_part) <= 99

    def test_no_append_number(self, generator):
        phrase = generator.generate_passphrase(append_number=False)
        last_part = phrase.split("-")[-1]
        assert not last_part.isdigit()

    def test_word_count_too_low(self, generator):
        with pytest.raises(ValueError):
            generator.generate_passphrase(word_count=2)

    def test_word_count_too_high(self, generator):
        with pytest.raises(ValueError):
            generator.generate_passphrase(word_count=11)

    def test_custom_word_list(self, generator):
        custom = ["alpha", "beta", "gamma", "delta", "epsilon"]
        phrase = generator.generate_passphrase(
            word_count=3, word_list=custom, append_number=False, capitalize=False
        )
        words = phrase.split("-")
        assert all(w in custom for w in words)

    def test_uniqueness(self, generator):
        phrases = {generator.generate_passphrase() for _ in range(10)}
        assert len(phrases) > 1


# ── Entropy calculation ───────────────────────────────────────────────────────

class TestEntropy:

    def test_entropy_increases_with_length(self, generator):
        cfg_short = PasswordConfig(length=8)
        cfg_long = PasswordConfig(length=16)
        r_short = generator.generate(cfg_short)
        r_long = generator.generate(cfg_long)
        assert r_long.entropy_bits > r_short.entropy_bits

    def test_entropy_increases_with_charset(self, generator):
        cfg_limited = PasswordConfig(
            use_uppercase=False, use_special=False, length=16
        )
        cfg_full = PasswordConfig(length=16)
        r_limited = generator.generate(cfg_limited)
        r_full = generator.generate(cfg_full)
        assert r_full.entropy_bits > r_limited.entropy_bits
