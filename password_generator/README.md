# 🔐 Password Generator

A secure, feature-rich password generator built with Python's `secrets` module — cryptographically safe and suitable for production use.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## ✨ Features

- 🔒 **Cryptographically secure** — powered by Python's `secrets` module (OS-level CSPRNG)
- 🎛️ **Highly configurable** — length, character types, exclusions, minimums
- 🧩 **Passphrase mode** — generate memorable word-based passphrases
- 📦 **Batch generation** — create up to 100 passwords at once
- 📊 **Strength analysis** — entropy-based strength rating per password
- 🖥️ **Rich CLI** — plain, JSON, and CSV output formats
- 🐍 **Clean Python API** — easy to import and use in your own projects
- ✅ **Fully tested** — comprehensive pytest suite

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/password-generator.git
cd password-generator
pip install -e .
```

### CLI Usage

```bash
# One password, defaults (16 chars, all types)
passgen

# Custom length
passgen -l 24

# Five passwords at 32 characters each
passgen -l 32 -c 5

# No special characters
passgen --no-special

# Show strength and entropy details
passgen --details

# JSON output
passgen -l 20 -c 3 --output json

# CSV output
passgen -l 16 -c 10 --output csv

# Memorable passphrase
passgen --passphrase

# 5-word passphrase with underscore separator
passgen --passphrase --words 5 --separator _

# Exclude ambiguous characters (0, O, 1, l, I)
passgen --no-ambiguous

# Enforce minimum character requirements
passgen -l 20 --min-upper 2 --min-digits 2 --min-special 1

# Exclude specific characters
passgen --exclude "{}[]"
```

### Output Examples

```
$ passgen -c 3 --details
[1] mK7#pLqR2@xNvBdJ
     Strength : Very Strong
     Entropy  : 104.8 bits
     Length   : 16
     Types    : uppercase, lowercase, digits, special

[2] Tz!9wYsM4^cXeAuF
     Strength : Very Strong
     Entropy  : 104.8 bits
     Length   : 16
     Types    : uppercase, lowercase, digits, special

[3] bH3*nQjV8&rWpGkD
     Strength : Very Strong
     Entropy  : 104.8 bits
     Length   : 16
     Types    : uppercase, lowercase, digits, special
```

```
$ passgen --passphrase --words 4
Swift-Ocean-Prism-Amber-47
```

```
$ passgen -l 12 --output json
{
  "password": "qT4!mNxK7@pL",
  "strength": "Strong",
  "entropy_bits": 78.6,
  "length": 12,
  "char_types_used": ["uppercase", "lowercase", "digits", "special"]
}
```

---

## 🐍 Python API

```python
from password_generator import PasswordConfig, PasswordGenerator

generator = PasswordGenerator()

# Default password
result = generator.generate()
print(result.password)       # e.g. "mK7#pLqR2@xNvBdJ"
print(result.strength)       # "Very Strong"
print(result.entropy_bits)   # 104.8

# Custom configuration
config = PasswordConfig(
    length=20,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=True,
    special_chars="!@#$%",   # restrict special chars
    exclude_chars="0O1lI",   # avoid ambiguous manually
    min_uppercase=2,
    min_digits=2,
    min_special=1,
)
result = generator.generate(config)
print(result)  # __str__ returns the password

# Batch generation
results = generator.generate_batch(count=10, config=config)
for r in results:
    print(f"{r.password:30s} [{r.strength}]")

# Passphrase
phrase = generator.generate_passphrase(
    word_count=4,
    separator="-",
    capitalize=True,
    append_number=True,
)
print(phrase)  # e.g. "Swift-Ocean-Prism-Amber-47"
```

---

## ⚙️ Configuration Reference

### `PasswordConfig` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `length` | `int` | `16` | Password length (4–512) |
| `use_uppercase` | `bool` | `True` | Include A–Z |
| `use_lowercase` | `bool` | `True` | Include a–z |
| `use_digits` | `bool` | `True` | Include 0–9 |
| `use_special` | `bool` | `True` | Include special characters |
| `special_chars` | `str` | `!@#$%^&*()…` | Which special characters to use |
| `exclude_chars` | `str` | `""` | Characters to explicitly exclude |
| `exclude_ambiguous` | `bool` | `False` | Exclude `0O1lI\|` |
| `min_uppercase` | `int` | `0` | Minimum uppercase characters |
| `min_lowercase` | `int` | `0` | Minimum lowercase characters |
| `min_digits` | `int` | `0` | Minimum digit characters |
| `min_special` | `int` | `0` | Minimum special characters |

### `PasswordResult` Fields

| Field | Type | Description |
|-------|------|-------------|
| `password` | `str` | The generated password |
| `strength` | `str` | Very Weak / Weak / Fair / Strong / Very Strong |
| `entropy_bits` | `float` | Shannon entropy: `length × log₂(charset_size)` |
| `length` | `int` | Password length |
| `char_types_used` | `list[str]` | Character types present |

---

## 🔬 How Security Works

This generator uses Python's [`secrets`](https://docs.python.org/3/library/secrets.html) module, which draws from the operating system's cryptographically secure pseudo-random number generator (CSPRNG):

- **Linux/macOS**: `/dev/urandom` (getrandom syscall)
- **Windows**: `CryptGenRandom`

This makes the generator suitable for generating passwords, API keys, tokens, and other security-sensitive values — unlike `random`, which is **not** suitable for cryptographic use.

### Entropy Formula

```
H = L × log₂(N)
```

Where `L` = password length and `N` = character set size.

| Entropy | Strength |
|---------|----------|
| < 28 bits | Very Weak |
| 28–36 bits | Weak |
| 36–60 bits | Fair |
| 60–80 bits | Strong |
| > 80 bits | Very Strong |

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage report
pytest --cov=password_generator --cov-report=term-missing

# Run a specific test class
pytest tests/ -k "TestGeneratePassphrase" -v
```

---

## 📁 Project Structure

```
password-generator/
├── password_generator.py   # Core module (PasswordConfig, PasswordGenerator)
├── cli.py                  # Command-line interface
├── tests/
│   └── test_password_generator.py  # Full test suite
├── docs/
├── setup.py
├── pyproject.toml
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

Please make sure all tests pass before submitting.

---

## 📄 License

MIT © [Your Name](https://github.com/yourusername)
