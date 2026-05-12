"""
Password Generator - Command Line Interface
"""

import argparse
import json
import sys
from password_generator import PasswordConfig, PasswordGenerator


STRENGTH_COLORS = {
    "Very Weak":   "\033[91m",   # red
    "Weak":        "\033[93m",   # yellow
    "Fair":        "\033[94m",   # blue
    "Strong":      "\033[92m",   # green
    "Very Strong": "\033[92;1m", # bold green
}
RESET = "\033[0m"


def colored_strength(strength: str, use_color: bool) -> str:
    if not use_color:
        return strength
    color = STRENGTH_COLORS.get(strength, "")
    return f"{color}{strength}{RESET}"


def print_result(result, show_details: bool, use_color: bool, index: int = None):
    prefix = f"[{index}] " if index is not None else ""
    print(f"{prefix}{result.password}")
    if show_details:
        strength = colored_strength(result.strength, use_color)
        print(f"     Strength : {strength}")
        print(f"     Entropy  : {result.entropy_bits:.1f} bits")
        print(f"     Length   : {result.length}")
        print(f"     Types    : {', '.join(result.char_types_used)}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passgen",
        description="🔐 Secure Password Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  passgen                            # 1 password, 16 chars, all types
  passgen -l 24 -c 5                 # 5 passwords, 24 chars each
  passgen -l 32 --no-special         # no special characters
  passgen --min-digits 2 --min-upper 2
  passgen --passphrase               # memorable passphrase
  passgen --passphrase --words 5     # 5-word passphrase
  passgen -l 20 --output json        # output as JSON
        """,
    )

    # Length / count
    parser.add_argument("-l", "--length", type=int, default=16,
                        help="Password length (default: 16)")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of passwords to generate (default: 1)")

    # Character types
    char_group = parser.add_argument_group("Character types")
    char_group.add_argument("--no-upper", action="store_true",
                            help="Exclude uppercase letters")
    char_group.add_argument("--no-lower", action="store_true",
                            help="Exclude lowercase letters")
    char_group.add_argument("--no-digits", action="store_true",
                            help="Exclude digits")
    char_group.add_argument("--no-special", action="store_true",
                            help="Exclude special characters")
    char_group.add_argument("--special-chars", type=str,
                            default="!@#$%^&*()-_=+[]{}|;:,.<>?",
                            help="Custom set of special characters")
    char_group.add_argument("--exclude", type=str, default="",
                            metavar="CHARS",
                            help="Characters to explicitly exclude")
    char_group.add_argument("--no-ambiguous", action="store_true",
                            help="Exclude ambiguous chars (0,O,1,l,I,|)")

    # Minimums
    min_group = parser.add_argument_group("Minimum character requirements")
    min_group.add_argument("--min-upper", type=int, default=0,
                           help="Minimum uppercase characters")
    min_group.add_argument("--min-lower", type=int, default=0,
                           help="Minimum lowercase characters")
    min_group.add_argument("--min-digits", type=int, default=0,
                           help="Minimum digit characters")
    min_group.add_argument("--min-special", type=int, default=0,
                           help="Minimum special characters")

    # Passphrase mode
    phrase_group = parser.add_argument_group("Passphrase mode")
    phrase_group.add_argument("--passphrase", action="store_true",
                              help="Generate a memorable passphrase instead")
    phrase_group.add_argument("--words", type=int, default=4,
                              help="Number of words in passphrase (default: 4)")
    phrase_group.add_argument("--separator", type=str, default="-",
                              help="Word separator (default: -)")
    phrase_group.add_argument("--no-capitalize", action="store_true",
                              help="Do not capitalize passphrase words")
    phrase_group.add_argument("--no-number", action="store_true",
                              help="Do not append number to passphrase")

    # Output
    out_group = parser.add_argument_group("Output options")
    out_group.add_argument("--output", choices=["plain", "json", "csv"],
                           default="plain",
                           help="Output format (default: plain)")
    out_group.add_argument("--details", action="store_true",
                           help="Show strength, entropy, and character type info")
    out_group.add_argument("--no-color", action="store_true",
                           help="Disable colored output")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    generator = PasswordGenerator()
    use_color = not args.no_color and sys.stdout.isatty()

    # ── Passphrase mode ──────────────────────────────────────────────────────
    if args.passphrase:
        passphrases = [
            generator.generate_passphrase(
                word_count=args.words,
                separator=args.separator,
                capitalize=not args.no_capitalize,
                append_number=not args.no_number,
            )
            for _ in range(args.count)
        ]

        if args.output == "json":
            print(json.dumps(passphrases, indent=2))
        elif args.output == "csv":
            print("\n".join(passphrases))
        else:
            for i, pp in enumerate(passphrases, 1):
                prefix = f"[{i}] " if args.count > 1 else ""
                print(f"{prefix}{pp}")
        return

    # ── Password mode ────────────────────────────────────────────────────────
    try:
        config = PasswordConfig(
            length=args.length,
            use_uppercase=not args.no_upper,
            use_lowercase=not args.no_lower,
            use_digits=not args.no_digits,
            use_special=not args.no_special,
            special_chars=args.special_chars,
            exclude_chars=args.exclude,
            exclude_ambiguous=args.no_ambiguous,
            min_uppercase=args.min_upper,
            min_lowercase=args.min_lower,
            min_digits=args.min_digits,
            min_special=args.min_special,
        )
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        results = generator.generate_batch(args.count, config)
    except ValueError as e:
        print(f"Generation error: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Output formatting ────────────────────────────────────────────────────
    if args.output == "json":
        out = [
            {
                "password": r.password,
                "strength": r.strength,
                "entropy_bits": round(r.entropy_bits, 2),
                "length": r.length,
                "char_types_used": r.char_types_used,
            }
            for r in results
        ]
        print(json.dumps(out if args.count > 1 else out[0], indent=2))

    elif args.output == "csv":
        print("password,strength,entropy_bits,length,char_types")
        for r in results:
            types = "|".join(r.char_types_used)
            print(f"{r.password},{r.strength},{r.entropy_bits:.2f},{r.length},{types}")

    else:  # plain
        show_index = args.count > 1
        for i, result in enumerate(results, 1):
            idx = i if show_index else None
            print_result(result, args.details, use_color, index=idx)


if __name__ == "__main__":
    main()
