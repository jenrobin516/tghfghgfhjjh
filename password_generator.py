"""
password_generator.py
----------------------
Generates one or more cryptographically secure random passwords.

Usage:
    python password_generator.py [--length N] [--count N]
                                 [--no-upper] [--no-lower]
                                 [--no-digits] [--no-symbols]

Example:
    python password_generator.py --length 20 --count 5
    python password_generator.py --length 12 --no-symbols
"""

import argparse
import secrets
import string


def build_alphabet(
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Return the character pool based on the chosen options."""
    pool = ""
    if upper:
        pool += string.ascii_uppercase
    if lower:
        pool += string.ascii_lowercase
    if digits:
        pool += string.digits
    if symbols:
        pool += string.punctuation
    if not pool:
        raise ValueError("At least one character class must be enabled.")
    return pool


def generate_password(length: int, alphabet: str) -> str:
    """Return a single password of *length* characters drawn from *alphabet*."""
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main():
    parser = argparse.ArgumentParser(description="Generate secure random passwords.")
    parser.add_argument(
        "--length", type=int, default=16, metavar="N",
        help="Length of each password (default: 16)",
    )
    parser.add_argument(
        "--count", type=int, default=1, metavar="N",
        help="Number of passwords to generate (default: 1)",
    )
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude symbol characters")
    args = parser.parse_args()

    alphabet = build_alphabet(
        upper=not args.no_upper,
        lower=not args.no_lower,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
    )

    for _ in range(args.count):
        print(generate_password(args.length, alphabet))


if __name__ == "__main__":
    main()
