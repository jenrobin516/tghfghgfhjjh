"""
csv_to_json.py
--------------
Converts a CSV file to a JSON file.

Usage:
    python csv_to_json.py <input.csv> [output.json] [--indent N]

Example:
    python csv_to_json.py data.csv
    python csv_to_json.py data.csv result.json --indent 4
"""

import argparse
import csv
import json
from pathlib import Path


def csv_to_json(
    input_path: Path,
    output_path: Path,
    indent: int = 2,
) -> int:
    """Convert *input_path* CSV to *output_path* JSON. Returns row count."""
    with input_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = list(reader)

    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(rows, json_file, indent=indent, ensure_ascii=False)

    return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Convert a CSV file to JSON.")
    parser.add_argument("input", help="Path to the input CSV file")
    parser.add_argument(
        "output", nargs="?", default=None,
        help="Path for the output JSON file (default: same name as input with .json extension)",
    )
    parser.add_argument(
        "--indent", type=int, default=2, metavar="N",
        help="JSON indentation level (default: 2; use 0 for compact output)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix(".json")
    indent = args.indent if args.indent > 0 else None

    count = csv_to_json(input_path, output_path, indent=indent)
    print(f"Converted {count} row(s) from '{input_path}' → '{output_path}'")


if __name__ == "__main__":
    main()
