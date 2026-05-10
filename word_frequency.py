"""
word_frequency.py
-----------------
Counts word frequencies in a text file and prints the top N most common words.

Usage:
    python word_frequency.py <file_path> [--top N]

Example:
    python word_frequency.py my_text.txt --top 10
"""

import argparse
import re
from collections import Counter


def count_words(file_path: str) -> Counter:
    """Read a file and return a Counter of lowercase word frequencies."""
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()
    words = re.findall(r"[a-z']+", text.lower())
    return Counter(words)


def main():
    parser = argparse.ArgumentParser(description="Count word frequencies in a text file.")
    parser.add_argument("file", help="Path to the input text file")
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top words to display (default: 10)",
    )
    args = parser.parse_args()

    counts = count_words(args.file)
    print(f"Top {args.top} words in '{args.file}':\n")
    for rank, (word, freq) in enumerate(counts.most_common(args.top), start=1):
        print(f"  {rank:>3}. {word:<20} {freq}")


if __name__ == "__main__":
    main()
