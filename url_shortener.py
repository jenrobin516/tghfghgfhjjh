"""
url_shortener.py
-----------------
A simple in-memory URL shortener / expander.

Usage (interactive REPL):
    python url_shortener.py

Commands inside the REPL:
    shorten <url>       – create a short code for <url>
    expand  <code>      – look up the original URL for <code>
    list                – show all stored mappings
    delete  <code>      – remove a mapping
    quit / exit         – exit the program

Example:
    > shorten https://www.example.com/some/very/long/path?query=1
    Shortened: abc12X  ->  https://www.example.com/some/very/long/path?query=1

    > expand abc12X
    https://www.example.com/some/very/long/path?query=1
"""

import secrets
import string

SLUG_CHARS = string.ascii_letters + string.digits
SLUG_LENGTH = 6


def generate_slug(existing: set) -> str:
    """Return a unique random slug not already in *existing*."""
    while True:
        slug = "".join(secrets.choice(SLUG_CHARS) for _ in range(SLUG_LENGTH))
        if slug not in existing:
            return slug


class URLShortener:
    def __init__(self):
        self._short_to_long: dict[str, str] = {}
        self._long_to_short: dict[str, str] = {}

    def shorten(self, url: str) -> str:
        """Return the slug for *url*, creating one if needed."""
        if url in self._long_to_short:
            return self._long_to_short[url]
        slug = generate_slug(set(self._short_to_long))
        self._short_to_long[slug] = url
        self._long_to_short[url] = slug
        return slug

    def expand(self, slug: str) -> str | None:
        """Return the original URL for *slug*, or None if not found."""
        return self._short_to_long.get(slug)

    def delete(self, slug: str) -> bool:
        """Remove *slug*. Returns True if it existed, False otherwise."""
        url = self._short_to_long.pop(slug, None)
        if url is None:
            return False
        self._long_to_short.pop(url, None)
        return True

    def all_mappings(self) -> list[tuple[str, str]]:
        """Return all (slug, url) pairs sorted by slug."""
        return sorted(self._short_to_long.items())


def main():
    shortener = URLShortener()
    print("URL Shortener — type 'help' for commands, 'quit' to exit.\n")

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit"):
            break
        elif cmd == "help":
            print("  shorten <url>   – create a short code")
            print("  expand  <code>  – look up the original URL")
            print("  list            – show all mappings")
            print("  delete  <code>  – remove a mapping")
            print("  quit            – exit")
        elif cmd == "shorten":
            if not arg:
                print("Usage: shorten <url>")
            else:
                slug = shortener.shorten(arg)
                print(f"Shortened: {slug}  ->  {arg}")
        elif cmd == "expand":
            if not arg:
                print("Usage: expand <code>")
            else:
                url = shortener.expand(arg)
                if url:
                    print(url)
                else:
                    print(f"No URL found for code '{arg}'.")
        elif cmd == "list":
            mappings = shortener.all_mappings()
            if not mappings:
                print("(no mappings stored)")
            else:
                for slug, url in mappings:
                    print(f"  {slug}  ->  {url}")
        elif cmd == "delete":
            if not arg:
                print("Usage: delete <code>")
            elif shortener.delete(arg):
                print(f"Deleted '{arg}'.")
            else:
                print(f"Code '{arg}' not found.")
        else:
            print(f"Unknown command '{cmd}'. Type 'help' for a list of commands.")


if __name__ == "__main__":
    main()
