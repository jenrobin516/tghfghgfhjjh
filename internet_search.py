#!/usr/bin/env python3
"""
internet_search.py — Multi-Backend Internet Search Script
==========================================================
Performs programmatic web searches from the command line and optionally
saves results to JSON or CSV.

Backends
--------
  1. DuckDuckGo  (default) — no API key required; uses the HTML endpoint
  2. Google CSE            — requires a Google API key + Custom Search Engine ID

Features
--------
  • Configurable number of results
  • Optional snippet/description extraction
  • Export to JSON or CSV
  • Rate-limiting / retry logic to handle transient blocks
  • Colourised terminal output

Dependencies
------------
    pip install requests beautifulsoup4

Usage
-----
    # Quick DuckDuckGo search (prints to terminal)
    python internet_search.py "reverse engineering tools"

    # Fetch 15 results and save as JSON
    python internet_search.py "python malware analysis" -n 15 -o results.json

    # Save as CSV
    python internet_search.py "capstone disassembler tutorial" -o results.csv

    # Use Google CSE backend (set env vars or pass flags)
    python internet_search.py "shellcode injection" --backend google \\
        --google-api-key YOUR_KEY --google-cse-id YOUR_CSE_ID

    # Disable colour (e.g. when piping output)
    python internet_search.py "YARA rules" --no-color
"""

import argparse
import csv
import json
import os
import sys
import time
from typing import Any

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit(
        "[!] Missing dependencies.  Run:  pip install requests beautifulsoup4"
    )

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
DIM    = "\033[2m"


def c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


# ---------------------------------------------------------------------------
# Search backends
# ---------------------------------------------------------------------------

_DDG_URL  = "https://html.duckduckgo.com/html/"
_DDG_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


def search_duckduckgo(query: str, num: int, retries: int = 3) -> list[dict[str, str]]:
    """
    Search DuckDuckGo via the plain-HTML endpoint (no API key needed).
    Returns a list of {'title', 'url', 'snippet'} dicts.
    """
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                _DDG_URL,
                data={"q": query},
                headers=_DDG_HEADERS,
                timeout=15,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            if attempt == retries:
                sys.exit(f"[!] DuckDuckGo request failed: {exc}")
            time.sleep(2 ** attempt)
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        results: list[dict[str, str]] = []

        for a in soup.find_all("a", class_="result__a", limit=num):
            title   = a.get_text(strip=True)
            raw_url = a.get("href", "")
            # DDG wraps URLs in a redirect — extract the real URL
            url = _unwrap_ddg_url(raw_url)

            # Snippet lives in the sibling .result__snippet span
            snippet_tag = None
            parent = a.find_parent("div", class_="result")
            if parent:
                snippet_tag = parent.find("a", class_="result__snippet")
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""

            results.append({"title": title, "url": url, "snippet": snippet})

        return results

    return []


def _unwrap_ddg_url(href: str) -> str:
    """DuckDuckGo wraps result URLs; extract the real destination."""
    if href.startswith("//duckduckgo.com/l/?"):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse("https:" + href).query)
        uddg = qs.get("uddg", [""])[0]
        return uddg if uddg else href
    return href


def search_google_cse(
    query: str,
    num: int,
    api_key: str,
    cse_id: str,
) -> list[dict[str, str]]:
    """
    Search using the Google Custom Search JSON API.
    Requires a valid API key and Custom Search Engine ID.
    Docs: https://developers.google.com/custom-search/v1/reference/rest/v1/cse/list
    """
    endpoint = "https://www.googleapis.com/customsearch/v1"
    results: list[dict[str, str]] = []

    # API returns max 10 per request; page through if needed
    fetched = 0
    start   = 1
    per_req = 10

    while fetched < num:
        params = {
            "key": api_key,
            "cx":  cse_id,
            "q":   query,
            "num": min(per_req, num - fetched),
            "start": start,
        }
        try:
            resp = requests.get(endpoint, params=params, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            sys.exit(f"[!] Google CSE request failed: {exc}")

        data = resp.json()
        items = data.get("items", [])
        if not items:
            break

        for item in items:
            results.append({
                "title":   item.get("title", ""),
                "url":     item.get("link", ""),
                "snippet": item.get("snippet", "").replace("\n", " "),
            })
            fetched += 1
            if fetched >= num:
                break

        start += per_req
        # Respect the API's own rate limit
        time.sleep(0.3)

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_results(
    results: list[dict[str, str]],
    query: str,
    backend: str,
    color: bool,
) -> None:
    header = f"\n  Search: {query!r}  [{backend}]  — {len(results)} result(s)\n"
    print(c(header, BOLD, color))
    print("  " + "─" * 70)

    for i, r in enumerate(results, 1):
        num_str  = c(f"[{i:>2}]", CYAN,   color)
        title    = c(r["title"],   BOLD,   color)
        url      = c(r["url"],     GREEN,  color)
        snippet  = c(r["snippet"], DIM,    color)

        print(f"\n  {num_str}  {title}")
        print(f"       {url}")
        if r["snippet"]:
            print(f"       {snippet}")

    print()


def save_results(results: list[dict[str, str]], path: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"[*] Saved {len(results)} results → {path}  (JSON)")
    elif ext == ".csv":
        fieldnames = ["title", "url", "snippet"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"[*] Saved {len(results)} results → {path}  (CSV)")
    else:
        sys.exit(f"[!] Unsupported output format '{ext}'.  Use .json or .csv")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search the internet from the command line.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("query", help="Search query string")
    parser.add_argument(
        "-n", "--num", type=int, default=10, metavar="N",
        help="Number of results to fetch (default: 10)",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save results to a file (.json or .csv)",
    )
    parser.add_argument(
        "--backend", choices=["duckduckgo", "google"], default="duckduckgo",
        help="Search backend to use (default: duckduckgo)",
    )
    parser.add_argument(
        "--google-api-key", default=os.environ.get("GOOGLE_API_KEY", ""),
        metavar="KEY",
        help="Google Custom Search API key (or set GOOGLE_API_KEY env var)",
    )
    parser.add_argument(
        "--google-cse-id", default=os.environ.get("GOOGLE_CSE_ID", ""),
        metavar="ID",
        help="Google Custom Search Engine ID (or set GOOGLE_CSE_ID env var)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output",
    )
    args = parser.parse_args()

    color = not args.no_color and sys.stdout.isatty()

    # Run search
    if args.backend == "duckduckgo":
        print(f"[*] Searching DuckDuckGo for: {args.query!r}")
        results = search_duckduckgo(args.query, args.num)
    else:
        if not args.google_api_key or not args.google_cse_id:
            sys.exit(
                "[!] Google backend requires --google-api-key and --google-cse-id\n"
                "    (or set GOOGLE_API_KEY and GOOGLE_CSE_ID environment variables)"
            )
        print(f"[*] Searching Google CSE for: {args.query!r}")
        results = search_google_cse(
            args.query, args.num, args.google_api_key, args.google_cse_id
        )

    if not results:
        print("[!] No results returned.  Try a different query or backend.")
        sys.exit(1)

    # Display
    print_results(results, args.query, args.backend, color)

    # Export if requested
    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
