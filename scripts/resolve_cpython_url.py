#!/usr/bin/env python3
"""Resolves the official CPython 3.14.10 Android AArch64 archive URL from python.org."""
import re
import sys
import urllib.request

BASE_URL = "https://www.python.org/ftp/python/3.14.10/"


def main() -> int:
    try:
        html = urllib.request.urlopen(BASE_URL, timeout=30).read().decode("utf-8", "replace")
    except Exception as exc:
        print(f"ERROR: Failed to query {BASE_URL}: {exc}", file=sys.stderr)
        return 1

    pattern = re.compile(
        r'href=["\']([^"\']*(?:aarch64|arm64)[^"\']*android[^"\']*\.tar\.(?:gz|xz)'
        r'|[^"\']*android[^"\']*(?:aarch64|arm64)[^"\']*\.tar\.(?:gz|xz))["\']',
        re.IGNORECASE,
    )
    matches = pattern.findall(html)
    if not matches:
        print("ERROR: No Android AArch64 tarball link found on python.org", file=sys.stderr)
        return 1

    href = matches[0]
    if href.startswith("http://") or href.startswith("https://"):
        print(href)
    else:
        print(BASE_URL + href.lstrip("/"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
