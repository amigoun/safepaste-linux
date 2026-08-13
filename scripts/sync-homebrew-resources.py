#!/usr/bin/env python3
"""Regenerate the Homebrew formula's resource blocks from PyPI.

`brew update-python-resources` does this too, but only on a machine with Homebrew.
This works anywhere, which matters because the formula is edited on Linux and only
ever *tested* on macOS.

A wrong hash is worse than a missing formula: the install fails at the download step
with nothing useful to say. So these are always generated, never typed.

    python3 scripts/sync-homebrew-resources.py [--check]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.request

FORMULA = pathlib.Path(__file__).resolve().parent.parent / "Formula" / "safepaste.rb"


def sdist(name: str) -> tuple[str, str, str]:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as r:
        data = json.load(r)
    for url in data["urls"]:
        if url["packagetype"] == "sdist":
            return data["info"]["version"], url["url"], url["digests"]["sha256"]
    raise SystemExit(f"{name} publishes no source distribution; a formula cannot build it")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify without rewriting")
    args = ap.parse_args()

    text = FORMULA.read_text(encoding="utf-8")
    resources = re.findall(
        r'resource "([^"]+)" do\n    url "([^"]+)"\n    sha256 "([^"]+)"', text
    )
    if not resources:
        raise SystemExit("no resource blocks found; has the formula layout changed?")

    stale = []
    for name, url, sha in resources:
        version, real_url, real_sha = sdist(name)
        fresh = sha == real_sha
        print(f"  {name:32} {version:12} {'current' if fresh else 'STALE'}")
        if not fresh:
            stale.append((name, url, sha, real_url, real_sha))

    if not stale:
        print("\n  all resource hashes match PyPI")
        return 0
    if args.check:
        print(f"\n  {len(stale)} resource(s) out of date; run without --check to update")
        return 1

    for _name, url, sha, real_url, real_sha in stale:
        text = text.replace(f'url "{url}"', f'url "{real_url}"')
        text = text.replace(f'sha256 "{sha}"', f'sha256 "{real_sha}"')
    FORMULA.write_text(text, encoding="utf-8")
    print(f"\n  updated {len(stale)} resource(s) in {FORMULA.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
