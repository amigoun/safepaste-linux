#!/usr/bin/env python3
"""Regenerate the Homebrew formula's resource blocks from PyPI.

`brew update-python-resources` does this too, but only on a machine with Homebrew.
This works anywhere, which matters because the formula is edited on Linux and only
ever *tested* on macOS.

A wrong hash is worse than a missing formula: the install fails at the download step
with nothing useful to say. So these are always generated, never typed.

    python3 scripts/sync-homebrew-resources.py [--check]

Without --check, every resource moves to the latest release on PyPI. With it, each
pinned url and sha256 is verified against PyPI's record of that same release, and a
newer upstream release is only reported: CI runs --check on every push, and a pin
that is still exactly what PyPI published is not broken because something newer
exists.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

FORMULA = pathlib.Path(__file__).resolve().parent.parent / "Formula" / "safepaste.rb"


def pypi(project: str) -> dict:
    """PyPI's JSON record for a project, or for `project/version`."""
    url = f"https://pypi.org/pypi/{project}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def sdist(name: str) -> tuple[str, str, str]:
    data = pypi(name)
    for url in data["urls"]:
        if url["packagetype"] == "sdist":
            return data["info"]["version"], url["url"], url["digests"]["sha256"]
    raise SystemExit(f"{name} publishes no source distribution; a formula cannot build it")


def pinned_version(url: str) -> str:
    # An sdist is <name>-<version>.tar.gz, and a normalised name has no "-" left.
    filename = url.rsplit("/", 1)[-1]
    return filename.removesuffix(".tar.gz").removesuffix(".zip").rpartition("-")[2]


def pin_problem(name: str, version: str, url: str, sha: str) -> str | None:
    """What is wrong with a pinned resource, or None if PyPI vouches for it exactly."""
    filename = url.rsplit("/", 1)[-1]
    try:
        data = pypi(f"{name}/{version}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return f"{version} is not a release of {name} on PyPI"
        raise
    for published in data["urls"]:
        if published["url"] != url:
            continue
        if published["packagetype"] != "sdist":
            return f"{filename} is not a source distribution"
        if published["digests"]["sha256"] != sha:
            return f"sha256 differs from PyPI's record for {filename}"
        if published.get("yanked") or data["info"].get("yanked"):
            return f"{name} {version} has been yanked"
        return None
    return f"PyPI lists no {url} for {name} {version}"


def check(resources: list[tuple[str, str, str]]) -> int:
    broken = 0
    for name, url, sha in resources:
        version = pinned_version(url)
        problem = pin_problem(name, version, url, sha)
        latest = sdist(name)[0]
        status = f"BROKEN: {problem}" if problem else "pinned release matches"
        newer = f" ({latest} available)" if latest != version else ""
        print(f"  {name:32} {version:12} {status}{newer}")
        broken += problem is not None

    if broken:
        print(f"\n  {broken} pinned resource(s) do not match PyPI")
        return 1
    print("\n  every pinned resource matches its PyPI release")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the pinned versions against PyPI without rewriting",
    )
    args = ap.parse_args()

    text = FORMULA.read_text(encoding="utf-8")
    resources = re.findall(
        r'resource "([^"]+)" do\n    url "([^"]+)"\n    sha256 "([^"]+)"', text
    )
    if not resources:
        raise SystemExit("no resource blocks found; has the formula layout changed?")
    if args.check:
        return check(resources)

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

    for _name, url, sha, real_url, real_sha in stale:
        text = text.replace(f'url "{url}"', f'url "{real_url}"')
        text = text.replace(f'sha256 "{sha}"', f'sha256 "{real_sha}"')
    FORMULA.write_text(text, encoding="utf-8")
    print(f"\n  updated {len(stale)} resource(s) in {FORMULA.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
