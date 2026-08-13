#!/usr/bin/env python3
"""Vendor the Gitleaks rule set at a pinned tag, validating it on the way in.

Run this at packaging time, not at runtime — SafePaste makes no network calls
once installed. The point of doing it here rather than shipping a submodule is
the validation: every rule is compiled and classified now, so a Go-RE2 pattern
that Python cannot handle fails the build instead of silently disabling a
detector on someone's desktop.

    scripts/fetch-rules.py [--tag v8.30.1] [--check]

--check verifies the vendored copy still matches its recorded digest and that
every rule compiles, without touching the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib
import urllib.request

# Pinned deliberately. Bumping this is a reviewed change: new rules alter what
# gets flagged on every user's clipboard.
DEFAULT_TAG = "v8.30.1"
URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/config/gitleaks.toml"

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "safepaste" / "detector" / "data"
VENDORED = DATA / "gitleaks.toml"
PROVENANCE = DATA / "gitleaks.provenance.json"


def fetch(tag: str) -> bytes:
    url = URL.format(tag=tag)
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed https host
        if r.status != 200:
            sys.exit(f"HTTP {r.status} fetching {url}")
        return r.read()


def validate(raw: bytes) -> dict:
    """Compile every rule; return a summary. Exits non-zero on any failure."""
    try:
        import regex
    except ImportError:
        sys.exit("the `regex` module is required: apt install python3-regex")

    # Validate through the same RE2->Python translation the runtime applies.
    # Without this the check passes against a modern pip `regex` while the
    # installed package silently drops rules on the distro's older one.
    sys.path.insert(0, str(ROOT))
    from safepaste.detector.rules import translate_re2

    print(f"regex module version: {getattr(regex, '__version__', 'unknown')}")

    doc = tomllib.loads(raw.decode("utf-8"))
    rules = doc.get("rules") or []
    if not rules:
        sys.exit("no [[rules]] found — did the upstream layout change?")

    failures: list[str] = []
    path_only: list[str] = []
    no_keywords: list[str] = []
    with_entropy = 0
    with_groups = 0

    for r in rules:
        rid = r.get("id", "<missing id>")
        pattern = r.get("regex")
        if not pattern:
            # e.g. pkcs12-file, which matches on file path alone. Useless for a
            # clipboard, so it is expected here and skipped at load time too.
            path_only.append(rid)
            continue
        try:
            compiled = regex.compile(translate_re2(pattern))
        except Exception as exc:  # noqa: BLE001 - reporting every failure at once
            failures.append(f"{rid}: {type(exc).__name__}: {exc}")
            continue
        if compiled.groups:
            with_groups += 1
        if r.get("entropy"):
            with_entropy += 1
        if not r.get("keywords"):
            no_keywords.append(rid)

    if failures:
        print(f"\n{len(failures)} rule(s) failed to compile:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)

    summary = {
        "rules_total": len(rules),
        "rules_with_regex": len(rules) - len(path_only),
        "rules_with_capture_groups": with_groups,
        "rules_with_entropy": with_entropy,
        "path_only_skipped": sorted(path_only),
        "no_keyword_prefilter": sorted(no_keywords),
        "global_stopwords": len(doc.get("allowlist", {}).get("stopwords", [])),
        "global_allowlist_regexes": len(doc.get("allowlist", {}).get("regexes", [])),
    }
    print("\nvalidation passed:")
    for k, v in summary.items():
        shown = v if not isinstance(v, list) else (v or "none")
        print(f"  {k}: {shown}")
    if no_keywords:
        print(
            f"  note: {len(no_keywords)} rule(s) have no keywords and so run on "
            "every scan — watch the benchmark."
        )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=DEFAULT_TAG)
    ap.add_argument(
        "--check",
        action="store_true",
        help="validate the vendored copy offline instead of fetching",
    )
    args = ap.parse_args()

    if args.check:
        if not VENDORED.exists():
            sys.exit(f"{VENDORED} missing — run without --check first")
        raw = VENDORED.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if PROVENANCE.exists():
            recorded = json.loads(PROVENANCE.read_text())["sha256"]
            if recorded != digest:
                sys.exit(f"digest drift!\n  recorded {recorded}\n  actual   {digest}")
            print(f"digest matches provenance ({digest[:16]}…)")
        validate(raw)
        return 0

    raw = fetch(args.tag)
    summary = validate(raw)

    DATA.mkdir(parents=True, exist_ok=True)
    VENDORED.write_bytes(raw)
    PROVENANCE.write_text(
        json.dumps(
            {
                "source": URL.format(tag=args.tag),
                "tag": args.tag,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "summary": summary,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"\nwrote {VENDORED} ({len(raw)} bytes) and {PROVENANCE.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
