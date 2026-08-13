"""Command-line interface for SafePaste.

The GUI clipboard guard is the point of this project, but a CLI matters on its
own: it is how detection gets exercised in CI and shell scripts with no
display server involved, how `safepaste redact` slots into a paste-bin upload
step, and how a user adds an exclusion (`safepaste hash`) without the
plaintext secret ever touching a config file on disk -- only its SHA-256 does.

Every subcommand is a thin shell around the detector/redactor library; nothing
here decides what counts as a secret, and this file must never modify that
library except for a genuine bug fix. The one rule this file adds on top of
the library: no code path may print a matched secret value. Findings carry
offsets and rule ids, `--json` mirrors that, and `redact`'s stdout is the one
place secret-shaped text legitimately leaves the process, already sanitised.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import signal
import sys
import textwrap
from collections import Counter

from .detector import (
    CATEGORIES,
    CATEGORY_LABELS,
    Detector,
    Finding,
    Rule,
    RuleSet,
    load_default,
    summarise,
    value_hash,
)
from .detector.engine import DEFAULT_MAX_SCAN_BYTES, DEFAULT_REGEX_TIMEOUT
from .detector.rules import humanise
from .redactor import DEFAULT_PLACEHOLDER, RedactionStyle, redact

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# input handling
# --------------------------------------------------------------------------


def _read_bytes(path: str) -> bytes:
    """Raw bytes from a path, or stdin when path is '-'."""
    if path == "-":
        return sys.stdin.buffer.read()
    return pathlib.Path(path).read_bytes()


def _decode(raw: bytes) -> str:
    """Bytes to text, tolerating malformed input instead of crashing a scan.

    Try strict decoding first and only fall back on failure, so the common
    case -- clipboard text that is legitimately multi-byte UTF-8 (accents,
    emoji, CJK) -- never trips a spurious warning.

    On genuine malformed input we fall back to errors="replace". The offsets
    Finding/scan report afterwards stay internally consistent (they index
    into *this* decoded string, which is the only string we ever scan), but
    they are NOT reliably a 1:1 map back to byte offsets in the original
    input: CPython's UTF-8 decoder follows the Unicode "maximal subpart"
    rule, so a truncated or otherwise malformed multi-byte lead sequence
    collapses into a SINGLE U+FFFD rather than one per bad byte (verified
    empirically -- e.g. b"\\xe2\\x82" is 2 bytes but decodes to 1 char, not
    2). An isolated invalid byte (e.g. b"\\xff") *is* 1:1. We say so on
    stderr rather than silently implying a byte-accurate offset.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        print(
            f"safepaste: input is not valid UTF-8; "
            f"{text.count(chr(0xFFFD))} malformed byte sequence(s) replaced "
            "with U+FFFD (reported offsets index the decoded text, not "
            "necessarily the raw bytes -- see cli.py's _decode() docstring)",
            file=sys.stderr,
        )
        return text


def _read_text_or_none(path: str) -> str | None:
    """`_read_bytes` + `_decode`, turned into the documented CLI contract:
    a missing/unreadable input prints one line to stderr instead of a
    traceback. Returns None on failure; the caller supplies the exit code.
    """
    try:
        raw = _read_bytes(path)
    except OSError as exc:
        print(f"safepaste: cannot read {path}: {exc.strerror or exc}", file=sys.stderr)
        return None
    return _decode(raw)


def _line_col(text: str, offset: int) -> tuple[int, int]:
    """1-based (line, column) for a character offset.

    1-based because that is what every editor and linter reports, so
    `line:col` from `scan` can be pasted straight into a "go to line" prompt.
    """
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    column = offset - line_start + 1
    return line, column


# --------------------------------------------------------------------------
# shared detector construction
# --------------------------------------------------------------------------


def _make_detector(args: argparse.Namespace) -> Detector:
    """Build the Detector shared by scan/redact/rules from the global flags."""
    ruleset = load_default(extra_paths=args.rule_paths)
    categories = frozenset(args.categories) if args.categories else None
    return Detector(
        ruleset=ruleset,
        categories=categories,
        regex_timeout=args.timeout,
        max_scan_bytes=args.max_bytes,
    )


def _finding_dict(finding: Finding, text: str) -> dict[str, object]:
    """Finding -> a JSON-safe dict: offsets and rule ids only, never the
    matched text, so this is safe to paste into a bug report as-is.
    """
    line, col = _line_col(text, finding.start)
    return {
        "rule_id": finding.rule_id,
        "label": finding.label,
        "category": finding.category,
        "start": finding.start,
        "end": finding.end,
        "length": finding.length,
        "entropy": finding.entropy,
        "line": line,
        "column": col,
    }


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    text = _read_text_or_none(args.path)
    if text is None:
        return 2

    findings = _make_detector(args).scan(text)

    if args.summary:
        summary = summarise(findings)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(f"secrets: {summary['secrets']}  findings: {summary['findings']}")
            print(f"categories: {', '.join(summary['categories']) or 'none'}")
            print(f"labels: {', '.join(summary['labels']) or 'none'}")
            print(f"redacted_chars: {summary['redacted_chars']}")
    elif args.json:
        print(json.dumps([_finding_dict(f, text) for f in findings], indent=2))
    else:
        for f in findings:
            line, col = _line_col(text, f.start)
            # Some rules carry no entropy threshold (the pattern is already
            # specific enough), so Finding.entropy is None -- show "n/a"
            # rather than fabricate a number.
            entropy_str = f"{f.entropy:.2f}" if f.entropy is not None else "n/a"
            print(
                f"{line}:{col}  {f.rule_id}  {f.label}  "
                f"({f.length} chars, entropy {entropy_str})"
            )

    # However the findings were rendered above, the exit code always reflects
    # "was anything found" -- that is the one thing a shell composes on
    # (`safepaste scan f && upload f`), independent of --json/--summary.
    return 1 if findings else 0


# --------------------------------------------------------------------------
# redact
# --------------------------------------------------------------------------


def cmd_redact(args: argparse.Namespace) -> int:
    text = _read_text_or_none(args.path)
    if text is None:
        return 2

    findings = _make_detector(args).scan(text)
    style = RedactionStyle(
        placeholder=args.placeholder,
        label_rules=args.label_rules,
        keep_prefix=args.keep_prefix,
    )
    result = redact(text, findings, style)

    # The redacted text IS the entire stdout contract -- `safepaste redact - >
    # clean.txt` must round-trip byte for byte apart from the replacements --
    # so write() rather than print() (no extra trailing newline invented) and
    # put every other word on stderr.
    sys.stdout.write(result.text)
    sys.stdout.flush()

    if result.changed:
        print(
            f"safepaste: redacted {result.secrets_removed} secret(s) "
            f"({result.chars_removed} chars replaced, {result.chars_kept} kept) "
            f"[{', '.join(result.labels)}]",
            file=sys.stderr,
        )
    else:
        print("safepaste: no secrets found, output unchanged", file=sys.stderr)

    # "Exit 0 always unless the input could not be read" -- finding secrets is
    # the expected, successful case for this command, not a failure.
    return 0


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------


def cmd_rules(args: argparse.Namespace) -> int:
    ruleset = load_default(extra_paths=args.rule_paths)
    categories = frozenset(args.categories) if args.categories else None
    rules = sorted(
        (r for r in ruleset.rules if categories is None or r.category in categories),
        key=lambda r: r.id,
    )

    if ruleset.skipped:
        log.debug(
            "skipped as path-only (no usable regex): %s",
            ", ".join(f"{rid} ({humanise(rid)})" for rid, _reason in ruleset.skipped),
        )

    if args.stats:
        _print_rule_stats(rules, ruleset, as_json=args.json)
    else:
        _print_rule_list(rules, ruleset, as_json=args.json)
    return 0


def _print_rule_list(rules: list[Rule], ruleset: RuleSet, *, as_json: bool) -> None:
    if as_json:
        payload = {
            "rules": [
                {
                    "id": r.id,
                    "label": r.label,
                    "category": r.category,
                    "entropy_gated": r.entropy is not None,
                    "enabled": r.enabled,
                    "default_off": r.default_off,
                    "active_by_default": r.enabled and not r.default_off,
                }
                for r in rules
            ],
            "skipped_path_only": len(ruleset.skipped),
        }
        print(json.dumps(payload, indent=2))
        return

    if rules:
        id_w = max(len(r.id) for r in rules)
        label_w = max(len(r.label) for r in rules)
        cat_w = max(len(CATEGORY_LABELS.get(r.category, r.category)) for r in rules)
        for r in rules:
            cat_label = CATEGORY_LABELS.get(r.category, r.category)
            entropy_flag = "yes" if r.entropy is not None else "no"
            # Three states, not two: vetoed, off-until-asked-for, or on.
            if not r.enabled:
                enabled_flag = "vetoed"
            elif r.default_off:
                enabled_flag = "opt-in"
            else:
                enabled_flag = "yes"
            print(
                f"{r.id:<{id_w}}  {r.label:<{label_w}}  {cat_label:<{cat_w}}  "
                f"entropy-gated={entropy_flag:<3} enabled={enabled_flag}"
            )
    else:
        print("no rules match the given --category filter", file=sys.stderr)

    print(f"{len(ruleset.skipped)} rule(s) skipped as path-only (no usable regex)")


def _print_rule_stats(rules: list[Rule], ruleset: RuleSet, *, as_json: bool) -> None:
    by_category = Counter(r.category for r in rules)
    vetoed = sum(1 for r in rules if not r.enabled)
    opt_in = sum(1 for r in rules if r.enabled and r.default_off)
    enabled = len(rules) - vetoed - opt_in
    entropy_gated = sum(1 for r in rules if r.entropy is not None)

    if as_json:
        payload = {
            "total": len(rules),
            "by_category": {c: by_category.get(c, 0) for c in CATEGORIES},
            "active_by_default": enabled,
            "opt_in": opt_in,
            "vetoed": vetoed,
            "entropy_gated": entropy_gated,
            "skipped_path_only": len(ruleset.skipped),
        }
        print(json.dumps(payload, indent=2))
        return

    print(f"total rules: {len(rules)}")
    for c in CATEGORIES:
        print(f"  {CATEGORY_LABELS[c]:<22} {by_category.get(c, 0)}")
    print(f"active by default: {enabled}  opt-in: {opt_in}  vetoed: {vetoed}")
    print(f"entropy-gated: {entropy_gated}")
    print(f"skipped as path-only (no usable regex): {len(ruleset.skipped)}")


# --------------------------------------------------------------------------
# hash
# --------------------------------------------------------------------------


def cmd_hash(args: argparse.Namespace) -> int:
    try:
        raw = sys.stdin.buffer.read()
    except OSError as exc:
        print(f"safepaste: cannot read stdin: {exc}", file=sys.stderr)
        return 2

    text = _decode(raw)
    # Strip exactly one trailing newline -- what a shell's `printf`/`echo`
    # adds -- and nothing else. rstrip() would also eat leading/trailing
    # spaces that could be part of the actual secret.
    if text.endswith("\n"):
        text = text[:-1]

    log.debug("hashing %d char(s) read from stdin", len(text))
    print(value_hash(text))
    return 0


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    # A single parent holds every cross-cutting flag so scan/redact/rules/hash
    # all accept the same set. Deliberately NOT also added to the top-level
    # `safepaste` parser: argparse's subparsers action parses each
    # subcommand's slice of argv into a *fresh* namespace and then blindly
    # copies it over the parent's, so a dest shared with the top-level parser
    # gets silently reset to its subparser default whenever the flag was only
    # given before the subcommand name (verified empirically -- `safepaste -v
    # scan -` produced no DEBUG output; `safepaste scan -v -` did). Requiring
    # these after the subcommand, e.g. `safepaste scan -v -`, avoids that trap
    # entirely: a flag placed too early is now a loud usage error instead of a
    # silent no-op.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log at DEBUG level, to stderr (stdout is never touched by logging)",
    )
    common.add_argument(
        "--category",
        dest="categories",
        action="append",
        choices=CATEGORIES,
        metavar="NAME",
        help="restrict to this detection category (repeatable); default: all. "
        "For `rules`, filters the listing instead of restricting a scan.",
    )
    common.add_argument(
        "--rules",
        dest="rule_paths",
        action="append",
        type=pathlib.Path,
        metavar="PATH",
        help="extra Gitleaks-format TOML rule file, loaded after the bundled "
        "set (repeatable)",
    )
    common.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=DEFAULT_REGEX_TIMEOUT,
        metavar="SECONDS",
        help=f"per-rule regex timeout (default: {DEFAULT_REGEX_TIMEOUT})",
    )
    common.add_argument(
        "--max-bytes",
        dest="max_bytes",
        type=int,
        default=DEFAULT_MAX_SCAN_BYTES,
        metavar="N",
        help=f"scan at most this many input bytes (default: {DEFAULT_MAX_SCAN_BYTES})",
    )

    epilog = textwrap.dedent(
        """\
        examples:
          safepaste scan document.txt
          wl-paste | safepaste scan -
          safepaste scan --json - < paste.txt
          safepaste redact - < paste.txt > clean.txt
          safepaste rules --stats
          printf '%s' "$SECRET" | safepaste hash
        """
    )
    parser = argparse.ArgumentParser(
        prog="safepaste",
        description="Detect and redact secrets in text, from the command line.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser(
        "scan",
        parents=[common],
        help="find secrets in a file or stdin; exit 1 if any were found",
    )
    scan_p.add_argument(
        "path", nargs="?", default="-", help="file to scan, or - for stdin (default)"
    )
    scan_p.add_argument(
        "--json",
        action="store_true",
        help="print findings as a JSON array (rule_id, label, category, start, "
        "end, length, entropy, line, column) instead of text",
    )
    scan_p.add_argument(
        "--summary",
        action="store_true",
        help="print only summarise()'s aggregate (secret/finding counts, "
        "categories, labels) instead of one line per finding",
    )
    scan_p.set_defaults(func=cmd_scan)

    redact_p = subparsers.add_parser(
        "redact",
        parents=[common],
        help="write the redacted text to stdout; counts go to stderr",
    )
    redact_p.add_argument(
        "path", nargs="?", default="-", help="file to redact, or - for stdin (default)"
    )
    redact_p.add_argument(
        "--placeholder",
        default=DEFAULT_PLACEHOLDER,
        metavar="TEXT",
        help=f"replacement text (default: {DEFAULT_PLACEHOLDER!r})",
    )
    redact_p.add_argument(
        "--label-rules",
        action="store_true",
        help="name the firing rule(s) in the placeholder, e.g. "
        "[REDACTED:aws-access-token]",
    )
    redact_p.add_argument(
        "--keep-prefix",
        type=int,
        default=0,
        metavar="N",
        help="keep the first N characters of each secret before the placeholder",
    )
    redact_p.set_defaults(func=cmd_redact)

    rules_p = subparsers.add_parser(
        "rules",
        parents=[common],
        help="list loaded detection rules",
    )
    rules_p.add_argument(
        "--json", action="store_true", help="print as JSON instead of a table"
    )
    rules_p.add_argument(
        "--stats",
        action="store_true",
        help="print counts by category and totals instead of listing each rule",
    )
    rules_p.set_defaults(func=cmd_rules)

    hash_p = subparsers.add_parser(
        "hash",
        parents=[common],
        help="hash a stdin value for use as an exclusion",
        description="Read a value from stdin and print its value_hash() "
        "(SHA-256, hex). Exactly one trailing newline is stripped if present "
        "(what a shell's printf/echo adds) and nothing else -- so this is how "
        "you add an exclusion by hand without ever writing the plaintext "
        "secret into a config file.",
    )
    hash_p.set_defaults(func=cmd_hash)

    return parser


def _configure_logging(verbose: bool) -> None:
    """Route the library's own log.* calls to stderr, never stdout.

    Quiet by default (WARNING and above -- e.g. an uncompilable user rule) so
    a script piping `safepaste scan`'s stdout is not polluted; -v additionally
    surfaces the INFO/DEBUG detail (rule counts, per-scan timing) that matters
    when something looks wrong but nothing is technically an error.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    pkg_logger = logging.getLogger("safepaste")
    pkg_logger.handlers.clear()  # idempotent if main() runs more than once in-process
    pkg_logger.addHandler(handler)
    pkg_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    pkg_logger.propagate = False  # don't also hand these to the root logger


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    try:
        return args.func(args)
    except BrokenPipeError:
        # A downstream reader (`safepaste scan huge.txt | head`) exited before
        # we finished writing. Redirect the real fd before this frame unwinds
        # so the interpreter's own shutdown-time flush doesn't print an
        # "Exception ignored" traceback -- see the CPython docs' io module
        # notes ("Note on SIGPIPE") for why this dance is necessary.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
        return 128 + signal.SIGPIPE
    except KeyboardInterrupt:
        print("safepaste: interrupted", file=sys.stderr)
        return 130


# `python -m safepaste.cli` is what you reach for when the installed entry point
# is the thing under suspicion. Without this it imported the module, ran nothing
# and exited 0, which looks exactly like "the detector found no rules".
if __name__ == "__main__":
    raise SystemExit(main())
