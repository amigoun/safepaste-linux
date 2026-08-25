"""The detection pipeline.

Ordering is the whole false-positive strategy, so it is worth stating plainly:

  1. keyword prefilter  — skip any rule whose literal keywords are absent. This
     is where Gitleaks gets both its speed and most of its precision.
  2. regex, with a timeout — Gitleaks' patterns are Go RE2, which is linear-time
     by construction. Python's engine is not, so a per-call timeout is a
     requirement rather than a nicety.
  3. entropy — reject candidates that do not look random enough.
  4. allowlists — per-rule, then global: template placeholders, `${VAR}`, and so on.
  5. user exclusions — values the user has explicitly said to stop flagging,
     compared by a keyed digest so no plaintext is ever retained and no guess
     can be tested against the stored digest either (see `value_hash`).

Nothing here logs clipboard content. Findings carry offsets and rule ids only;
that invariant is enforced by tests/test_privacy.py.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass

import regex

from . import entropy as entropy_mod
from .rules import CATEGORY_LABELS, Rule, RuleSet, load_default

log = logging.getLogger(__name__)

# Clipboards can hold megabytes (a copied spreadsheet, a base64 image). Scanning
# all of it buys nothing and costs latency on every copy.
DEFAULT_MAX_SCAN_BYTES = 1_048_576
DEFAULT_REGEX_TIMEOUT = 0.25


# Named in the digest itself, so a config file states which algorithm produced
# its exclusions. That is what lets an entry written by an older SafePaste be
# recognised on sight rather than guessed at (safepaste.config drops those), and
# what makes adding a second scheme later a non-event.
EXCLUSION_SCHEME = "hmac-sha256"


def value_hash(secret: str, key: bytes) -> str:
    """Stable id for a secret value, for exclusions. Never reversible.

    Keyed, and that is the whole point. A bare SHA-256 is only one-way for values
    that were unguessable to begin with: `hunter2`, `admin` or a weak database
    password can be recovered from their digest by anyone who reads the exclusion
    list, one guess at a time, offline. HMAC under a key that lives outside
    config.toml leaves a reader of that file nothing to test a guess against.

    `key` is required rather than defaulted so that no call site can quietly
    produce the guessable form; see `safepaste.config.ensure_exclusion_key` for
    where the key comes from.
    """
    if not key:
        raise ValueError(
            "an exclusion digest needs a key; refusing to write an unkeyed one"
        )
    mac = hmac.new(key, secret.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return f"{EXCLUSION_SCHEME}:{mac.hexdigest()}"


def is_keyed_digest(entry: str) -> bool:
    """Whether an exclusion entry carries a keyed digest this version can check."""
    return entry.startswith(f"{EXCLUSION_SCHEME}:")


@dataclass(frozen=True)
class Finding:
    """One secret located in the text.

    `start`/`end` bound the *secret* and are what gets replaced. `match_start`/
    `match_end` bound the whole regex match, which is usually wider — it often
    includes the `API_KEY=` preamble that we deliberately keep.
    """

    rule_id: str
    label: str
    category: str
    start: int
    end: int
    match_start: int
    match_end: int
    entropy: float | None = None

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)


class Detector:
    def __init__(
        self,
        ruleset: RuleSet | None = None,
        *,
        categories: frozenset[str] | None = None,
        excluded_hashes: frozenset[str] = frozenset(),
        exclusion_key: bytes | None = None,
        regex_timeout: float = DEFAULT_REGEX_TIMEOUT,
        max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    ) -> None:
        self.ruleset = ruleset if ruleset is not None else load_default()
        self.categories = categories
        # Anything that is not a keyed digest cannot be checked, so it is dropped
        # here rather than silently never matching. Config drops these too; a
        # Detector built by hand (the CLI, a test) gets the same treatment.
        self.excluded_hashes = frozenset(
            h for h in excluded_hashes if is_keyed_digest(h)
        )
        unusable = len(excluded_hashes) - len(self.excluded_hashes)
        if unusable:
            log.warning(
                "ignoring %d exclusion(s) that are not %s digests",
                unusable,
                EXCLUSION_SCHEME,
            )
        self.exclusion_key = exclusion_key
        if self.excluded_hashes and exclusion_key is None:
            # Fail-safe: values the user dismissed get flagged again rather than
            # being let through on an unverifiable match.
            log.warning(
                "%d exclusion(s) cannot be checked without the exclusion key; "
                "those values will be flagged again",
                len(self.excluded_hashes),
            )
        self.regex_timeout = regex_timeout
        self.max_scan_bytes = max_scan_bytes
        self._active = self.ruleset.enabled_for(categories)

    @property
    def active_rules(self) -> list[Rule]:
        return self._active

    def _secret_span(self, m: regex.Match, rule: Rule) -> tuple[int, int] | None:
        """Which slice of the match is the secret itself.

        Mirrors Gitleaks: an explicit `secretGroup` wins; otherwise, if the
        pattern has any capture group, group 1 *is* the secret. That convention
        is why `AWS_SECRET_ACCESS_KEY=wJal…` can be redacted to
        `AWS_SECRET_ACCESS_KEY=[REDACTED]` rather than losing the whole line.
        """
        # `or` would be wrong here: a rule that explicitly sets `secretGroup = 0`
        # (meaning "the secret is the whole match") is falsy, and `0 or fallback`
        # discards it in favour of the fallback. Distinguish "unset" from "0".
        group = (
            rule.secret_group
            if rule.secret_group is not None
            else (1 if m.re.groups >= 1 else 0)
        )
        try:
            span = m.span(group)
        except (IndexError, regex.error):  # pragma: no cover - defensive
            return None
        if span == (-1, -1):  # group declared but did not participate
            span = m.span(0)
        return span if span[1] > span[0] else None

    def _is_excluded(self, secret: str) -> bool:
        """Whether the user has said to stop flagging this exact value.

        Both guards are for the common case rather than for correctness: most
        users exclude nothing, and an HMAC per surviving candidate is not free.
        """
        if not self.excluded_hashes or self.exclusion_key is None:
            return False
        return value_hash(secret, self.exclusion_key) in self.excluded_hashes

    def scan(self, text: str) -> list[Finding]:
        if not text:
            return []

        # Byte-budget the scan, but cut on a character boundary so offsets stay
        # valid for the caller's string. `text[:max_scan_bytes]` would slice by
        # *character* count, not bytes -- for non-ASCII input (accented text,
        # emoji, CJK) that silently admits up to ~4x the configured budget,
        # defeating the whole point of capping scan cost. Slice the encoded
        # bytes instead, backing off over any trailing UTF-8 continuation
        # bytes (the `10xxxxxx` pattern) so the cut lands on a whole character.
        truncated = False
        encoded = text.encode("utf-8", "surrogatepass")
        if len(encoded) > self.max_scan_bytes:
            cut = self.max_scan_bytes
            while cut > 0 and (encoded[cut] & 0xC0) == 0x80:
                cut -= 1
            text = encoded[:cut].decode("utf-8", "surrogatepass")
            truncated = True

        lowered = text.lower()
        findings: list[Finding] = []
        timed_out: list[str] = []
        started = time.monotonic()

        for rule in self._active:
            if rule.keywords and not any(k in lowered for k in rule.keywords):
                continue
            try:
                matches = list(rule.pattern.finditer(text, timeout=self.regex_timeout))
            except TimeoutError:
                # A pathological input made this rule superlinear. Drop the rule
                # for this scan rather than hang the clipboard.
                timed_out.append(rule.id)
                continue
            except regex.error as exc:  # pragma: no cover - defensive
                log.warning("rule %s failed at match time: %s", rule.id, exc)
                continue

            for m in matches:
                span = self._secret_span(m, rule)
                if span is None:
                    continue
                secret = text[span[0] : span[1]]
                if not entropy_mod.passes(secret, rule.entropy):
                    continue
                if self._is_excluded(secret):
                    continue
                line = _line_containing(text, span[0])
                whole = m.group(0)
                if any(a.excludes(secret, whole, line) for a in rule.allowlists):
                    continue
                if any(
                    a.excludes(secret, whole, line)
                    for a in self.ruleset.global_allowlists
                ):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        label=rule.label,
                        category=rule.category,
                        start=span[0],
                        end=span[1],
                        match_start=m.start(),
                        match_end=m.end(),
                        entropy=entropy_mod.shannon(secret) if rule.entropy else None,
                    )
                )

        elapsed = time.monotonic() - started
        if timed_out:
            log.warning(
                "%d rule(s) exceeded the %.0fms regex budget and were skipped: %s",
                len(timed_out),
                self.regex_timeout * 1000,
                ", ".join(sorted(timed_out)),
            )
        log.debug(
            "scanned %d chars in %.1fms, %d finding(s)%s",
            len(text),
            elapsed * 1000,
            len(findings),
            " (input truncated to scan cap)" if truncated else "",
        )
        findings.sort(key=lambda f: (f.start, f.end, f.rule_id))
        return findings


def _line_containing(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start:] if end == -1 else text[start:end]


def merge_spans(findings: list[Finding]) -> list[tuple[int, int]]:
    """Union of overlapping secret spans, in order.

    Several rules routinely flag the same value — a Datadog key matches both
    `datadog-access-token` and `generic-api-key`. Redaction and the "N secrets"
    count must both work off merged spans, or the same secret is replaced twice
    and reported twice.
    """
    spans = sorted((f.start, f.end) for f in findings)
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def summarise(findings: list[Finding]) -> dict[str, object]:
    """Content-free summary, safe to log or send over D-Bus."""
    merged = merge_spans(findings)
    labels: list[str] = []
    for f in findings:
        if f.label not in labels:
            labels.append(f.label)
    return {
        "secrets": len(merged),
        "findings": len(findings),
        "labels": labels,
        "categories": sorted({f.category for f in findings}),
        "redacted_chars": sum(e - s for s, e in merged),
    }
