"""Loading and classifying detection rules.

The on-disk format *is* the Gitleaks format, deliberately: the vendored upstream
set and a user's own `~/.config/safepaste/rules/*.toml` parse through the same
code path, so "add a custom regex" needs no second schema and no new docs.

Three SafePaste-only keys are honoured, all optional:
  * `category`    — groups the rule under a Preferences toggle.
  * `enabled`     — an absolute veto. Redeclare a vendored rule's id in your
                    own file with `enabled = false` to silence it for good.
  * `default_off` — ships inactive but switchable, for rules too noisy to have on
                    by default. See RuleSet.enabled_for for why this is not just
                    `enabled = false`.
"""

from __future__ import annotations

import logging
import pathlib
import tomllib
from dataclasses import dataclass, field, replace
from typing import Any

import regex

log = logging.getLogger(__name__)

DATA_DIR = pathlib.Path(__file__).parent / "data"
GITLEAKS_TOML = DATA_DIR / "gitleaks.toml"
EXTRA_TOML = DATA_DIR / "safepaste-extra.toml"

# The toggles offered in Preferences. Order is display order.
CATEGORIES = (
    "api_keys",
    "tokens",
    "passwords",
    "private_keys",
    "connection_strings",
    "jwts",
    "high_entropy",
)

# Human labels for the same.
CATEGORY_LABELS = {
    "api_keys": "API keys",
    "tokens": "Access tokens",
    "passwords": "Passwords",
    "private_keys": "Private keys",
    "connection_strings": "Connection strings",
    "jwts": "JWTs",
    "high_entropy": "High entropy strings",
}

# Upstream rules carry no category, so they are classified on load. Explicit
# entries win; anything unmatched falls through the keyword table below and then
# to "api_keys", which is the honest default for a vendor-branded key rule.
_CATEGORY_OVERRIDES = {
    "jwt": "jwts",
    "jwt-base64": "jwts",
    "private-key": "private_keys",
    "pkcs12-file": "private_keys",
    "kubernetes-secret-yaml": "passwords",
    "nuget-config-password": "passwords",
    "hashicorp-tf-password": "passwords",
    "planetscale-password": "passwords",
    "sidekiq-sensitive-url": "connection_strings",
    "sidekiq-secret": "tokens",
    "slack-webhook-url": "connection_strings",
    "curl-auth-header": "tokens",
    "curl-auth-user": "passwords",
    "generic-api-key": "api_keys",
}

# Ordered: first hit wins, so put the specific before the general.
_CATEGORY_KEYWORDS = (
    ("private_keys", ("private-key", "privatekey", "ssh-key", "pgp", "pkcs")),
    ("jwts", ("jwt",)),
    ("passwords", ("password", "passwd", "-pass", "credentials")),
    ("connection_strings", ("-url", "-uri", "dsn", "connection", "conn-string")),
    ("tokens", ("token", "-pat", "oauth", "bearer", "session", "refresh")),
    ("api_keys", ("api-key", "apikey", "secret", "key", "client-id")),
)


# Words that read as one unit, or that have a canonical casing worth keeping.
# Anything absent is simply lowercased, which is right for the long tail of
# vendor names.
_ACRONYMS = {
    "api": "API",
    "aws": "AWS",
    "cli": "CLI",
    "dsn": "DSN",
    "gcp": "GCP",
    "id": "ID",
    "jwt": "JWT",
    "oauth": "OAuth",
    "ox": "OX",
    "pat": "PAT",
    "pem": "PEM",
    "pgp": "PGP",
    "pki": "PKI",
    "rsa": "RSA",
    "sdk": "SDK",
    "smtp": "SMTP",
    "ssh": "SSH",
    "ssl": "SSL",
    "tls": "TLS",
    "uri": "URI",
    "url": "URL",
    "clickhouse": "ClickHouse",
    "cockroachdb": "CockroachDB",
    "datadog": "Datadog",
    "github": "GitHub",
    "gitlab": "GitLab",
    "graphql": "GraphQL",
    "jfrog": "JFrog",
    "launchdarkly": "LaunchDarkly",
    "mariadb": "MariaDB",
    "mongodb": "MongoDB",
    "mysql": "MySQL",
    "npm": "npm",
    "openai": "OpenAI",
    "postgres": "Postgres",
    "postgresql": "PostgreSQL",
    "sendgrid": "SendGrid",
    "youtube": "YouTube",
}


def translate_re2(pattern: str) -> str:
    r"""Rewrite Go RE2 syntax that Python's engines spell differently.

    Currently one substitution: RE2's `\z` (end of text) becomes Python's `\Z`.
    They are the same anchor; only the spelling differs, and Python has no `\z`
    at all.

    This is not cosmetic. Ubuntu 24.04 ships python3-regex 0.1.20221031, which
    rejects `\z` outright, while a pip-installed modern `regex` accepts it. Four
    upstream rules — curl-auth-header, curl-auth-user, openshift-user-token and
    sentry-org-token — therefore failed to compile on the target distro while
    working fine in a development venv. Because the loader skips uncompilable
    rules with only a log warning, the installed package would have quietly run
    four detectors short, and the test suite would still have passed. Hence also
    `RuleSet.compile_failures`, which makes that condition loud.

    The scan is escape-aware so a literal `\\z` (escaped backslash, then z) is
    left alone. It does not track character classes; `\z` inside `[...]` is not an
    anchor in either dialect, and no rule in the vendored set does that.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            following = pattern[i + 1]
            out.append("\\Z" if following == "z" else char + following)
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


def humanise(rule_id: str) -> str:
    """Turn a rule id into something fit for a dialog.

    Upstream descriptions are full sentences written for a report ("Identified a
    pattern that may indicate AWS credentials, risking unauthorized cloud
    resource access…"), which is far too long for a list of what was found. The
    id is already a tight noun phrase, so build the label from that instead:
    `aws-access-token` -> "AWS access token", `github-pat` -> "GitHub PAT".
    """
    stem = rule_id.removeprefix("safepaste-")
    words = [w for w in stem.replace("_", "-").split("-") if w]
    if not words:
        return rule_id
    out = [_ACRONYMS.get(w.lower(), w.lower()) for w in words]
    # Capitalise the first word unless it is already cased deliberately.
    if out[0] == out[0].lower() and out[0] not in _ACRONYMS.values():
        out[0] = out[0].capitalize()
    return " ".join(out)


def classify(rule_id: str, description: str = "") -> str:
    """Pick a Preferences category for a rule.

    The id is consulted before the description on purpose. Upstream descriptions
    are prose and routinely mention several credential words at once — the AWS
    rule's description says "AWS credentials", which would file an access *token*
    under Passwords if the description won.
    """
    if rule_id in _CATEGORY_OVERRIDES:
        return _CATEGORY_OVERRIDES[rule_id]
    identifier = rule_id.lower()
    for category, needles in _CATEGORY_KEYWORDS:
        if any(n in identifier for n in needles):
            return category
    haystack = description.lower()
    for category, needles in _CATEGORY_KEYWORDS:
        if any(n in haystack for n in needles):
            return category
    return "api_keys"


@dataclass(frozen=True)
class Allowlist:
    """A reason to discard an otherwise-matching candidate.

    Gitleaks semantics, which are easy to get subtly wrong:

    * `regexTarget` selects what the regexes are tested against — the secret
      (default), the whole match, or the containing line. Stopwords are always
      tested against the secret.
    * `condition` is OR by default: any declared criterion matching is enough to
      allow. Under AND, *every* declared criterion must match.
    * `paths` constrains the *file* a finding came from. A clipboard has no file,
      so that criterion can never be satisfied here. Under OR it simply
      contributes nothing; under AND it renders the whole allowlist inert. Both
      matter — upstream's generic-api-key has an AND allowlist whose regexes
      would otherwise suppress any secret sitting on a `LICENSE=` line.
    """

    regexes: tuple[regex.Pattern, ...] = ()
    stopwords: tuple[str, ...] = ()
    target: str = "secret"
    condition: str = "OR"
    path_scoped: bool = False

    def excludes(self, secret: str, match: str, line: str) -> bool:
        subject = {"secret": secret, "match": match, "line": line}.get(
            self.target, secret
        )
        # Only criteria the rule actually declared take part in the vote.
        votes: list[bool] = []
        if self.path_scoped:
            votes.append(False)  # unsatisfiable for clipboard text
        if self.stopwords:
            lowered = secret.lower()
            votes.append(any(w.lower() in lowered for w in self.stopwords))
        if self.regexes:
            votes.append(any(r.search(subject) for r in self.regexes))
        if not votes:
            return False
        return all(votes) if self.condition.upper() == "AND" else any(votes)

    @classmethod
    def from_toml(cls, raw: dict[str, Any]) -> Allowlist:
        """Build an Allowlist, or raise MalformedEntry saying why it cannot be.

        Every field is type-checked rather than trusted, because the cheap
        mistakes here fail open: `regexes = "abc"` iterates as three
        one-character patterns that excuse any secret containing a, b or c.
        """
        if not isinstance(raw, dict):
            raise MalformedEntry("an allowlist must be a table")
        condition = raw.get("condition", "OR")
        if not isinstance(condition, str) or condition.upper() not in ("OR", "AND"):
            raise MalformedEntry(f"condition must be \"OR\" or \"AND\", not {condition!r}")
        target = raw.get("regexTarget", "secret")
        if target not in ("secret", "match", "line"):
            raise MalformedEntry(
                f"regexTarget must be secret, match or line, not {target!r}"
            )
        patterns = _string_list(raw, "regexes")
        regexes = _compile_all(patterns)
        if len(regexes) < len(patterns) and condition.upper() == "AND":
            # Under AND a dropped criterion is one fewer thing that must hold,
            # which would make the allowlist excuse more, not less.
            raise MalformedEntry("an AND allowlist with an uncompilable regex")
        return cls(
            regexes=tuple(regexes),
            stopwords=tuple(_string_list(raw, "stopwords")),
            target=target,
            condition=condition,
            path_scoped=bool(raw.get("paths")),
        )


class MalformedEntry(ValueError):
    """A rule-file entry that cannot be used as written."""


def _string_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise MalformedEntry(f"{key} must be an array of strings")
    return value


def _allowlists(raw: dict[str, Any], where: str) -> list[Allowlist]:
    """Every usable allowlist under `allowlist`/`allowlists`, skipping the rest.

    Skipping is the safe direction: a dropped allowlist means more is flagged.
    """
    out: list[Allowlist] = []
    for key in ("allowlist", "allowlists"):
        block = raw.get(key)
        if block is None:
            continue
        for entry in block if isinstance(block, list) else [block]:
            try:
                out.append(Allowlist.from_toml(entry))
            except MalformedEntry as exc:
                log.warning("%s: skipping an allowlist: %s", where, exc)
    return out


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: regex.Pattern
    keywords: tuple[str, ...]  # lowercased at load time
    category: str
    entropy: float | None = None
    secret_group: int | None = None
    allowlists: tuple[Allowlist, ...] = ()
    # Absolute veto; see RuleSet.enabled_for.
    enabled: bool = True
    # Ships inactive but switchable by naming its category.
    default_off: bool = False

    @property
    def label(self) -> str:
        """Short human name for the dialog, e.g. 'AWS access token'."""
        return humanise(self.id)


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    global_allowlists: list[Allowlist] = field(default_factory=list)
    # Rules dropped because they cannot apply to a clipboard at all (path-only).
    # Expected, and not a problem.
    skipped: list[tuple[str, str]] = field(default_factory=list)
    # Rules dropped because their regex would not compile here. Always a problem:
    # it means a detector is missing on this machine but present on another.
    compile_failures: list[tuple[str, str]] = field(default_factory=list)

    def enabled_for(self, categories: frozenset[str] | None) -> list[Rule]:
        """Active rules, given the categories the user has switched on.

        Three distinct questions, which is why there are two flags rather than
        one. Collapsing them into a single `enabled` field cannot express all
        three at once — the first draft tried, and made the high-entropy toggle
        literally unable to turn its rule on.

        * `enabled = false` — an absolute veto. This is how a user silences one
          specific vendored rule they disagree with: redeclare its id in
          ~/.config/safepaste/rules/ with `enabled = false`. It must win even when
          the rule's category is switched on, or the feature does nothing.
        * `default_off = true` — ships inactive but remains switchable. Naming the
          rule's category *is* the request to switch it on.
        * `categories = None` — "everything on by default", used by tests and by
          `safepaste scan`. It honours `default_off`, so a bare Detector behaves
          like a freshly installed one rather than surfacing the noisy rules.
        """
        return [
            r
            for r in self.rules
            if r.enabled
            and (r.category in categories if categories is not None else not r.default_off)
        ]


def _compile_all(patterns: list[str]) -> list[regex.Pattern]:
    out = []
    for p in patterns:
        try:
            out.append(regex.compile(translate_re2(p)))
        except regex.error as exc:
            log.warning("skipping uncompilable allowlist pattern: %s", exc)
    return out


def _parse_rule(raw: dict[str, Any], where: str) -> Rule | None:
    """Build a Rule, or None for a rule with no regex to run (path-only, or a
    bare `enabled`/`default_off` override of a rule loaded earlier).

    Raises MalformedEntry for a rule that cannot be used as written, and
    UncompilableRule for one whose regex this `regex` cannot compile.
    """
    rid = raw["id"]
    # A string here is truthy whatever it says, so `enabled = "false"` would
    # quietly leave the rule on: refuse it rather than guess.
    for switch in ("enabled", "default_off"):
        if not isinstance(raw.get(switch, False), bool):
            raise MalformedEntry(f"{switch} must be true or false")
    pattern_src = raw.get("regex")
    if not pattern_src:
        # Path-only rules (e.g. pkcs12-file) cannot apply to a clipboard: there
        # is no filename to match. Dropping them is correct, not a limitation.
        return None
    if not isinstance(pattern_src, str):
        raise MalformedEntry("regex must be a string")

    description = raw.get("description", rid)
    if not isinstance(description, str):
        raise MalformedEntry("description must be a string")
    keywords = _string_list(raw, "keywords")
    entropy = raw.get("entropy")
    # bool is an int to Python, and `entropy = true` is a typo, not a threshold.
    if entropy is not None and (
        isinstance(entropy, bool) or not isinstance(entropy, int | float)
    ):
        raise MalformedEntry("entropy must be a number")
    secret_group = raw.get("secretGroup")
    if secret_group is not None and (
        isinstance(secret_group, bool)
        or not isinstance(secret_group, int)
        or secret_group < 0
    ):
        raise MalformedEntry("secretGroup must be a non-negative integer")
    category = raw.get("category")
    if category is not None and category not in CATEGORIES:
        log.warning(
            "%s: rule %s has unknown category %r; classifying it instead",
            where,
            rid,
            category,
        )
        category = None

    try:
        pattern = regex.compile(translate_re2(pattern_src))
    except regex.error as exc:
        # Recorded as a compile failure by the caller, not merely logged: a rule
        # that silently vanishes is a detector the user thinks they have.
        log.error("rule %s has an uncompilable regex, skipping: %s", rid, exc)
        raise UncompilableRule(str(exc)) from exc
    if secret_group is not None and secret_group > pattern.groups:
        raise MalformedEntry(
            f"secretGroup {secret_group} but the regex has {pattern.groups} group(s)"
        )

    return Rule(
        id=rid,
        description=description,
        pattern=pattern,
        keywords=tuple(k.lower() for k in keywords),
        category=category or classify(rid, description),
        entropy=entropy,
        secret_group=secret_group,
        allowlists=tuple(_allowlists(raw, f"{where}: rule {rid}")),
        enabled=raw.get("enabled", True),
        default_off=raw.get("default_off", False),
    )


class UncompilableRule(Exception):
    """A rule whose regex the installed `regex` module rejects."""


def load_file(path: pathlib.Path, into: RuleSet) -> None:
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.error("cannot load rules from %s: %s", path, exc)
        return

    into.global_allowlists.extend(_allowlists(doc, str(path)))

    entries = doc.get("rules") or []
    if not isinstance(entries, list):
        log.warning(
            "%s: `rules` must be an array of tables, written [[rules]]; "
            "no rules loaded from it",
            path,
        )
        return

    seen = {r.id for r in into.rules}
    for raw in entries:
        rid = raw.get("id") if isinstance(raw, dict) else None
        if not rid or not isinstance(rid, str):
            log.warning("%s: skipping a rule with no usable id", path)
            continue
        try:
            rule = _parse_rule(raw, str(path))
        except UncompilableRule:
            into.compile_failures.append((rid, "regex did not compile"))
            continue
        except MalformedEntry as exc:
            log.warning("%s: skipping rule %s: %s", path, rid, exc)
            continue
        if rule is None:
            switches = {k: raw[k] for k in ("enabled", "default_off") if k in raw}
            if rid in seen and switches:
                # A veto names the rule it silences and nothing else; making
                # the user copy the regex too would mean a typo in that copy
                # leaves the rule they meant to turn off still running.
                into.rules = [
                    replace(r, **switches) if r.id == rid else r
                    for r in into.rules
                ]
            else:
                into.skipped.append((rid, "no usable regex"))
            continue
        if rule.id in seen:
            # Later files win, so a user file can retune a vendored rule by id.
            into.rules = [r for r in into.rules if r.id != rule.id]
        seen.add(rule.id)
        into.rules.append(rule)


def load_default(extra_paths: list[pathlib.Path] | None = None) -> RuleSet:
    """Vendored Gitleaks set, then SafePaste's own, then any user files."""
    rs = RuleSet()
    for path in (GITLEAKS_TOML, EXTRA_TOML):
        if path.exists():
            load_file(path, rs)
        else:
            log.warning("rule file missing: %s", path)
    for path in extra_paths or []:
        load_file(path, rs)
    log.info(
        "loaded %d rules (%d path-only skipped), %d global allowlists",
        len(rs.rules),
        len(rs.skipped),
        len(rs.global_allowlists),
    )
    if rs.compile_failures:
        # Loud, because the effect is invisible otherwise: fewer detectors than
        # the user believes they have, with no symptom until something leaks.
        log.error(
            "%d rule(s) failed to compile and are NOT active: %s. "
            "This usually means the installed `regex` is older than the rule set "
            "expects (regex %s in use).",
            len(rs.compile_failures),
            ", ".join(rid for rid, _ in rs.compile_failures),
            getattr(regex, "__version__", "unknown"),
        )
    return rs
