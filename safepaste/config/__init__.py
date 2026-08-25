"""User configuration.

Read with stdlib `tomllib`; written by a small emitter below, because tomllib is
read-only and pulling in a TOML *writer* for a schema this fixed is not worth a
dependency. The emitter handles exactly the value types this schema uses and
raises on anything else rather than producing invalid TOML.

The directory is created 0700 and no clipboard content is ever stored in it. The
one place a secret could leak into config is the exclusion list, so that holds
keyed digests only — HMAC-SHA256 under `exclusion.key`, a sibling file that is
deliberately *not* part of config.toml. See `safepaste.detector.value_hash` for
why an unkeyed hash is not enough, and `ensure_exclusion_key` below for the key.
"""

from __future__ import annotations

import logging
import os
import pathlib
import secrets
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field, fields

from ..detector.engine import EXCLUSION_SCHEME, is_keyed_digest
from ..detector.rules import CATEGORIES

log = logging.getLogger(__name__)

def _config_root() -> pathlib.Path:
    """Where this platform keeps per-user configuration.

    XDG_CONFIG_HOME is honoured everywhere if set, because a user who sets it
    means it. Otherwise: ~/.config on Linux, ~/Library on macOS — the backend
    supplies the segments below that (see Backend.config_dir_name).
    """
    override = os.environ.get("XDG_CONFIG_HOME")
    if override:
        return pathlib.Path(override)
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library"
    if sys.platform == "win32":
        # Roaming, not Local: settings are small and worth following the user.
        return pathlib.Path(os.environ.get("APPDATA", pathlib.Path.home()))
    return pathlib.Path.home() / ".config"


def _config_dir() -> pathlib.Path:
    root = _config_root()
    if os.environ.get("XDG_CONFIG_HOME"):
        return root / "safepaste"
    if sys.platform == "darwin":
        return root / "Application Support" / "SafePaste"
    if sys.platform == "win32":
        return root / "SafePaste"
    return root / "safepaste"


CONFIG_DIR = _config_dir()
CONFIG_FILE = CONFIG_DIR / "config.toml"
RULES_DIR = CONFIG_DIR / "rules"

# Beside config.toml, in a file of its own. config.toml is the one that gets
# pasted into a bug report, copied to a second machine or committed to a dotfiles
# repo; the key must not travel with it, because the two together are an offline
# dictionary attack on every low-entropy value the user excluded.
EXCLUSION_KEY_NAME = "exclusion.key"
EXCLUSION_KEY_BYTES = 32

# Categories enabled out of the box. High-entropy matching is the one that
# generates complaints on ordinary text, so it stays opt-in.
DEFAULT_CATEGORIES = tuple(c for c in CATEGORIES if c != "high_entropy")

MODES = ("redact", "ask", "notify", "off")


@dataclass
class Config:
    # --- protection -------------------------------------------------------
    # redact: swap the clipboard immediately, then offer to restore. Fail-safe:
    #         ignoring the dialog leaves you protected.
    # ask:    leave the original in place and ask first.
    # notify: passive notification only.
    # off:    detection disabled.
    mode: str = "redact"
    # How long the original stays recoverable after a redaction, in seconds.
    restore_timeout_secs: int = 60
    categories: tuple[str, ...] = DEFAULT_CATEGORIES

    # --- redaction --------------------------------------------------------
    placeholder: str = "[REDACTED]"
    label_rules: bool = False
    keep_prefix: int = 0

    # --- detection tuning -------------------------------------------------
    regex_timeout: float = 0.25
    max_scan_bytes: int = 1_048_576

    # --- exclusions -------------------------------------------------------
    # Keyed digests of values the user chose to stop flagging. Never plaintext,
    # and never a bare hash either: see `safepaste.detector.value_hash`.
    excluded_hashes: tuple[str, ...] = ()

    # --- hardening --------------------------------------------------------
    # prctl(PR_SET_DUMPABLE, 0) stops another process running as you from
    # attaching to this one and reading the value held for "Restore original".
    # Off by default because it also makes /proc/self/root unreadable, and that
    # is what xdg-desktop-portal opens to identify its caller -- so with it on,
    # About SafePaste and auto-paste stop working (measured; see
    # safepaste.hardening). Swap and core-dump protection are unconditional and
    # need no switch.
    refuse_ptrace: bool = False

    # --- input ------------------------------------------------------------
    safe_paste_hotkey: str = "<Control><Alt>v"
    # Auto-injecting the paste needs the RemoteDesktop portal, which prompts for
    # consent once. Off by default so first run is friction-free.
    auto_paste: bool = False
    # Returned by the portal after consent. Storing it is what keeps the consent
    # dialog to a single appearance. It is a capability handle, not a secret of
    # the user's, but the config file is 0600 regardless.
    portal_restore_token: str = ""

    extra_rule_globs: tuple[str, ...] = ("rules/*.toml",)

    # --- per-application policy -------------------------------------------
    # Application identity -> mode, overriding `mode` when the paste target is
    # known. Stored as pairs rather than a dict so the dataclass stays hashable-ish
    # and the TOML emitter has one less shape to handle; `app_mode()` does lookups.
    #
    # Identity is an executable name on Windows ("1password.exe") and a bundle
    # identifier on macOS ("com.agilebits.onepassword7"). Empty on Linux, and it can
    # only ever be empty there: org.gnome.Shell.Introspect refuses to name the
    # focused window, so there is nothing to key a policy on.
    app_modes: tuple[tuple[str, str], ...] = ()

    _warnings: list[str] = field(default_factory=list, repr=False, compare=False)

    # -- validation --------------------------------------------------------

    def validated(self) -> Config:
        """Clamp nonsense into range, recording why, rather than refusing to start.

        A hand-edited config with one bad key should not leave the user with no
        clipboard protection at all.
        """
        if self.mode not in MODES:
            self._warnings.append(
                f"unknown mode {self.mode!r}, falling back to 'redact'"
            )
            self.mode = "redact"
        unknown = [c for c in self.categories if c not in CATEGORIES]
        if unknown:
            self._warnings.append(f"ignoring unknown categories: {', '.join(unknown)}")
            self.categories = tuple(c for c in self.categories if c in CATEGORIES)
        if self.restore_timeout_secs < 0:
            self._warnings.append("restore_timeout_secs cannot be negative, using 60")
            self.restore_timeout_secs = 60
        if not 0.01 <= self.regex_timeout <= 10:
            self._warnings.append("regex_timeout out of range, using 0.25")
            self.regex_timeout = 0.25
        if self.max_scan_bytes < 1024:
            self._warnings.append("max_scan_bytes too small, using 1 MiB")
            self.max_scan_bytes = 1_048_576
        if self.keep_prefix < 0:
            self.keep_prefix = 0
        keyed = tuple(h for h in self.excluded_hashes if is_keyed_digest(h))
        unkeyed = len(self.excluded_hashes) - len(keyed)
        if unkeyed:
            # Written by SafePaste 0.6 and earlier as a bare SHA-256. Those are
            # recoverable by guessing -- which is the whole reason for the keyed
            # scheme -- and cannot be converted, because converting needs the
            # plaintext we deliberately never kept. So they stop counting, and
            # the values get flagged again: one dialog each re-adds them keyed.
            self._warnings.append(
                f"ignoring {unkeyed} exclusion(s) stored as a bare hash, which is "
                "guessable for a short or common value. Those values will be "
                "flagged again -- dismiss each once to re-add it as "
                f"{EXCLUSION_SCHEME}. The old lines stay in config.toml until "
                "SafePaste next writes it; deleting them by hand is safe"
            )
        self.excluded_hashes = keyed
        valid_policy = []
        for app, mode in self.app_modes:
            if mode not in MODES:
                self._warnings.append(
                    f"ignoring policy for {app!r}: unknown mode {mode!r}"
                )
                continue
            if not app.strip():
                continue
            valid_policy.append((app, mode))
        self.app_modes = tuple(valid_policy)
        return self

    @property
    def category_set(self) -> frozenset[str]:
        return frozenset(self.categories)

    @property
    def excluded_hash_set(self) -> frozenset[str]:
        return frozenset(self.excluded_hashes)

    def app_mode(self, identity: str | None) -> str:
        """The mode to apply for a given paste target.

        Falls back to the global mode when the identity is unknown or has no rule,
        which is what makes this safe to consult unconditionally: on a platform that
        cannot identify the target, every lookup simply returns the global mode.
        """
        if not identity:
            return self.mode
        wanted = identity.lower()
        for app, mode in self.app_modes:
            if app.lower() == wanted:
                return mode
        return self.mode

    def extra_rule_paths(self) -> list[pathlib.Path]:
        found: list[pathlib.Path] = []
        for pattern in self.extra_rule_globs:
            found.extend(sorted(CONFIG_DIR.glob(pattern)))
        return found


# ---------------------------------------------------------------------------
# load / save
# ---------------------------------------------------------------------------

_SECTIONS = {
    "protection": ("mode", "restore_timeout_secs", "categories"),
    "redaction": ("placeholder", "label_rules", "keep_prefix"),
    "detection": ("regex_timeout", "max_scan_bytes", "extra_rule_globs"),
    "exclusions": ("excluded_hashes",),
    "hardening": ("refuse_ptrace",),
    "input": ("safe_paste_hotkey", "auto_paste", "portal_restore_token"),
}

# Not in _SECTIONS: its keys are application identities chosen by the user, not a
# fixed set, so it is read and written by hand below.
POLICY_SECTION = "policy"


def load(path: pathlib.Path | None = None) -> Config:
    path = path or CONFIG_FILE
    if not path.exists():
        return Config().validated()
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.error("cannot read %s (%s); using defaults", path, exc)
        cfg = Config().validated()
        cfg._warnings.append(f"config file unreadable: {exc}")
        return cfg

    known = {f.name for f in fields(Config) if not f.name.startswith("_")}
    values: dict[str, object] = {}
    for section, keys in _SECTIONS.items():
        block = doc.get(section) or {}
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if key not in known or key not in keys:
                log.warning("ignoring unknown config key [%s].%s", section, key)
                continue
            # Tuple-typed fields arrive as TOML arrays.
            values[key] = tuple(value) if isinstance(value, list) else value

    policy = doc.get(POLICY_SECTION) or {}
    if isinstance(policy, dict):
        values["app_modes"] = tuple(
            (str(app), str(mode)) for app, mode in policy.items()
        )

    return Config(**values).validated()  # type: ignore[arg-type]


def save(cfg: Config, path: pathlib.Path | None = None) -> None:
    path = path or CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkdir's mode is subject to umask, so set it explicitly.
    os.chmod(path.parent, 0o700)
    # Derive the rules directory from the path we were actually given, not from
    # the module-level default. Using RULES_DIR here meant that saving to an
    # explicit path — a test, or `--config somewhere-else` — still created
    # ~/.config/safepaste/rules, quietly writing outside the caller's chosen
    # location.
    (path.parent / "rules").mkdir(parents=True, exist_ok=True, mode=0o700)

    lines = [
        "# SafePaste configuration.",
        f"# Exclusions are {EXCLUSION_SCHEME} digests, never plaintext:",
        "#   printf '%s' 'the-value' | safepaste hash",
        f"# They are keyed by {EXCLUSION_KEY_NAME} in this directory, so they only",
        "# mean anything on this machine and this file alone gives up nothing.",
        "",
    ]
    for section, keys in _SECTIONS.items():
        lines.append(f"[{section}]")
        for key in keys:
            lines.append(f"{key} = {_emit(getattr(cfg, key))}")
        lines.append("")

    if cfg.app_modes:
        lines.append(f"[{POLICY_SECTION}]")
        lines.append("# Application identity -> mode, overriding [protection].mode")
        lines.append("# when the paste target is known. Executable name on Windows,")
        lines.append("# bundle identifier on macOS. Unusable on Linux: the desktop")
        lines.append("# will not say which window has focus.")
        for app, mode in cfg.app_modes:
            lines.append(f"{_emit(app)} = {_emit(mode)}")
        lines.append("")

    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)  # atomic, so a crash mid-write cannot truncate the config


def _emit(value: object) -> str:
    if isinstance(value, bool):  # before int — bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(_emit(v) for v in value) + "]"
    raise TypeError(f"cannot serialise {type(value).__name__} to TOML")


# ---------------------------------------------------------------------------
# the exclusion key
# ---------------------------------------------------------------------------


def exclusion_key_path(config_path: pathlib.Path | None = None) -> pathlib.Path:
    """Where the key lives: beside the config file it belongs to.

    Beside rather than inside, so that handing someone your config.toml hands
    them no way to test guesses against your exclusions.
    """
    parent = config_path.parent if config_path is not None else CONFIG_DIR
    return parent / EXCLUSION_KEY_NAME


def load_exclusion_key(config_path: pathlib.Path | None = None) -> bytes | None:
    """The machine-local exclusion key, or None if there is not one yet.

    Never creates anything -- a read is a read. Every failure here returns None,
    which fails in the safe direction: exclusions stop matching, so values get
    flagged again rather than being waved through on a digest nothing can verify.
    """
    path = exclusion_key_path(config_path)
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        log.error("cannot read the exclusion key at %s (%s)", path, exc)
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        log.error("the exclusion key at %s is not hex; exclusions cannot match", path)
        return None
    if len(key) < EXCLUSION_KEY_BYTES:
        log.error(
            "the exclusion key at %s is %d bytes, expected %d; exclusions cannot match",
            path,
            len(key),
            EXCLUSION_KEY_BYTES,
        )
        return None
    return key


def ensure_exclusion_key(config_path: pathlib.Path | None = None) -> bytes:
    """The machine-local exclusion key, minting one on first use.

    Created by writing a temporary file and *linking* it into place, not by
    writing the final path directly. Two SafePaste processes can want a key at
    the same moment (the daemon on a detection, `safepaste hash` in a shell); the
    link fails for the loser, who then reads the winner's key. An os.replace
    would let the loser overwrite it instead, silently invalidating every
    exclusion the winner had just written. It also means no reader ever sees a
    half-written key.
    """
    existing = load_exclusion_key(config_path)
    if existing is not None:
        return existing

    path = exclusion_key_path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)  # mkdir's mode is subject to umask

    key = secrets.token_bytes(EXCLUSION_KEY_BYTES)
    # mkstemp, not a name of our own: it opens 0600 and O_EXCL, so the key never
    # exists even for an instant as a file another user on the box can read, and
    # a temporary left behind by an earlier crash cannot collide with this one.
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f"{EXCLUSION_KEY_NAME}.", suffix=".tmp"
    )
    tmp = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key.hex() + "\n")
            # A half-written key reads as no key at all, which would quietly
            # invalidate every exclusion written under it. Cheap: once ever.
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
    finally:
        tmp.unlink()

    won = load_exclusion_key(config_path)
    if won is None:  # pragma: no cover - the directory went away under us
        log.error(
            "could not persist an exclusion key at %s; exclusions will not stick", path
        )
        return key
    if won != key:
        log.info("another process created the exclusion key first; using that one")
    else:
        log.info("minted a new exclusion key at %s", path)
    return won
