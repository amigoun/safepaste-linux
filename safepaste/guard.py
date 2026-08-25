"""What to do when a secret reaches the clipboard. No desktop APIs.

This is the policy layer, deliberately separated from `safepaste.daemon`, which is
the GLib main loop and D-Bus service wrapped around it. The split exists because
the ordering below is the whole safety argument, and it is the last thing that
should be reimplemented once per platform:

    detect -> replace the clipboard -> hold the original -> only then tell the user

Replacing *before* asking is what makes the default fail-safe. If the user ignores
the dialog, dismisses it by accident, or the process dies mid-decision, the
clipboard is already clean. Asking first would leave the raw secret sitting there
during exactly the window in which somebody is distracted.

Everything platform-shaped arrives through `Backend`, so a macOS shell would
supply its own run loop and IPC and reuse this file unchanged.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from . import config as config_mod
from .backend import Backend, ClipboardEvent, get_backend
from .detector import Detector, load_default, summarise, value_hash
from .redactor import Redaction, RedactionStyle, redact

log = logging.getLogger(__name__)


class Timer(Protocol):
    """A one-shot scheduler, so this layer needs no main loop of its own."""

    def schedule(self, seconds: float, fn: Callable[[], None]) -> Any: ...
    def cancel(self, handle: Any) -> None: ...


class _NoTimer:
    """Fallback when no scheduler is supplied.

    Safe, because the timer is only an optimisation: it drops the retained
    plaintext promptly rather than leaving it until the next restore attempt.
    Expiry itself is enforced by `HeldOriginal.alive`, which is checked on every
    read, so correctness does not depend on anything firing.
    """

    def schedule(self, seconds: float, fn: Callable[[], None]) -> Any:
        return None

    def cancel(self, handle: Any) -> None:
        return None


@dataclass
class HeldOriginal:
    """A pre-redaction clipboard value, retained in memory for a short window."""

    text: str
    digest: str
    expires_at: float
    labels: tuple[str, ...]

    @property
    def alive(self) -> bool:
        return time.monotonic() < self.expires_at


class Guard:
    def __init__(
        self,
        config: config_mod.Config | None = None,
        *,
        backend: Backend | None = None,
        on_detection: Callable[[list, Redaction, ClipboardEvent], None] | None = None,
        timer: Timer | None = None,
    ) -> None:
        self.config = config or config_mod.load()
        for warning in self.config._warnings:
            log.warning("config: %s", warning)

        self.backend = backend or get_backend()
        self.timer = timer or _NoTimer()
        # Injected by whatever front end exists; a headless guard has no presenter.
        self.on_detection = on_detection

        # Set before the detector is built: building one reads the key.
        self._cached_exclusion_key: bytes | None = None
        self.detector = self._build_detector()
        self.writer = self.backend.clipboard_writer()
        self.monitor = self.backend.clipboard_monitor(self.handle)
        self.locks = self.backend.lock_watcher()

        self._paused_until = 0.0
        self._held: HeldOriginal | None = None
        self._held_handle: Any = None
        self._last_finding_count = 0
        self._last_secret_hashes: tuple[str, ...] = ()
        self._injector = None

        # Installed last, deliberately: the gate reads `paused`, which needs
        # _paused_until to exist. Wiring it earlier would make a clipboard change
        # arriving during construction raise AttributeError.
        self.monitor.should_read = self._wants_clipboard

    def _wants_clipboard(self) -> bool:
        """Whether a clipboard change is worth reading at all, before reading it.

        `handle` rejects these cases too, but the read happens *first* and on
        GNOME/Wayland it blocks for a full 2s timeout while the screen is locked.
        Measured on a real desktop: the lock was known three seconds before each
        wasted read. So the question has to be asked before the read, not after.

        The ownership case is not an optimisation but a deadlock guard. Where the
        writer holds the clipboard itself, it answers conversion requests from
        this same main loop -- so reading here would block waiting for an answer
        only this thread can give. Skipping is also simply correct: a value we
        are serving is a value we wrote, which `note_own_write` would discard
        anyway.
        """
        if self.config.mode == "off" or self.paused:
            return False
        if self._writer_holds_clipboard():
            log.debug("skipping the read; we are serving this value ourselves")
            return False
        return not self.locked

    def _writer_holds_clipboard(self) -> bool:
        owns = getattr(self.writer, "owns_clipboard", None)
        return bool(owns()) if callable(owns) else False

    def _read_clipboard(self) -> ClipboardEvent | None:
        """The clipboard as an event, from wherever it can be had without blocking.

        When the writer is serving the value, ask it rather than the X server:
        going out for something this process is holding would deadlock on itself.
        This matters beyond the deadlock, too -- a restored original is a value we
        serve, and `safe_paste` on it must see the secret, not an empty read.
        """
        held = None
        current = getattr(self.writer, "current_text", None)
        if callable(current):
            held = current()
        if held is not None:
            return ClipboardEvent.of(held)
        return self.monitor.reader.read_text()

    # -- setup -------------------------------------------------------------

    def _build_detector(self) -> Detector:
        extra = self.config.extra_rule_paths()
        if extra:
            log.info("loading %d extra rule file(s)", len(extra))
        return Detector(
            load_default(extra_paths=extra),
            categories=self.config.category_set,
            excluded_hashes=self.config.excluded_hash_set,
            exclusion_key=self._cached_exclusion_key or config_mod.load_exclusion_key(),
            regex_timeout=self.config.regex_timeout,
            max_scan_bytes=self.config.max_scan_bytes,
        )

    def _exclusion_key(self) -> bytes | None:
        """The key exclusion digests are computed under, minted on first need.

        Cached for the life of the process on purpose: reading it again per
        detection would let a key swapped underneath us split the exclusion list
        into values that still match and values that no longer do.

        Only the write side mints one -- `_build_detector` reads without creating,
        since a user who never excludes anything needs no key and there would be
        nothing to check against anyway.

        None if the key cannot be written at all (a read-only config directory).
        This sits on the detection path, so it must not be able to take redaction
        down with it: losing the key costs "never flag this again", nothing more.
        """
        if self._cached_exclusion_key is None:
            try:
                self._cached_exclusion_key = config_mod.ensure_exclusion_key()
            except OSError as exc:
                log.error(
                    "cannot mint an exclusion key (%s); "
                    "'never flag this value again' will not work",
                    exc,
                )
                return None
        return self._cached_exclusion_key

    @property
    def redaction_style(self) -> RedactionStyle:
        return RedactionStyle(
            placeholder=self.config.placeholder,
            label_rules=self.config.label_rules,
            keep_prefix=self.config.keep_prefix,
        )

    @property
    def paused(self) -> bool:
        return time.monotonic() < self._paused_until

    @property
    def last_finding_count(self) -> int:
        return self._last_finding_count

    @property
    def locked(self) -> bool:
        return self.locks is not None and self.locks.locked

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        if not self.monitor.start():
            log.error("clipboard monitor failed to start; nothing to do")
            return False
        if self.locks is not None:
            self.locks.start()
        log.info(
            "safepaste guarding: backend=%s mode=%s categories=%d rules=%d",
            self.backend.name,
            self.config.mode,
            len(self.config.categories),
            len(self.detector.active_rules),
        )
        return True

    def stop(self) -> None:
        if self._injector is not None:
            self._injector.close()
            self._injector = None
        self.monitor.stop()
        # A writer may be holding the selection on our behalf; on Linux the X
        # connection and its main-loop watch belong to it. Shutdown-only, so
        # dropping the clipboard here is the same thing that exiting would do.
        close = getattr(self.writer, "close", None)
        if callable(close):
            close()
        self.forget_original()

    # -- the pipeline ------------------------------------------------------

    def handle(self, event: ClipboardEvent) -> None:
        """React to a new clipboard value. Called by the monitor."""
        if self.config.mode == "off" or self.paused:
            return
        if self.locked:
            # Where a platform reports it: on GNOME/Wayland wl-clipboard blocks
            # for as long as the lock screen holds keyboard focus, and nothing can
            # paste anyway.
            log.debug("session locked; ignoring clipboard change")
            return

        findings = self.detector.scan(event.text)
        self._last_finding_count = len(findings)
        if not findings:
            return

        info = summarise(findings)
        # Content-free by construction: labels and counts only.
        log.info(
            "detected %s secret(s) on the clipboard: %s",
            info["secrets"],
            ", ".join(info["labels"]),
        )
        # Digests, not the values: this outlives the retention window, and
        # "never flag this again" only ever needs to compare.
        key = self._exclusion_key()
        self._last_secret_hashes = (
            tuple(value_hash(event.text[f.start : f.end], key) for f in findings)
            if key is not None
            else ()
        )

        result = redact(event.text, findings, self.redaction_style)

        if self.config.mode == "redact":
            # Replace first. This is what makes ignoring the dialog safe.
            self.monitor.note_own_write(result.text)
            if self.writer.write(result.text):
                self.hold_original(event, result.labels)
            else:
                log.error("could not replace the clipboard; it still holds the secret")

        if self.on_detection is not None:
            self.on_detection(findings, result, event)

    def target_mode(self) -> tuple[str, str | None]:
        """The mode to apply to a paste happening now, and the target's identity.

        Only meaningful where the platform can name the foreground application. On
        GNOME it never can, so this always returns the global mode -- which is why
        callers can use it unconditionally.
        """
        identity = self.backend.foreground_app()
        return self.config.app_mode(identity), identity

    def safe_paste(self) -> int:
        """Sanitise whatever is on the clipboard right now, on demand.

        This is the one path that already knows where the paste is going, so
        per-application policy applies here even without keyboard interception:
        pressing the shortcut inside a password manager can legitimately do nothing.
        """
        if self.locks is not None and self.locks.refresh():
            log.info("safe paste ignored: session is locked")
            return 0

        mode, identity = self.target_mode()
        if mode == "off":
            log.info(
                "safe paste ignored: policy for %s is 'off'", identity or "this target"
            )
            return 0
        event = self._read_clipboard()
        if event is None:
            return 0
        findings = self.detector.scan(event.text)
        if not findings:
            log.info("safe paste: clipboard is clean")
            return 0
        result = redact(event.text, findings, self.redaction_style)
        self.monitor.note_own_write(result.text)
        if not self.writer.write(result.text):
            return 0
        self.hold_original(event, result.labels)
        log.info("safe paste: removed %d secret(s)", result.secrets_removed)
        self._complete_paste()
        return result.secrets_removed

    # -- the retained original ---------------------------------------------

    def hold_original(self, event: ClipboardEvent, labels: tuple[str, ...]) -> None:
        self.forget_original()
        ttl = self.config.restore_timeout_secs
        if ttl <= 0:
            return
        self._held = HeldOriginal(
            text=event.text,
            digest=event.digest,
            expires_at=time.monotonic() + ttl,
            labels=labels,
        )
        self._held_handle = self.timer.schedule(ttl, self._on_hold_expired)

    def _on_hold_expired(self) -> None:
        log.debug("retention window elapsed; dropping the held original")
        self.forget_original()

    def forget_original(self) -> None:
        if self._held_handle is not None:
            self.timer.cancel(self._held_handle)
            self._held_handle = None
        if self._held is not None:
            # Best effort: drop the only strong reference promptly. Python cannot
            # guarantee the bytes leave the heap, and with swap enabled they may
            # already have reached disk — the README says so rather than implying
            # a guarantee.
            self._held.text = ""
            self._held = None

    def restore_original(self) -> bool:
        if self._held is None or not self._held.alive:
            log.info("no original available to restore")
            return False
        text = self._held.text
        self.monitor.note_own_write(text)
        if not self.writer.write(text):
            return False
        log.info("restored the original clipboard value")
        self.forget_original()
        return True

    # -- injection ---------------------------------------------------------

    def _complete_paste(self) -> None:
        """Send the paste keystroke, if the user opted in.

        Quiet and non-fatal on failure: the sanitised text is already on the
        clipboard, so the worst case is the user pressing the paste key
        themselves, which is the default behaviour anyway.
        """
        if not self.config.auto_paste:
            return
        if self._injector is None:
            self._injector = self.backend.injector(
                restore_token=self.config.portal_restore_token or None,
                on_restore_token=self._store_restore_token,
            )
            if self._injector is None:
                log.info("this platform offers no keyboard injection; paste it yourself")
                return
        self._injector.paste()

    def _store_restore_token(self, token: str) -> None:
        self.config.portal_restore_token = token
        config_mod.save(self.config)
        log.debug("stored the injection permission token; consent will not be re-asked")

    # -- settings ----------------------------------------------------------

    def exclude_last_value(self) -> bool:
        """Stop flagging the values from the most recent detection."""
        if not self._last_secret_hashes:
            return False
        self.config.excluded_hashes = tuple(
            dict.fromkeys(self.config.excluded_hashes + self._last_secret_hashes)
        )
        config_mod.save(self.config)
        self.detector = self._build_detector()
        log.info("added %d value(s) to the exclusion list", len(self._last_secret_hashes))
        return True

    def set_mode(self, mode: str) -> None:
        if mode not in config_mod.MODES:
            log.warning("ignoring unknown mode %r", mode)
            return
        self.config.mode = mode
        config_mod.save(self.config)
        log.info("mode set to %s", mode)

    def set_paused(self, paused: bool, seconds: int = 0) -> None:
        self._paused_until = time.monotonic() + seconds if paused else 0.0
        if paused:
            log.info("protection paused for %ds", seconds)
        else:
            log.info("protection resumed")

    def reload(self) -> None:
        self.config = config_mod.load()
        for warning in self.config._warnings:
            log.warning("config: %s", warning)
        self.detector = self._build_detector()
        log.info("reloaded: %d rules active", len(self.detector.active_rules))

    # -- read-only helpers for a front end ---------------------------------

    def inspect(self, text: str) -> dict:
        return summarise(self.detector.scan(text))

    def redact_text(self, text: str) -> Redaction:
        return redact(text, self.detector.scan(text), self.redaction_style)
