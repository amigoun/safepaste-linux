"""A minimal run loop, for backends whose clipboard monitor polls.

`safepaste.daemon` is the Linux front end: a GLib main loop plus a D-Bus service,
needed there because the XFIXES monitor watches a file descriptor and because the
tray and hotkey both talk over D-Bus. None of that applies to a backend that
detects changes by comparing an integer.

So macOS gets this instead — a `while` loop and `sleep`. It deliberately does not
create an NSApplication: nothing here needs a Cocoa run loop, because the only
things that would (NSStatusItem and RegisterEventHotKey) are not implemented yet.
Adding them later means replacing this loop with a real run loop, not rewriting
anything above it.

Notifications go out through the backend's own mechanism where it has one. There
is no IPC surface, so the on-demand "sanitise now" path is reached through the
CLI rather than a hotkey.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from collections.abc import Callable
from typing import Any

from . import config as config_mod
from .backend import Backend, get_backend
from .guard import Guard

log = logging.getLogger(__name__)


class _SleepTimer:
    """Guard's one-shot scheduler, expressed as a deadline the loop checks.

    No threads: the loop already ticks several times a second, so a due callback
    is at most one interval late — irrelevant for dropping a retained secret after
    sixty seconds.
    """

    def __init__(self) -> None:
        self._due: list[tuple[float, Callable[[], None], int]] = []
        self._next_id = 0

    def schedule(self, seconds: float, fn: Callable[[], None]) -> Any:
        self._next_id += 1
        self._due.append((time.monotonic() + seconds, fn, self._next_id))
        return self._next_id

    def cancel(self, handle: Any) -> None:
        self._due = [entry for entry in self._due if entry[2] != handle]

    def run_due(self) -> None:
        now = time.monotonic()
        ready = [entry for entry in self._due if entry[0] <= now]
        self._due = [entry for entry in self._due if entry[0] > now]
        for _, fn, _ in ready:
            try:
                fn()
            except Exception:  # noqa: BLE001 - a bad callback must not stop the loop
                log.exception("scheduled callback failed")


class PollingShell:
    """Drives a poll-based backend until interrupted."""

    def __init__(
        self,
        cfg: config_mod.Config | None = None,
        *,
        backend: Backend | None = None,
        interval: float = 0.3,
        notify: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.interval = interval
        self.timer = _SleepTimer()
        self.notify = notify if notify is not None else _default_notifier()
        self.guard = Guard(
            cfg,
            backend=backend or get_backend(),
            on_detection=self._on_detection,
            timer=self.timer,
        )
        self._stop = False
        self._hotkey = None
        self._listener = None
        self._tray = None

        if not hasattr(self.guard.monitor, "poll_once"):
            raise TypeError(
                f"the {self.guard.backend.name} backend's monitor is not "
                "poll-driven, so it needs a run loop of its own rather than this "
                "shell (on Linux, use safepaste.daemon)"
            )

    # -- presentation ------------------------------------------------------

    def _on_detection(self, findings: list, result, _event) -> None:
        secrets = result.secrets_removed if result.changed else len(findings)
        noun = "secret" if secrets == 1 else "secrets"
        labels = ", ".join(result.labels[:3]) or "unknown"
        if len(result.labels) > 3:
            labels += f", and {len(result.labels) - 3} more"

        if self._tray is not None:
            self._tray.set_alert(secrets)

        if self.guard.config.mode == "redact":
            title = f"{secrets} {noun} removed from the clipboard"
            body = f"{labels}. {result.chars_kept:,} characters kept."
        else:
            # In every other mode the clipboard is untouched, and saying "removed"
            # would be a plain untruth about a secret that is still sitting there.
            title = f"{secrets} {noun} on the clipboard"
            body = labels
        self.notify(title, body)

    # -- lifecycle ---------------------------------------------------------

    def stop(self, *_args: object) -> None:
        self._stop = True

    def _attach_platform_extras(self) -> None:
        """Take whatever optional capabilities this platform offers.

        Both are genuinely optional: without the hotkey the on-demand path is still
        reachable through the CLI, and without the listener the poll below is not a
        degraded mode but the designed fallback.
        """
        backend = self.guard.backend

        binder = backend.hotkey_binder(on_pressed=self.guard.safe_paste)
        if binder is not None and binder.available():
            accel = self.guard.config.safe_paste_hotkey
            self._hotkey = binder if binder.install(accel) else None
            if self._hotkey is None:
                log.info("continuing without a global shortcut")

        listener_factory = getattr(backend, "clipboard_listener", None)
        if listener_factory is not None:
            self._listener = listener_factory(self.guard.monitor)

        tray = backend.tray(
            on_mode=self._set_mode,
            on_pause=lambda secs: self._set_paused(True, secs),
            on_resume=lambda: self._set_paused(False, 0),
            on_safe_paste=self.guard.safe_paste,
            on_preferences=self._show_preferences,
            on_quit=self.stop,
        )
        if tray is not None and tray.start():
            self._tray = tray
            tray.set_state(self.guard.config.mode, self.guard.paused)
        elif tray is not None:
            log.info("no tray icon on this session; everything else is unaffected")

    def _set_mode(self, mode: str) -> None:
        self.guard.set_mode(mode)
        if self._tray is not None:
            self._tray.set_state(self.guard.config.mode, self.guard.paused)

    def _set_paused(self, paused: bool, seconds: int) -> None:
        self.guard.set_paused(paused, seconds)
        if self._tray is not None:
            self._tray.set_state(self.guard.config.mode, self.guard.paused)

    def _show_preferences(self) -> None:
        """No settings window on these platforms yet.

        Rather than a dead menu entry, say where the settings actually live. A GUI
        would need a real toolkit, which is a larger decision than a tray icon.
        """
        from . import config as cfg

        self.notify(
            "SafePaste settings",
            f"Edit {cfg.CONFIG_FILE} and the daemon will pick it up on restart.",
        )

    def run(self) -> int:
        if not self.guard.start():
            return 1
        self._attach_platform_extras()

        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self.stop)

        if self._listener is not None:
            log.info("waiting on clipboard notifications; Ctrl-C to stop")
        else:
            log.info(
                "polling the clipboard every %.0fms; Ctrl-C to stop",
                self.interval * 1000,
            )
        try:
            while not self._stop:
                # Pump first: a hotkey press or a clipboard notification is already
                # queued by the OS and should be serviced before we sleep again.
                if not self.guard.backend.pump():
                    break
                # Still polled even when notifications are active. The poll is one
                # integer compare when nothing changed, and it means a missed or
                # unsupported notification degrades latency rather than correctness.
                self.guard.monitor.poll_once()
                self.timer.run_due()
                time.sleep(self.interval)
        finally:
            if self._tray is not None:
                self._tray.stop()
            if self._listener is not None:
                self._listener.stop()
            if self._hotkey is not None:
                self._hotkey.uninstall()
            self.guard.stop()
        log.info("stopped")
        return 0


def _default_notifier() -> Callable[[str, str], bool]:
    """The platform's notification mechanism, or a log line if it has none."""
    if sys.platform == "darwin":
        from .backend.darwin import notify

        return notify

    def _log_only(title: str, body: str) -> bool:
        log.info("%s — %s", title, body)
        return True

    return _log_only


def main(argv: list[str] | None = None) -> int:
    import argparse
    import pathlib

    ap = argparse.ArgumentParser(
        prog="safepaste-shell",
        description="Watch the clipboard for secrets (polling run loop).",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--mode", choices=config_mod.MODES)
    ap.add_argument("--config", type=pathlib.Path)
    ap.add_argument(
        "--interval",
        type=float,
        default=0.3,
        help="seconds between clipboard checks (default: %(default)s)",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    cfg = config_mod.load(args.config)
    if args.mode:
        cfg.mode = args.mode
    try:
        return PollingShell(cfg, interval=args.interval).run()
    except (TypeError, NotImplementedError) as exc:
        log.error("%s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
