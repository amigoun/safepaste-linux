"""Watching the clipboard for changes on GNOME/Wayland.

Why this goes through X11 on a Wayland desktop, which looks wrong at first
glance: Mutter implements no clipboard-management protocol (neither
`zwlr_data_control_manager_v1` nor `ext_data_control_manager_v1`), so
`wl-paste --watch` refuses to run, and it gates clipboard reads on keyboard
focus, so an unfocused Wayland client sees an *empty* clipboard. A background
daemon therefore has no Wayland vantage point at all.

What does work is the XWayland selection bridge. Mutter mirrors the clipboard
into the X11 CLIPBOARD selection byte-for-byte in both directions, and XFIXES
delivers a SetSelectionOwnerNotify for every change — including changes made by
Wayland-native applications. scripts/probe-clipboard.py verifies all of that on
the running desktop; run it if this ever appears to stop working.

Reading the bytes used to be delegated to `wl-paste`. It no longer is, because
on Mutter every `wl-paste` invocation maps and focuses a 1x1 window to get around
the focus gating — two of them per copy, which flickers the screen and, when the
focus grab loses its race, silently skips the scan. `safepaste.clipboard.x11`
reads the same bytes off the same XWayland bridge with no window on screen; see
that module for the measurements. `WlPasteReader` stays as the fallback, so a
failed X11 read costs a flicker rather than a missed secret.

`gi` is imported inside the two methods that touch the main loop rather than at
module scope, and that is load-bearing rather than tidy. The detection library
is deliberately free of any GTK import so the suite runs on a bare runner, and
the macOS and Windows CI jobs install nothing but `regex` and `pytest` — a
module-level `from gi.repository import GLib` here fails collection on both the
moment anything under tests/ imports this file.
"""

from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..backend import ClipboardEvent, content_hash
from .x11 import TEXT_TARGET_PREFERENCE, X11SelectionReader, has_rich_targets

log = logging.getLogger(__name__)

# Text flavours we are willing to scan, best first. Shared with the X11 reader:
# two copies of this list would eventually disagree about which flavour wins.
TEXT_MIME_PREFERENCE = TEXT_TARGET_PREFERENCE

# How long a value we wrote ourselves stays recognised as ours. Generous on
# purpose: this is a correctness mechanism, not a performance one, and the cost
# of it being too short is a redaction loop.
OWN_WRITE_TTL = 10.0

READ_TIMEOUT = 2.0


def _has_rich_flavours(types: list[str]) -> bool:
    """Whether a plain-text replacement would discard something.

    Lives here rather than on ClipboardEvent because it is entirely a statement
    about *MIME* naming. A macOS backend answers the same question about UTIs, and
    portable code must never parse either.

    `wl-paste --list-types` reports the ICCCM meta-target `TARGETS` alongside the
    real flavours, and an unrecognised name would otherwise read as "a richer
    representation we are about to destroy" -- which made the dialog claim
    formatting was lost on clipboards holding nothing but plain text.
    """
    return has_rich_targets(types)


@dataclass
class _OwnWrites:
    """Values this process put on the clipboard, so it ignores its own echo.

    Every write we make provokes a change notification. Without this the daemon
    would rescan its own redaction, and — worse — "Restore original" would be
    instantly re-redacted, making the button appear broken.
    """

    seen: dict[str, float] = field(default_factory=dict)

    def remember(self, digest: str) -> None:
        self.seen[digest] = time.monotonic() + OWN_WRITE_TTL

    def claim(self, digest: str) -> bool:
        """True if we wrote this. Consumes the record."""
        self._expire()
        if digest in self.seen:
            del self.seen[digest]
            return True
        return False

    def _expire(self) -> None:
        now = time.monotonic()
        for digest in [d for d, exp in self.seen.items() if exp < now]:
            del self.seen[digest]


class WlPasteReader:
    """One-shot clipboard reads via wl-clipboard.

    Kept only as the fallback behind `X11SelectionReader`. Every call maps and
    focuses a window on Mutter, so it is the flicker; using it is strictly better
    than not reading the clipboard at all, and strictly worse than the X11 path.
    """

    def list_types(self) -> list[str]:
        try:
            out = subprocess.run(
                ["wl-paste", "--list-types"],
                capture_output=True,
                timeout=READ_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("could not list clipboard types: %s", exc)
            return []
        return [t.strip() for t in out.stdout.decode("utf-8", "replace").split() if t.strip()]

    def read_text(self) -> ClipboardEvent | None:
        """Return the clipboard as text, or None if it holds no text at all."""
        types = self.list_types()
        if not types:
            return None
        mime = next((m for m in TEXT_MIME_PREFERENCE if m in types), None)
        if mime is None:
            # An image, a file list, or an application-private flavour. Nothing
            # for a secret scanner to do.
            log.debug("clipboard holds no text flavour (%d types)", len(types))
            return None
        try:
            proc = subprocess.run(
                ["wl-paste", "--no-newline", "--type", mime],
                capture_output=True,
                timeout=READ_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("clipboard read failed: %s", exc)
            return None
        if proc.returncode != 0:
            return None
        text = proc.stdout.decode("utf-8", "replace")
        if not text:
            return None
        return ClipboardEvent.of(
            text,
            flavour=mime,
            has_rich_flavours=_has_rich_flavours(types),
            flavours=tuple(types),
        )


class FallbackReader:
    """The flicker-free read, with the old one behind it.

    The ordering is a safety decision, not a preference. A read that fails is
    reported by `read_text` as None, which the monitor cannot distinguish from a
    clipboard holding no text -- so before this existed, a failed read meant a
    copy nobody scanned. `X11SelectionReader.last_error` separates the two, and
    only a genuine failure reaches `wl-paste`.
    """

    def __init__(
        self,
        primary: X11SelectionReader | None = None,
        fallback: WlPasteReader | None = None,
    ) -> None:
        self.primary = primary if primary is not None else X11SelectionReader()
        self.fallback = fallback if fallback is not None else WlPasteReader()

    def list_types(self) -> list[str]:
        types = self.primary.list_types()
        if types or self.primary.last_error is None:
            return types
        log.warning(
            "X11 clipboard read failed (%s); falling back to wl-paste",
            self.primary.last_error,
        )
        return self.fallback.list_types()

    def close(self) -> None:
        self.primary.close()

    def read_text(self) -> ClipboardEvent | None:
        event = self.primary.read_text()
        if event is not None or self.primary.last_error is None:
            return event
        log.warning(
            "X11 clipboard read failed (%s); falling back to wl-paste",
            self.primary.last_error,
        )
        return self.fallback.read_text()


class XFixesMonitor:
    """Event-driven clipboard watcher, wired into the GLib main loop."""

    def __init__(
        self,
        on_change: Callable[[ClipboardEvent], None],
        reader: object | None = None,
    ) -> None:
        self.on_change = on_change
        self.reader = reader if reader is not None else FallbackReader()
        self.own_writes = _OwnWrites()
        # Set by Guard; see ClipboardMonitor.should_read.
        self.should_read = None
        self._last_digest: str | None = None
        self._watch_id: int | None = None
        self._display = None
        self._owner_notify: tuple[int, int] | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        from Xlib import display as xdisplay
        from Xlib.ext import xfixes

        try:
            self._display = xdisplay.Display()
        except Exception as exc:  # noqa: BLE001 - Xlib raises many shapes here
            log.error("cannot open the X display (is XWayland running?): %s", exc)
            return False

        if not self._display.has_extension("XFIXES"):
            log.error("X server has no XFIXES extension; cannot watch the clipboard")
            return False
        self._display.xfixes_query_version()

        clipboard = self._display.get_atom("CLIPBOARD")
        # Trap 1: python-xlib binds select_selection_input onto the *Display*,
        # not the Window, unlike most Xlib wrappers.
        self._display.xfixes_select_selection_input(
            self._display.screen().root,
            clipboard,
            xfixes.XFixesSetSelectionOwnerNotifyMask,
        )
        self._display.flush()

        # Trap 2: extension_add_subevent registers a dynamically-generated *copy*
        # of the event class, so isinstance() against xfixes.SetSelectionOwnerNotify
        # is always False and would silently discard every event. Compare the
        # (type, sub_code) pair the display exposes instead.
        self._owner_notify = tuple(self._display.extension_event.SetSelectionOwnerNotify)

        from gi.repository import GLib

        self._watch_id = GLib.unix_fd_add_full(
            GLib.PRIORITY_DEFAULT,
            self._display.fileno(),
            GLib.IOCondition.IN,
            self._on_fd_ready,
            None,
        )
        log.info("clipboard monitor active (XFIXES via XWayland)")
        return True

    def stop(self) -> None:
        # The reader holds its own X connection, deliberately separate from the
        # one below; nothing else will close it.
        close = getattr(self.reader, "close", None)
        if callable(close):
            close()
        if self._watch_id is not None:
            from gi.repository import GLib

            GLib.source_remove(self._watch_id)
            self._watch_id = None
        if self._display is not None:
            try:
                self._display.close()
            except Exception:  # noqa: BLE001 - closing a dead connection
                pass
            self._display = None

    # -- writing -----------------------------------------------------------

    def note_own_write(self, text: str) -> None:
        """Tell the monitor we are about to place `text` on the clipboard."""
        self.own_writes.remember(content_hash(text))

    # -- event plumbing ----------------------------------------------------

    def _on_fd_ready(self, fd: int, condition, _data) -> bool:
        if self._display is None:
            return False
        try:
            changed = self._drain()
        except Exception as exc:  # noqa: BLE001 - never let the loop die
            log.exception("clipboard monitor error: %s", exc)
            return True
        if changed:
            self._handle_change()
        return True

    def _drain(self) -> bool:
        """Consume queued X events; True if the clipboard changed.

        The forced next_event() is load-bearing. python-xlib's pending_events()
        reports only what it has already decoded — it does not poll the socket —
        so looping on it alone sees nothing while events sit on the wire. GLib has
        told us the fd is readable, so next_event() will not block.
        """
        assert self._display is not None
        changed = False
        if self._is_owner_notify(self._display.next_event()):
            changed = True
        while self._display.pending_events():
            if self._is_owner_notify(self._display.next_event()):
                changed = True
        return changed

    def _is_owner_notify(self, event: object) -> bool:
        return (
            getattr(event, "type", None),
            getattr(event, "sub_code", None),
        ) == self._owner_notify

    def _handle_change(self) -> None:
        if self.should_read is not None and not self.should_read():
            # Measured on a real desktop: the screen locks, a clipboard change
            # arrives seconds later, and the read blocks for the full timeout before
            # anything can discard it. The lock is already known by then, so ask
            # first rather than paying 2s to learn nothing.
            log.debug("skipping the clipboard read; the caller is not interested")
            self._last_digest = None
            return
        event = self.reader.read_text()
        if event is None:
            self._last_digest = None
            return
        if self.own_writes.claim(event.digest):
            log.debug("ignoring our own clipboard write")
            self._last_digest = event.digest
            return
        if event.digest == self._last_digest:
            # Some applications reassert ownership of unchanged content.
            log.debug("clipboard content unchanged, skipping")
            return
        self._last_digest = event.digest
        self.on_change(event)
