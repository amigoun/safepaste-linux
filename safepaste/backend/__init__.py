"""The seam between portable logic and the desktop underneath it.

Detection, redaction and configuration know nothing about any operating system —
that is roughly a thousand lines, and every one of the subtle bugs worth
remembering lives there. Everything platform-shaped is reached through the
protocols below, so a second desktop is an addition rather than a fork.

The Linux implementation is large (~3,500 lines) because Wayland is hostile to
this class of program, not because the job is hard: 877 lines hand-roll
StatusNotifierItem because AppIndicator would drag GTK3 into a GTK4 process, 330
implement a portal handshake because synthetic input is forbidden, and 274 route
clipboard monitoring through XWayland because Mutter offers no
clipboard-management protocol and gates reads on keyboard focus. On a desktop
with ordinary clipboard and input APIs most of that collapses to a few dozen
lines each.

Sketch of what a macOS backend would bind to, recorded here so the shape of the
contract is not accidental:

    ClipboardMonitor   poll NSPasteboard.general.changeCount — an integer that
                       increments on every change. No focus gating, no protocol
                       archaeology.
    ClipboardWriter    NSPasteboard, which sets several representations at once,
                       so the "redaction drops text/html" caveat disappears.
    HotkeyBinder       RegisterEventHotKey, or NSEvent global monitor.
    Injector           CGEventPost. No portal, no consent dialog beyond the
                       one-time Accessibility grant.
    Tray               NSStatusItem.
    LockWatcher        not needed; nothing blocks while the screen is locked.

Two things macOS could do that GNOME 46 cannot: intercept a real Cmd+V via
CGEventTap, and identify the paste target through
NSWorkspace.frontmostApplication.bundleIdentifier — which is what per-application
policy needs and what org.gnome.Shell.Introspect refuses to tell us.

These are Protocols rather than base classes on purpose: an implementation only
has to have the right shape, so a backend can be a thin adapter over whatever the
platform already provides instead of inheriting from us.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


def content_hash(text: str) -> str:
    """Identity for a clipboard value. Used to recognise our own writes."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass
class ClipboardEvent:
    """A text clipboard value, as observed by a backend."""

    text: str
    digest: str
    # Whatever the platform calls the flavour this text came from: a MIME type on
    # Linux, a UTI on macOS. Opaque to portable code — only logged.
    flavour: str = ""
    # Whether the clipboard also held richer representations that a plain-text
    # replacement would discard. The backend decides this, because only it knows
    # its own flavour naming; portable code must not parse MIME strings.
    has_rich_flavours: bool = False
    flavours: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def of(
        cls,
        text: str,
        *,
        flavour: str = "",
        has_rich_flavours: bool = False,
        flavours: tuple[str, ...] = (),
    ) -> ClipboardEvent:
        return cls(
            text=text,
            digest=content_hash(text),
            flavour=flavour,
            has_rich_flavours=has_rich_flavours,
            flavours=flavours,
        )


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class ClipboardReader(Protocol):
    def read_text(self) -> ClipboardEvent | None:
        """Current clipboard as text, or None if it holds no text at all."""


@runtime_checkable
class ClipboardWriter(Protocol):
    def write(self, text: str) -> bool:
        """Replace the clipboard. True only if it actually succeeded.

        Returning True on a failed write is worse than returning False: the
        caller uses this to decide whether the original is still worth holding
        for an undo, and whether the secret is still exposed.
        """

    def clear(self) -> bool: ...


@runtime_checkable
class ClipboardMonitor(Protocol):
    """Watches for changes and calls back with each new text value.

    Implementations must not report a value the daemon itself just wrote — see
    `note_own_write`. Without that, redacting provokes a rescan of the redaction,
    and restoring an original is immediately re-redacted, which makes the undo
    button look broken.
    """

    reader: ClipboardReader

    def start(self) -> bool: ...
    def stop(self) -> None: ...

    def note_own_write(self, text: str) -> None:
        """Declare a value we are about to place, so its echo is ignored."""


@runtime_checkable
class LockWatcher(Protocol):
    """Tracks whether the session is locked, where that matters.

    Optional: a backend with no such concept returns None from
    `Backend.lock_watcher()` and portable code treats the session as unlocked.
    """

    locked: bool

    def start(self) -> bool: ...
    def refresh(self) -> bool: ...


@runtime_checkable
class HotkeyBinder(Protocol):
    def available(self) -> bool: ...
    def install(self, binding: str) -> bool: ...
    def uninstall(self) -> bool: ...
    def installed(self) -> bool: ...
    def conflicts(self, binding: str) -> list[str]:
        """Existing bindings that would fight this accelerator."""


@runtime_checkable
class Injector(Protocol):
    """Sends the paste keystroke, where the platform permits it at all."""

    @property
    def ready(self) -> bool: ...
    def paste(self, done: Callable[[bool], None] | None = None) -> None: ...
    def close(self) -> None: ...


@runtime_checkable
class Tray(Protocol):
    def start(self) -> bool: ...
    def stop(self) -> None: ...
    def set_state(self, mode: str, paused: bool) -> None: ...
    def set_alert(self, secrets: int) -> None: ...
    def clear_alert(self) -> None: ...


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class Backend:
    """Factory for one desktop's implementations.

    Every accessor may return None for a capability the platform does not offer,
    and portable code must degrade rather than fail: no tray on a session with no
    status-notifier host, no injector where synthetic input is refused. Only
    `clipboard_monitor` and `clipboard_writer` are mandatory — without those there
    is no product.
    """

    name = "unknown"

    def config_dir_name(self) -> tuple[str, ...]:
        """Path segments under the user's config root, for this platform's convention."""
        return ("safepaste",)

    # -- mandatory ---------------------------------------------------------

    def clipboard_monitor(
        self, on_change: Callable[[ClipboardEvent], None]
    ) -> ClipboardMonitor:
        raise NotImplementedError

    def clipboard_writer(self) -> ClipboardWriter:
        raise NotImplementedError

    # -- optional ----------------------------------------------------------

    def lock_watcher(self) -> LockWatcher | None:
        return None

    def hotkey_binder(self) -> HotkeyBinder | None:
        return None

    def injector(
        self,
        restore_token: str | None = None,
        on_restore_token: Callable[[str], None] | None = None,
    ) -> Injector | None:
        return None

    def tray(self, **callbacks: Callable) -> Tray | None:
        return None


def get_backend(name: str | None = None) -> Backend:
    """Pick a backend for this platform, or by explicit name (for tests).

    Fails with a message naming what a new backend must implement, rather than an
    ImportError that reads like a broken install.
    """
    chosen = name or sys.platform

    if chosen.startswith("linux"):
        from .linux import LinuxBackend

        return LinuxBackend()

    if chosen == "darwin":
        raise NotImplementedError(
            "SafePaste has no macOS backend yet. One needs a safepaste.backend."
            "darwin module providing ClipboardMonitor (NSPasteboard.changeCount), "
            "ClipboardWriter (NSPasteboard), and optionally HotkeyBinder "
            "(RegisterEventHotKey), Injector (CGEventPost) and Tray "
            "(NSStatusItem). The detector, redactor and config layers need no "
            "changes. See safepaste/backend/__init__.py for the contract."
        )

    raise NotImplementedError(
        f"no SafePaste backend for platform {chosen!r}; "
        "see safepaste/backend/__init__.py for the contract a new one must satisfy"
    )
