"""The macOS backend.

Written on Linux with no Mac to hand, then verified against a real NSPasteboard on
a macos-latest CI runner — see scripts/verify-darwin.py, which the `macos` job runs
on every push. The unit tests drive a *fake* pasteboard, so they establish the
logic and say nothing about the PyObjC calls; that job is what covers those.

Why macOS is a friendlier target than Wayland, which is worth stating because the
Linux backend's size is misleading:

* `NSPasteboard.changeCount()` is a monotonic integer bumped on every clipboard
  change. Polling it is cheap and needs no permission — as against Mutter, which
  offers no clipboard-management protocol at all and gates reads on keyboard focus,
  forcing the Linux backend through XWayland and XFIXES.
* `NSPasteboard` writes several representations at once, so **the "redacting drops
  text/html" limitation does not exist here.** That is the one caveat the Linux
  dialog has to apologise for.
* `CGEventPost` sends a keystroke with no portal handshake and no per-session
  consent dialog — just the one-time Accessibility grant.

Two capabilities macOS could have that GNOME 46 cannot, both deliberately *not*
implemented yet:

* A real Cmd+V interception via `CGEventTap`. Feasible, but a tap that responds
  slowly is *disabled by the system*, and a Python tap on every keystroke is a poor
  bet. That belongs in native code.
* Per-application policy, via `NSWorkspace.frontmostApplication.bundleIdentifier`.
  This is the piece that is impossible on GNOME (`org.gnome.Shell.Introspect`
  returns Access denied), so it is the most valuable thing to build here next.

The status item and global hotkey live in `.darwin_loop`, because both need a
serviced NSApplication run loop and neither was possible until something provided
one. `pump()` services it, so the existing polling shell drives all of it.

First-run checklist on a Mac:
    python3 -m pip install pyobjc-framework-Cocoa pyobjc-framework-Quartz regex
    python3 -m safepaste rules --stats        # portable core, should just work
    python3 -m safepaste.backend.darwin       # self-check against the real pasteboard
    python3 -m safepaste.service -v           # the polling shell, tray and hotkey
Accessibility permission (System Settings > Privacy & Security) is required only
for injection, and only if auto_paste is switched on.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from typing import Any, Protocol

from . import Backend, ClipboardEvent, ClipboardMonitor, ClipboardWriter, Injector

log = logging.getLogger(__name__)

# Uniform Type Identifiers. The plain-text one is what we scan and replace; the
# others are the representations a plain-only write would silently discard.
UTI_STRING = "public.utf8-plain-text"
UTI_HTML = "public.html"
UTI_RTF = "public.rtf"

# Text-ish UTIs that carry no formatting, so replacing them loses nothing.
PLAIN_UTIS = frozenset(
    {
        UTI_STRING,
        "public.plain-text",
        "public.text",
        "NSStringPboardType",  # the legacy name, still seen in the wild
    }
)

# How often to read changeCount. Reading it is a cheap Mach call, but not free;
# a third of a second is imperceptible for a clipboard and costs nothing
# measurable. Clipboard managers on macOS conventionally sit in this range.
DEFAULT_POLL_INTERVAL = 0.3


class Pasteboard(Protocol):
    """Exactly the slice of NSPasteboard this backend uses.

    Named as a protocol so tests can substitute a fake and the polling and
    write logic can be exercised off a Mac. Method names are PyObjC's, keeping the
    mapping to the Cocoa documentation obvious.
    """

    def changeCount(self) -> int: ...
    def types(self) -> list[str]: ...
    def stringForType_(self, uti: str) -> str | None: ...
    def clearContents(self) -> int: ...
    def setString_forType_(self, text: str, uti: str) -> bool: ...


def _general_pasteboard() -> Pasteboard:
    """The real one. Imported here, not at module scope, so importing this module
    on a non-Mac (or in a test) does not require PyObjC."""
    from AppKit import NSPasteboard  # noqa: PLC0415 - deliberately deferred

    return NSPasteboard.generalPasteboard()


def has_rich_representations(utis: list[str]) -> bool:
    """Whether a plain-text-only write would discard something.

    The macOS counterpart of the MIME check in the Linux monitor. Portable code
    never sees either — it only receives the boolean.
    """
    return any(u not in PLAIN_UTIS for u in utis)


class DarwinClipboardReader:
    def __init__(self, pasteboard: Pasteboard) -> None:
        self._pb = pasteboard

    def read_text(self) -> ClipboardEvent | None:
        utis = list(self._pb.types() or [])
        if not utis:
            return None
        text = self._pb.stringForType_(UTI_STRING)
        if not text:
            # An image, a file promise, or an application-private flavour.
            log.debug("clipboard holds no plain text (%d representation(s))", len(utis))
            return None
        return ClipboardEvent.of(
            str(text),
            flavour=UTI_STRING,
            has_rich_flavours=has_rich_representations(utis),
            flavours=tuple(utis),
        )


class DarwinClipboardWriter:
    """Writes plain text, and optionally mirrors the redaction into other flavours.

    `clearContents()` is mandatory before writing and it bumps `changeCount`, so
    the write is observed as a change like any other — which is exactly why
    `note_own_write` exists on the monitor.
    """

    def __init__(self, pasteboard: Pasteboard) -> None:
        self._pb = pasteboard

    def write(self, text: str) -> bool:
        try:
            self._pb.clearContents()
            ok = bool(self._pb.setString_forType_(text, UTI_STRING))
        except Exception as exc:  # noqa: BLE001 - PyObjC raises assorted types
            log.error("clipboard write failed: %s", exc)
            return False
        if not ok:
            log.error("NSPasteboard refused the write")
            return False
        # Length only, never content.
        log.debug("wrote %d chars to the clipboard", len(text))
        return True

    def write_flavours(self, by_uti: dict[str, str]) -> bool:
        """Write several representations in one transaction.

        The capability Linux lacks: `wl-copy` serves one MIME type per invocation,
        so redacting a rich selection there drops the HTML. Here the caller can
        hand over a redacted plain *and* a redacted HTML form and keep both.
        """
        if not by_uti:
            return False
        try:
            self._pb.clearContents()
            results = [
                bool(self._pb.setString_forType_(value, uti))
                for uti, value in by_uti.items()
            ]
        except Exception as exc:  # noqa: BLE001
            log.error("multi-flavour clipboard write failed: %s", exc)
            return False
        if not all(results):
            log.warning(
                "%d of %d representations were refused", results.count(False), len(results)
            )
        # The plain-text one is the one that matters for safety.
        return bool(results and results[0])

    def clear(self) -> bool:
        try:
            self._pb.clearContents()
        except Exception as exc:  # noqa: BLE001
            log.error("clipboard clear failed: %s", exc)
            return False
        return True


class DarwinClipboardMonitor:
    """Polls `NSPasteboard.changeCount()`.

    There is no change *notification* on macOS, which sounds like a downside and
    is not: an integer compare beats the Linux path's XFIXES-through-XWayland
    arrangement in both simplicity and reliability, and it cannot be defeated by
    focus rules or a locked screen.

    The repeating schedule is injected rather than created here, so the run loop
    belongs to the shell and the polling logic stays testable.
    """

    def __init__(
        self,
        on_change: Callable[[ClipboardEvent], None],
        pasteboard: Pasteboard,
        *,
        schedule_repeating: Callable[[float, Callable[[], None]], Any] | None = None,
        cancel: Callable[[Any], None] | None = None,
        interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.on_change = on_change
        self.reader = DarwinClipboardReader(pasteboard)
        self._pb = pasteboard
        self._schedule = schedule_repeating
        self._cancel = cancel
        self._interval = interval
        self._handle: Any = None
        self._last_change_count: int | None = None
        self._own_writes: dict[str, float] = {}
        # Set by Guard; see ClipboardMonitor.should_read.
        self.should_read = None
        self._last_digest: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        try:
            self._last_change_count = int(self._pb.changeCount())
        except Exception as exc:  # noqa: BLE001
            log.error("cannot read the pasteboard change count: %s", exc)
            return False
        if self._schedule is not None:
            self._handle = self._schedule(self._interval, self.poll_once)
        log.info(
            "clipboard monitor active (NSPasteboard changeCount, every %.0fms)",
            self._interval * 1000,
        )
        return True

    def stop(self) -> None:
        if self._handle is not None and self._cancel is not None:
            self._cancel(self._handle)
        self._handle = None

    def note_own_write(self, text: str) -> None:
        import time

        from . import content_hash

        # Same reason as on Linux: our own write is observed as a change, and
        # without this a redaction gets rescanned and a restore is instantly
        # re-redacted, which makes the undo look broken.
        self._own_writes[content_hash(text)] = time.monotonic() + 10.0

    # -- polling -----------------------------------------------------------

    def poll_once(self) -> None:
        """One change-count comparison. Called by whatever drives the run loop."""
        try:
            current = int(self._pb.changeCount())
        except Exception as exc:  # noqa: BLE001
            log.warning("pasteboard poll failed: %s", exc)
            return
        if current == self._last_change_count:
            return
        self._last_change_count = current

        if self.should_read is not None and not self.should_read():
            log.debug("skipping the clipboard read; the caller is not interested")
            self._last_digest = None
            return
        event = self.reader.read_text()
        if event is None:
            self._last_digest = None
            return
        if self._claim_own_write(event.digest):
            log.debug("ignoring our own clipboard write")
            self._last_digest = event.digest
            return
        if event.digest == self._last_digest:
            # changeCount moves when an application reasserts identical content.
            log.debug("clipboard content unchanged, skipping")
            return
        self._last_digest = event.digest
        self.on_change(event)

    def _claim_own_write(self, digest: str) -> bool:
        import time

        now = time.monotonic()
        for stale in [d for d, exp in self._own_writes.items() if exp < now]:
            del self._own_writes[stale]
        if digest in self._own_writes:
            del self._own_writes[digest]
            return True
        return False


class DarwinInjector:
    """Sends the paste chord with CGEventPost.

    No portal, no session, no consent dialog beyond the one-time Accessibility
    grant — a much shorter road than the Linux RemoteDesktop handshake.

    Cmd+V rather than Shift+Insert: on macOS Cmd+V is the universal paste and
    nothing else is. We are not grabbing it, only sending it, so there is no
    re-trigger hazard.
    """

    KEY_V = 0x09  # kVK_ANSI_V
    FLAG_COMMAND = 1 << 20  # kCGEventFlagMaskCommand

    def __init__(self) -> None:
        self._checked = False

    @property
    def ready(self) -> bool:
        return self._trusted()

    def _trusted(self) -> bool:
        """Whether this process has been granted Accessibility permission."""
        try:
            from ApplicationServices import AXIsProcessTrusted  # noqa: PLC0415

            return bool(AXIsProcessTrusted())
        except Exception as exc:  # noqa: BLE001
            log.debug("cannot determine Accessibility trust: %s", exc)
            return False

    def paste(self, done: Callable[[bool], None] | None = None) -> None:
        ok = self._send()
        if done is not None:
            done(ok)

    def _send(self) -> bool:
        if not self._trusted():
            if not self._checked:
                self._checked = True
                log.info(
                    "automatic pasting needs Accessibility permission: System "
                    "Settings > Privacy & Security > Accessibility. Leaving the "
                    "paste to you."
                )
            return False
        try:
            from Quartz import (  # noqa: PLC0415
                CGEventCreateKeyboardEvent,
                CGEventPost,
                CGEventSetFlags,
                kCGHIDEventTap,
            )

            for pressed in (True, False):
                event = CGEventCreateKeyboardEvent(None, self.KEY_V, pressed)
                CGEventSetFlags(event, self.FLAG_COMMAND)
                CGEventPost(kCGHIDEventTap, event)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not inject the paste keystroke: %s", exc)
            return False
        log.debug("injected Cmd+V")
        return True

    def close(self) -> None:
        return None


def notify(title: str, body: str) -> bool:
    """Post a user notification without requiring a bundled application.

    UNUserNotificationCenter needs a signed bundle with entitlements, which a
    plain interpreter does not have. `osascript` works from anywhere, at the cost
    of a process spawn per notification — acceptable for something that fires when
    a secret is found, not in a loop.
    """
    script = (
        f'display notification {_applescript_string(body)} '
        f'with title {_applescript_string(title)}'
    )
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("notification failed: %s", exc)
        return False
    return proc.returncode == 0


def _applescript_string(text: str) -> str:
    """Quote for AppleScript. Only backslash and double quote are special."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


class DarwinBackend(Backend):
    name = "darwin"

    def __init__(
        self,
        pasteboard: Pasteboard | None = None,
        *,
        schedule_repeating: Callable[[float, Callable[[], None]], Any] | None = None,
        cancel: Callable[[Any], None] | None = None,
        interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        # Injected for tests; None means "ask AppKit when first needed".
        self._pasteboard = pasteboard
        self._schedule = schedule_repeating
        self._cancel = cancel
        self._interval = interval

    def _pb(self) -> Pasteboard:
        if self._pasteboard is None:
            self._pasteboard = _general_pasteboard()
        return self._pasteboard

    def config_dir_name(self) -> tuple[str, ...]:
        # macOS convention is ~/Library/Application Support/<name>, and the config
        # layer joins these segments under the platform's config root.
        return ("Application Support", "SafePaste")

    def clipboard_monitor(
        self, on_change: Callable[[ClipboardEvent], None]
    ) -> ClipboardMonitor:
        return DarwinClipboardMonitor(
            on_change,
            self._pb(),
            schedule_repeating=self._schedule,
            cancel=self._cancel,
            interval=self._interval,
        )

    def clipboard_writer(self) -> ClipboardWriter:
        return DarwinClipboardWriter(self._pb())

    def run_loop(self):
        """NSApplication and its pump, created on first use.

        Shared, because the status item and the hotkey both need a serviced run
        loop and there must only be one NSApplication.
        """
        if getattr(self, "_loop", None) is None:
            from .darwin_loop import RunLoop

            loop = RunLoop()
            self._loop = loop if loop.start() else False
        return self._loop or None

    def hotkey_binder(
        self, on_pressed: Callable[[], None] | None = None
    ) -> Any:
        if on_pressed is None:
            return None
        loop = self.run_loop()
        if loop is None:
            return None
        from .darwin_loop import HotkeyBinder

        binder = HotkeyBinder(loop, on_pressed)
        return binder if binder.available() else None

    def tray(self, **callbacks: Callable) -> Any:
        loop = self.run_loop()
        if loop is None:
            return None
        from .darwin_loop import Tray

        return Tray(loop, **callbacks)

    def foreground_app(self) -> str | None:
        """The frontmost application's bundle identifier.

        Needs no permission, unlike almost everything else in this area -- and it is
        precisely what org.gnome.Shell.Introspect refuses to tell us on GNOME.
        """
        try:
            from AppKit import NSWorkspace

            app = NSWorkspace.sharedWorkspace().frontmostApplication()
            if app is None:
                return None
            identity = app.bundleIdentifier()
            if identity:
                return str(identity).lower()
            # A process with no bundle (a bare binary): fall back to its name, which
            # is still a stable enough thing to write a policy against.
            name = app.localizedName()
            return str(name).lower() if name else None
        except Exception as exc:  # noqa: BLE001
            log.debug("cannot identify the frontmost application: %s", exc)
            return None

    def pump(self) -> bool:
        loop = getattr(self, "_loop", None)
        if not loop:
            return True
        return loop.pump()

    def injector(
        self,
        restore_token: str | None = None,
        on_restore_token: Callable[[str], None] | None = None,
    ) -> Injector | None:
        # restore_token is a portal concept with no macOS counterpart: permission
        # is granted once in System Settings and persists there, so there is
        # nothing for us to store.
        return DarwinInjector()

    # lock_watcher inherits None: unlike wl-clipboard, NSPasteboard does not block
    # while the screen is locked, so there is nothing to watch for.


def _self_check() -> int:
    """`python3 -m safepaste.backend.darwin` — smoke-test against the real pasteboard.

    Exists because none of this has run on a Mac. It saves and restores the
    clipboard, and prints lengths only, never content.
    """
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    backend = DarwinBackend()
    try:
        pb = backend._pb()
    except Exception as exc:  # noqa: BLE001
        print(f"cannot reach NSPasteboard: {exc}")
        print("install PyObjC:  python3 -m pip install pyobjc-framework-Cocoa")
        return 2

    reader = DarwinClipboardReader(pb)
    writer = DarwinClipboardWriter(pb)

    before = reader.read_text()
    print(f"change count: {pb.changeCount()}")
    print(f"representations: {list(pb.types() or [])}")
    print(f"text present: {before is not None}"
          + (f", {len(before.text)} chars, rich={before.has_rich_flavours}" if before else ""))

    probe = "safepaste-darwin-self-check"
    print(f"writing a probe value... {writer.write(probe)}")
    roundtrip = reader.read_text()
    print(f"read back matches: {roundtrip is not None and roundtrip.text == probe}")
    print(f"change count moved: {pb.changeCount()}")

    if before is not None:
        writer.write(before.text)
        print("original restored")
    else:
        writer.clear()
        print("clipboard cleared (it held no text to begin with)")

    print(f"Accessibility granted (needed only for auto-paste): {DarwinInjector().ready}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_check())
