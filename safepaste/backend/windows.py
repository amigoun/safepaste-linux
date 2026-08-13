"""The Windows backend.

Uses `ctypes` against user32/kernel32 rather than pywin32: no extra dependency, and
a PyInstaller bundle stays simple.

Windows is the most capable of the three platforms for this job, which is worth
recording because the Linux backend's bulk suggests the opposite:

* `GetClipboardSequenceNumber` gives change detection with no window and no
  permission. (`AddClipboardFormatListener` + `WM_CLIPBOARDUPDATE` is a genuine
  *notification* rather than polling, and is the natural upgrade once a message
  pump exists for the tray.)
* `SetWindowsHookEx(WH_KEYBOARD_LL)` can intercept **and suppress** a real Ctrl+V
  with no special privilege — the thing that is impossible on Wayland and needs an
  Accessibility grant on macOS. Not implemented here, but nothing in this design
  precludes it.
* `GetForegroundWindow` → `QueryFullProcessImageName` identifies the paste target,
  which is what per-application policy needs and what
  `org.gnome.Shell.Introspect` refuses to tell us on GNOME.

The two things that genuinely hurt, both encoded below:

1. **The clipboard is a global exclusive lock.** `OpenClipboard` fails with
   ERROR_ACCESS_DENIED whenever another process holds it, which happens routinely.
   Every access retries with backoff, and every success is paired with a
   `CloseClipboard` in a finally block — holding it blocks every other application
   on the desktop.
2. **`SetClipboardData` transfers ownership of the memory.** On success the system
   owns the handle and freeing it corrupts the clipboard; on failure we still own it
   and *not* freeing it leaks. Both directions are handled explicitly.

`CF_LOCALE` deserves a mention because it is a trap: Windows adds it automatically
alongside any text you place, so treating it as a "rich" format would make every
plain-text copy look like it carried formatting.

Not implemented, returning None per the contract: `hotkey_binder`
(`RegisterHotKey` needs a message pump) and `tray` (`Shell_NotifyIcon` needs a
window). A Windows user gets monitoring, redaction and notifications, and reaches
the on-demand path through the CLI.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from . import Backend, ClipboardEvent, ClipboardMonitor, ClipboardWriter, Injector

log = logging.getLogger(__name__)

# Standard clipboard format identifiers (winuser.h).
CF_TEXT = 1
CF_OEMTEXT = 7
CF_UNICODETEXT = 13
CF_LOCALE = 16

# Formats that carry no formatting, so replacing them with plain text loses
# nothing. CF_LOCALE is here deliberately: Windows synthesises it next to any text
# you place, and omitting it would make every plain copy look rich.
PLAIN_FORMATS = frozenset({CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT, CF_LOCALE})

# Another process holds the clipboard. Routine, not exceptional.
ERROR_ACCESS_DENIED = 5

OPEN_RETRIES = 8
OPEN_BACKOFF = 0.02  # doubles each attempt: ~5s worst case across 8 tries

DEFAULT_POLL_INTERVAL = 0.3


def utf16_size_with_nul(text: str) -> int:
    r"""Bytes needed to hold `text` as UTF-16, including the terminating NUL.

    `len(text) * 2` is wrong and fails only on real input. Python's len() counts
    *code points*; UTF-16 counts *code units*, and any astral character — every
    emoji, for one — is a surrogate pair occupying two units. Sizing the buffer by
    len() therefore under-allocates, and the copy is silently truncated: caught on
    a windows-latest runner as "20 chars in, 19 out".
    """
    return len(text.encode("utf-16-le")) + 2


class Win32Clipboard(Protocol):
    """The slice of the Win32 clipboard API this backend uses.

    A protocol so the retry logic, format classification and polling can be tested
    without Windows — which matters, because the failure mode that actually bites
    here is a *timing* one that no amount of reading the documentation settles.
    """

    def sequence_number(self) -> int: ...
    def open(self) -> bool:
        """True if the clipboard was acquired; False if another process holds it."""

    def close(self) -> None: ...
    def empty(self) -> bool: ...
    def get_text(self) -> str | None: ...
    def set_text(self, text: str) -> bool: ...
    def formats(self) -> list[int]: ...


class _CtypesClipboard:
    """The real thing. Every ctypes reference is created here and nowhere else."""

    def __init__(self) -> None:
        import ctypes  # noqa: PLC0415 - deferred so this module imports anywhere
        from ctypes import wintypes

        self._ctypes = ctypes
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        u, k = self._user32, self._kernel32
        u.OpenClipboard.argtypes = [wintypes.HWND]
        u.OpenClipboard.restype = wintypes.BOOL
        u.CloseClipboard.argtypes = []
        u.CloseClipboard.restype = wintypes.BOOL
        u.EmptyClipboard.argtypes = []
        u.EmptyClipboard.restype = wintypes.BOOL
        u.GetClipboardData.argtypes = [wintypes.UINT]
        u.GetClipboardData.restype = wintypes.HANDLE
        u.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u.SetClipboardData.restype = wintypes.HANDLE
        u.GetClipboardSequenceNumber.argtypes = []
        u.GetClipboardSequenceNumber.restype = wintypes.DWORD
        u.EnumClipboardFormats.argtypes = [wintypes.UINT]
        u.EnumClipboardFormats.restype = wintypes.UINT
        k.GlobalLock.argtypes = [wintypes.HGLOBAL]
        k.GlobalLock.restype = wintypes.LPVOID
        k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        k.GlobalUnlock.restype = wintypes.BOOL
        k.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k.GlobalAlloc.restype = wintypes.HGLOBAL
        k.GlobalFree.argtypes = [wintypes.HGLOBAL]
        k.GlobalFree.restype = wintypes.HGLOBAL

    def sequence_number(self) -> int:
        return int(self._user32.GetClipboardSequenceNumber())

    def open(self) -> bool:
        if self._user32.OpenClipboard(None):
            return True
        err = self._ctypes.get_last_error()
        if err != ERROR_ACCESS_DENIED:
            log.debug("OpenClipboard failed with error %d", err)
        return False

    def close(self) -> None:
        self._user32.CloseClipboard()

    def empty(self) -> bool:
        return bool(self._user32.EmptyClipboard())

    def formats(self) -> list[int]:
        found: list[int] = []
        fmt = self._user32.EnumClipboardFormats(0)
        while fmt:
            found.append(int(fmt))
            fmt = self._user32.EnumClipboardFormats(fmt)
        return found

    def get_text(self) -> str | None:
        handle = self._user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None
        pointer = self._kernel32.GlobalLock(handle)
        if not pointer:
            return None
        try:
            return self._ctypes.wstring_at(pointer)
        finally:
            self._kernel32.GlobalUnlock(handle)

    def set_text(self, text: str) -> bool:
        GMEM_MOVEABLE = 0x0002
        buffer = self._ctypes.create_unicode_buffer(text)
        # Sized from the UTF-16 encoding, never from len(text) -- see
        # utf16_size_with_nul. Cross-checked against what ctypes actually built.
        size = utf16_size_with_nul(text)
        assert size == self._ctypes.sizeof(buffer), (
            f"size mismatch: computed {size}, buffer is {self._ctypes.sizeof(buffer)}"
        )
        handle = self._kernel32.GlobalAlloc(GMEM_MOVEABLE, size)
        if not handle:
            log.error("GlobalAlloc failed for %d bytes", size)
            return False
        pointer = self._kernel32.GlobalLock(handle)
        if not pointer:
            self._kernel32.GlobalFree(handle)
            return False
        try:
            self._ctypes.memmove(pointer, buffer, size)
        finally:
            self._kernel32.GlobalUnlock(handle)

        if not self._user32.SetClipboardData(CF_UNICODETEXT, handle):
            # Ownership did NOT transfer, so this one is ours to release.
            self._kernel32.GlobalFree(handle)
            log.error("SetClipboardData failed (error %d)", self._ctypes.get_last_error())
            return False
        # Ownership HAS transferred. Freeing the handle now would corrupt the
        # clipboard for every other application.
        return True


def _real_clipboard() -> Win32Clipboard:
    return _CtypesClipboard()


def has_rich_formats(formats: list[int]) -> bool:
    """Whether a plain-text-only replacement would discard something."""
    return any(f not in PLAIN_FORMATS for f in formats)


class _Session:
    """A scoped, retrying clipboard acquisition.

    Acquiring can fail simply because another process is mid-copy, so retry with
    backoff rather than treating it as an error. Releasing is unconditional: a
    clipboard left open blocks the whole desktop.
    """

    def __init__(self, api: Win32Clipboard, sleep: Callable[[float], None] = time.sleep) -> None:
        self._api = api
        self._sleep = sleep
        self.acquired = False

    def __enter__(self) -> _Session:
        delay = OPEN_BACKOFF
        for attempt in range(OPEN_RETRIES):
            if self._api.open():
                self.acquired = True
                if attempt:
                    log.debug("clipboard acquired after %d retries", attempt)
                return self
            self._sleep(delay)
            delay *= 2
        log.warning(
            "could not acquire the clipboard after %d attempts; another process is "
            "holding it", OPEN_RETRIES,
        )
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.acquired:
            self._api.close()
            self.acquired = False


class WindowsClipboardReader:
    def __init__(self, api: Win32Clipboard, sleep: Callable[[float], None] = time.sleep) -> None:
        self._api = api
        self._sleep = sleep

    def read_text(self) -> ClipboardEvent | None:
        with _Session(self._api, self._sleep) as session:
            if not session.acquired:
                return None
            formats = self._api.formats()
            if not formats:
                return None
            text = self._api.get_text()
            if not text:
                log.debug("clipboard holds no unicode text (%d format(s))", len(formats))
                return None
            return ClipboardEvent.of(
                text,
                flavour="CF_UNICODETEXT",
                has_rich_flavours=has_rich_formats(formats),
                flavours=tuple(str(f) for f in formats),
            )


class WindowsClipboardWriter:
    def __init__(self, api: Win32Clipboard, sleep: Callable[[float], None] = time.sleep) -> None:
        self._api = api
        self._sleep = sleep

    def write(self, text: str) -> bool:
        with _Session(self._api, self._sleep) as session:
            if not session.acquired:
                return False
            # EmptyClipboard is required before setting data, and it is also what
            # discards the other representations -- including the rich ones we are
            # deliberately not preserving yet.
            if not self._api.empty():
                log.error("EmptyClipboard failed")
                return False
            if not self._api.set_text(text):
                return False
        # Length only, never content.
        log.debug("wrote %d chars to the clipboard", len(text))
        return True

    def clear(self) -> bool:
        with _Session(self._api, self._sleep) as session:
            if not session.acquired:
                return False
            return bool(self._api.empty())


class WindowsClipboardMonitor:
    """Polls `GetClipboardSequenceNumber`.

    Needs no window and no permission, which is why it is the v1 choice: it drops
    straight into the existing polling shell. `AddClipboardFormatListener` is
    strictly better and is the natural upgrade once a message pump exists for the
    tray, but it requires one.
    """

    def __init__(
        self,
        on_change: Callable[[ClipboardEvent], None],
        api: Win32Clipboard,
        *,
        schedule_repeating: Callable[[float, Callable[[], None]], Any] | None = None,
        cancel: Callable[[Any], None] | None = None,
        interval: float = DEFAULT_POLL_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.on_change = on_change
        self.reader = WindowsClipboardReader(api, sleep)
        self._api = api
        self._schedule = schedule_repeating
        self._cancel = cancel
        self._interval = interval
        self._handle: Any = None
        self._last_sequence: int | None = None
        self._own_writes: dict[str, float] = {}
        # Set by Guard; see ClipboardMonitor.should_read.
        self.should_read = None
        self._last_digest: str | None = None

    def start(self) -> bool:
        try:
            self._last_sequence = int(self._api.sequence_number())
        except Exception as exc:  # noqa: BLE001
            log.error("cannot read the clipboard sequence number: %s", exc)
            return False
        if self._schedule is not None:
            self._handle = self._schedule(self._interval, self.poll_once)
        log.info(
            "clipboard monitor active (GetClipboardSequenceNumber, every %.0fms)",
            self._interval * 1000,
        )
        return True

    def stop(self) -> None:
        if self._handle is not None and self._cancel is not None:
            self._cancel(self._handle)
        self._handle = None

    def note_own_write(self, text: str) -> None:
        from . import content_hash

        self._own_writes[content_hash(text)] = time.monotonic() + 10.0

    def poll_once(self) -> None:
        try:
            current = int(self._api.sequence_number())
        except Exception as exc:  # noqa: BLE001
            log.warning("clipboard poll failed: %s", exc)
            return
        if current == self._last_sequence:
            return
        self._last_sequence = current

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
            log.debug("clipboard content unchanged, skipping")
            return
        self._last_digest = event.digest
        self.on_change(event)

    def _claim_own_write(self, digest: str) -> bool:
        now = time.monotonic()
        for stale in [d for d, exp in self._own_writes.items() if exp < now]:
            del self._own_writes[stale]
        if digest in self._own_writes:
            del self._own_writes[digest]
            return True
        return False


class WindowsInjector:
    """Sends Ctrl+V with SendInput. No permission required."""

    VK_CONTROL = 0x11
    VK_V = 0x56

    @property
    def ready(self) -> bool:
        return True

    def paste(self, done: Callable[[bool], None] | None = None) -> None:
        ok = self._send()
        if done is not None:
            done(ok)

    def _send(self) -> bool:
        try:
            import ctypes  # noqa: PLC0415
            from ctypes import wintypes

            KEYEVENTF_KEYUP = 0x0002
            INPUT_KEYBOARD = 1

            # ULONG_PTR: pointer-width, so c_size_t rather than a fixed 32 bits.
            ULONG_PTR = ctypes.c_size_t

            class MOUSEINPUT(ctypes.Structure):
                _fields_ = [
                    ("dx", wintypes.LONG),
                    ("dy", wintypes.LONG),
                    ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ULONG_PTR),
                ]

            class KEYBDINPUT(ctypes.Structure):
                _fields_ = [
                    ("wVk", wintypes.WORD),
                    ("wScan", wintypes.WORD),
                    ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ULONG_PTR),
                ]

            class HARDWAREINPUT(ctypes.Structure):
                _fields_ = [
                    ("uMsg", wintypes.DWORD),
                    ("wParamL", wintypes.WORD),
                    ("wParamH", wintypes.WORD),
                ]

            class INPUT(ctypes.Structure):
                # All three union members are declared even though only the
                # keyboard one is used. SendInput validates cbSize against the
                # real INPUT, and a union sized by KEYBDINPUT alone is too small:
                # MOUSEINPUT is the largest member. Getting this wrong fails with
                # ERROR_INVALID_PARAMETER (87) and zero events delivered -- caught
                # on a windows-latest runner.
                class _U(ctypes.Union):
                    _fields_ = [
                        ("mi", MOUSEINPUT),
                        ("ki", KEYBDINPUT),
                        ("hi", HARDWAREINPUT),
                    ]

                _anonymous_ = ("u",)
                _fields_ = [("type", wintypes.DWORD), ("u", _U)]

            def event(vk: int, up: bool) -> INPUT:
                item = INPUT()
                item.type = INPUT_KEYBOARD
                item.ki = KEYBDINPUT(vk, 0, KEYEVENTF_KEYUP if up else 0, 0, 0)
                return item

            # Press and release in strict order; a stuck Ctrl would be worse than a
            # missed paste.
            sequence = (
                event(self.VK_CONTROL, False),
                event(self.VK_V, False),
                event(self.VK_V, True),
                event(self.VK_CONTROL, True),
            )
            array = (INPUT * len(sequence))(*sequence)
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            sent = user32.SendInput(len(sequence), array, ctypes.sizeof(INPUT))
            if sent != len(sequence):
                log.warning(
                    "SendInput delivered %d of %d events (error %d)",
                    sent, len(sequence), ctypes.get_last_error(),
                )
                return False
        except Exception as exc:  # noqa: BLE001
            log.warning("could not inject the paste keystroke: %s", exc)
            return False
        log.debug("injected Ctrl+V")
        return True

    def close(self) -> None:
        return None


def notify(title: str, body: str) -> bool:
    """A toast, without requiring a packaged app identity.

    PowerShell's BurntToast or the WinRT ToastNotificationManager both want an
    AppUserModelID that an unpackaged script does not have. A message box would
    block. So this logs by default and is left as the obvious extension point once
    a tray window exists, which is also what would host a proper toast.
    """
    log.info("%s — %s", title, body)
    return True


class WindowsBackend(Backend):
    name = "windows"

    def __init__(
        self,
        api: Win32Clipboard | None = None,
        *,
        schedule_repeating: Callable[[float, Callable[[], None]], Any] | None = None,
        cancel: Callable[[Any], None] | None = None,
        interval: float = DEFAULT_POLL_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api = api
        self._schedule = schedule_repeating
        self._cancel = cancel
        self._interval = interval
        self._sleep = sleep

    def message_window(self):
        """The message-only window, created on first use.

        Held on the backend rather than the shell because three components need the
        same handle: the hotkey binder, the clipboard listener and (later) the tray.
        """
        if getattr(self, "_window", None) is None:
            from .win32_loop import MessageWindow

            window = MessageWindow()
            try:
                created = window.create()
            except Exception as exc:  # noqa: BLE001
                # No user32 at all (imported off Windows), or a session with no
                # desktop. Either way: no window, and the caller carries on without
                # the features that need one.
                log.info("no message window available (%s)", exc)
                created = False
            self._window = window if created else False
        return self._window or None

    def hotkey_binder(
        self, on_pressed: Callable[[], None] | None = None
    ) -> Any:
        """RegisterHotKey, which needs the message window.

        Returns None if the window could not be created -- a Windows *service* with
        no desktop, for instance -- and the portable layers carry on without a
        shortcut, as they do on any platform that lacks one.
        """
        # Checked before the window is created: constructing one is not free, and
        # there is nothing to deliver a press to.
        if on_pressed is None:
            return None
        window = self.message_window()
        if window is None:
            return None
        from .win32_loop import HotkeyBinder

        return HotkeyBinder(window, on_pressed)

    def clipboard_listener(self, monitor):
        """Upgrade a polling monitor to WM_CLIPBOARDUPDATE notifications.

        Returns None if there is no window, in which case the caller keeps polling —
        which is correct, not degraded: the poll is the fallback by design.
        """
        window = self.message_window()
        if window is None:
            return None
        from .win32_loop import ClipboardListener

        listener = ClipboardListener(window, monitor)
        return listener if listener.start() else None

    def _clipboard(self) -> Win32Clipboard:
        if self._api is None:
            self._api = _real_clipboard()
        return self._api

    def config_dir_name(self) -> tuple[str, ...]:
        return ("SafePaste",)

    def clipboard_monitor(
        self, on_change: Callable[[ClipboardEvent], None]
    ) -> ClipboardMonitor:
        return WindowsClipboardMonitor(
            on_change,
            self._clipboard(),
            schedule_repeating=self._schedule,
            cancel=self._cancel,
            interval=self._interval,
            sleep=self._sleep,
        )

    def clipboard_writer(self) -> ClipboardWriter:
        return WindowsClipboardWriter(self._clipboard(), self._sleep)

    def injector(
        self,
        restore_token: str | None = None,
        on_restore_token: Callable[[str], None] | None = None,
    ) -> Injector | None:
        # No token concept: SendInput needs no grant to store.
        return WindowsInjector()

    def tray(self, **callbacks: Callable) -> Any:
        """Shell_NotifyIcon, which needs the same window as the hotkey."""
        window = self.message_window()
        if window is None:
            return None
        from .win32_loop import Tray

        return Tray(window, **callbacks)

    def foreground_app(self) -> str | None:
        """The executable name of the foreground window's process.

        PROCESS_QUERY_LIMITED_INFORMATION rather than PROCESS_QUERY_INFORMATION on
        purpose: it is the least privilege that can answer this, and it works
        against elevated processes where the broader right is refused.
        """
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowThreadProcessId.argtypes = [
                wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
            ]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                return None

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value
            )
            if not handle:
                log.debug("cannot open pid %d to name it", pid.value)
                return None
            try:
                size = wintypes.DWORD(1024)
                buffer = ctypes.create_unicode_buffer(size.value)
                if not kernel32.QueryFullProcessImageNameW(
                    handle, 0, buffer, ctypes.byref(size)
                ):
                    return None
                import ntpath

                return ntpath.basename(buffer.value).lower() or None
            finally:
                kernel32.CloseHandle(handle)
        except Exception as exc:  # noqa: BLE001
            log.debug("cannot identify the foreground application: %s", exc)
            return None

    def pump(self) -> bool:
        """Drain the message queue, if a window was ever created.

        Cheap when idle, and skipped entirely when there is no window -- a service
        session with no desktop keeps polling and never pays for this.
        """
        window = getattr(self, "_window", None)
        if not window:
            return True
        return window.pump_once()

    # hotkey_binder and tray inherit None. RegisterHotKey and Shell_NotifyIcon both
    # need a message pump, which arrives with the tray, not before it. No lock
    # watcher is needed: the Win32 clipboard does not block on a locked session the
    # way wl-clipboard does.


def _self_check() -> int:
    """`python -m safepaste.backend.windows` — smoke-test the real clipboard.

    Saves and restores the clipboard; prints lengths only, never content.
    """
    import sys

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    if sys.platform != "win32":
        print(f"this check only means anything on Windows (running on {sys.platform})")
        return 77
    api = _real_clipboard()
    reader, writer = WindowsClipboardReader(api), WindowsClipboardWriter(api)

    before = reader.read_text()
    print(f"sequence number: {api.sequence_number()}")
    print(f"text present: {before is not None}"
          + (f", {len(before.text)} chars, rich={before.has_rich_flavours}" if before else ""))

    probe = "safepaste-windows-self-check"
    print(f"writing a probe value... {writer.write(probe)}")
    roundtrip = reader.read_text()
    print(f"read back matches: {roundtrip is not None and roundtrip.text == probe}")
    print(f"sequence number moved: {api.sequence_number()}")

    if before is not None:
        writer.write(before.text)
        print("original restored")
    else:
        writer.clear()
        print("clipboard cleared (it held no text to begin with)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_check())
