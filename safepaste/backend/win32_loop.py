"""A message-only window and its pump, for Windows.

This is the piece everything else on Windows waits for. Four separate features all
need a window handle and a running message loop, which is why they arrive together
rather than one at a time:

    Shell_NotifyIcon            a tray icon delivers its clicks as a window message
    RegisterHotKey              delivers WM_HOTKEY to a window
    AddClipboardFormatListener  delivers WM_CLIPBOARDUPDATE — genuine change
                                notification, replacing the sequence-number poll
    SetWindowsHookEx(WH_KEYBOARD_LL)  a low-level hook is only serviced while its
                                installing thread pumps messages

`HWND_MESSAGE` as the parent gives a window that never appears on screen, is not
enumerated by the shell, and costs nothing — exactly right for a background
service.

Deliberately not attempted here: the keyboard hook. It belongs in its own change,
because a hook that responds too slowly gets silently dropped by Windows and that
needs measuring rather than assuming.

None of the ctypes below can be exercised off Windows, so the structure follows
the same rule as the rest of the backend: the Win32 surface is thin and sits
behind a seam, the logic around it is tested, and scripts/verify-windows.py covers
the real API on a runner.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

# Window messages we care about.
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_TIMER = 0x0113
WM_HOTKEY = 0x0312
WM_CLIPBOARDUPDATE = 0x031D
# Anything from WM_APP up is ours to define; the tray reports clicks on this one.
WM_TRAY_CALLBACK = 0x8000 + 1  # WM_APP + 1

# RegisterHotKey modifier flags.
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_WIN = 0x0008
MOD_NOREPEAT = 0x4000

HWND_MESSAGE = -3

# Virtual-key codes for the characters a shortcut might plausibly use. Only what is
# needed to parse an accelerator string; letters and digits are computed.
_NAMED_KEYS = {
    "insert": 0x2D,
    "delete": 0x2E,
    "space": 0x20,
    "tab": 0x09,
    "return": 0x0D,
    "enter": 0x0D,
}


def parse_accelerator(accel: str) -> tuple[int, int] | None:
    """Turn a GTK-style accelerator into (modifiers, virtual-key).

    The same `<Control><Alt>v` spelling is used across all platforms so one config
    file means one thing everywhere, rather than each backend inventing a syntax.
    Returns None if it cannot be parsed, so a hand-edited config produces a warning
    rather than a crash.
    """
    text = accel.strip()
    mods = 0
    mapping = {
        "<control>": MOD_CONTROL,
        "<primary>": MOD_CONTROL,  # GTK's portable spelling for Ctrl
        "<ctrl>": MOD_CONTROL,
        "<alt>": MOD_ALT,
        "<shift>": MOD_SHIFT,
        "<super>": MOD_WIN,
        "<meta>": MOD_WIN,
    }
    lowered = text.lower()
    while lowered.startswith("<"):
        end = lowered.find(">")
        if end == -1:
            return None
        token = lowered[: end + 1]
        if token not in mapping:
            return None
        mods |= mapping[token]
        lowered = lowered[end + 1 :]
        text = text[end + 1 :]

    key = lowered.strip()
    if not key:
        return None
    if key in _NAMED_KEYS:
        vk = _NAMED_KEYS[key]
    elif len(key) == 1 and (key.isalpha() or key.isdigit()):
        # For ASCII letters and digits the virtual-key code is the uppercase
        # character code, which is why this needs no lookup table.
        vk = ord(key.upper())
    else:
        return None
    if mods == 0:
        # A bare key would grab it system-wide from every application.
        return None
    return mods | MOD_NOREPEAT, vk


class MessageWindow:
    """A hidden window plus the loop that services it.

    Handlers are plain callables registered per message id, so the tray, the hotkey
    binder and the clipboard monitor each attach what they need without knowing
    about each other.
    """

    CLASS_NAME = "SafePasteMessageWindow"

    def __init__(self) -> None:
        self._handlers: dict[int, list[Callable[[int, int], None]]] = {}
        self._timers: dict[int, Callable[[], None]] = {}
        self._next_timer_id = 1
        self.hwnd: int | None = None
        self._running = False
        self._ctypes: Any = None
        self._user32: Any = None
        self._wndproc_ref: Any = None  # must outlive the window
        self._atom: Any = None

    # -- registration ------------------------------------------------------

    def on_message(self, message: int, handler: Callable[[int, int], None]) -> None:
        """Call `handler(wparam, lparam)` whenever `message` arrives."""
        self._handlers.setdefault(message, []).append(handler)

    # -- lifecycle ---------------------------------------------------------

    def create(self) -> bool:
        import ctypes  # noqa: PLC0415
        from ctypes import wintypes

        self._ctypes = ctypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user32 = user32

        WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long,
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        )

        class WNDCLASS(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", ctypes.c_void_p),
                ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        user32.DefWindowProcW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        ]
        user32.DefWindowProcW.restype = ctypes.c_longlong

        def dispatch(hwnd, message, wparam, lparam):  # noqa: ANN001, ANN202
            try:
                if message == WM_TIMER:
                    callback = self._timers.pop(int(wparam), None)
                    if callback is not None:
                        user32.KillTimer(hwnd, int(wparam))
                        callback()
                    return 0
                for handler in self._handlers.get(int(message), ()):
                    handler(int(wparam), int(lparam))
                if message in (WM_DESTROY, WM_CLOSE):
                    self._running = False
                    user32.PostQuitMessage(0)
                    return 0
            except Exception:  # noqa: BLE001 - a handler must never kill the loop
                log.exception("window message handler failed")
            return user32.DefWindowProcW(hwnd, message, wparam, lparam)

        # Kept on the instance: if this is garbage collected the window calls into
        # freed memory, which crashes the process rather than raising.
        self._wndproc_ref = WNDPROC(dispatch)

        wndclass = WNDCLASS()
        wndclass.lpfnWndProc = self._wndproc_ref
        wndclass.hInstance = kernel32.GetModuleHandleW(None)
        wndclass.lpszClassName = self.CLASS_NAME

        self._atom = user32.RegisterClassW(ctypes.byref(wndclass))
        if not self._atom:
            err = ctypes.get_last_error()
            ERROR_CLASS_ALREADY_EXISTS = 1410
            if err != ERROR_CLASS_ALREADY_EXISTS:
                log.error("RegisterClassW failed (error %d)", err)
                return False

        self.hwnd = user32.CreateWindowExW(
            0, self.CLASS_NAME, self.CLASS_NAME, 0, 0, 0, 0, 0,
            HWND_MESSAGE,  # never shown, never enumerated by the shell
            None, wndclass.hInstance, None,
        )
        if not self.hwnd:
            log.error("CreateWindowExW failed (error %d)", ctypes.get_last_error())
            return False
        log.info("message-only window created (hwnd=%s)", self.hwnd)
        return True

    def schedule(self, seconds: float, fn: Callable[[], None]) -> Any:
        """One-shot timer, satisfying Guard's Timer protocol via WM_TIMER."""
        if self.hwnd is None:
            return None
        timer_id = self._next_timer_id
        self._next_timer_id += 1
        self._timers[timer_id] = fn
        # Milliseconds, and never zero: USER_TIMER_MINIMUM would be silently
        # substituted anyway.
        self._user32.SetTimer(self.hwnd, timer_id, max(1, int(seconds * 1000)), None)
        return timer_id

    def cancel(self, handle: Any) -> None:
        if handle is None or self.hwnd is None:
            return
        self._timers.pop(int(handle), None)
        self._user32.KillTimer(self.hwnd, int(handle))

    def pump_once(self) -> bool:
        """Drain pending messages without blocking. True unless quit was posted.

        Separate from `run` so a test can drive the loop deterministically instead
        of racing a background thread.
        """
        if self.hwnd is None:
            return False
        import ctypes
        from ctypes import wintypes

        PM_REMOVE = 0x0001

        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND), ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM), ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD), ("pt_x", ctypes.c_long),
                ("pt_y", ctypes.c_long),
            ]

        message = MSG()
        alive = True
        while self._user32.PeekMessageW(ctypes.byref(message), None, 0, 0, PM_REMOVE):
            if message.message == 0x0012:  # WM_QUIT
                alive = False
                break
            self._user32.TranslateMessage(ctypes.byref(message))
            self._user32.DispatchMessageW(ctypes.byref(message))
        return alive

    def run(self) -> None:
        """Block, servicing messages, until quit is posted."""
        import time

        self._running = True
        while self._running:
            if not self.pump_once():
                break
            # PeekMessage does not block, so yield rather than spin. A hotkey or a
            # clipboard update is queued by the OS and waits, so this costs only
            # latency measured in milliseconds.
            time.sleep(0.01)

    def stop(self) -> None:
        self._running = False
        if self.hwnd is not None and self._user32 is not None:
            self._user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)

    def destroy(self) -> None:
        if self.hwnd is not None and self._user32 is not None:
            for timer_id in list(self._timers):
                self._user32.KillTimer(self.hwnd, timer_id)
            self._timers.clear()
            self._user32.DestroyWindow(self.hwnd)
            self.hwnd = None


class HotkeyBinder:
    """RegisterHotKey against the message window.

    Nothing like the Linux route through gsettings: no schema, no desktop-specific
    daemon, and no permission. The binding lasts as long as the process, so there is
    no persistent state to install or clean up -- `install` and `uninstall` here are
    about this process's lifetime, not the user's configuration.
    """

    HOTKEY_ID = 1

    def __init__(self, window: MessageWindow, on_pressed: Callable[[], None]) -> None:
        self._window = window
        self._on_pressed = on_pressed
        self._registered: str | None = None
        window.on_message(WM_HOTKEY, self._handle)

    def _handle(self, wparam: int, _lparam: int) -> None:
        if wparam == self.HOTKEY_ID:
            self._on_pressed()

    def available(self) -> bool:
        return self._window.hwnd is not None

    def install(self, binding: str) -> bool:
        if self._window.hwnd is None:
            log.warning("cannot register a hotkey without a window")
            return False
        parsed = parse_accelerator(binding)
        if parsed is None:
            log.error("cannot parse the accelerator %r", binding)
            return False
        mods, vk = parsed
        self.uninstall()
        if not self._window._user32.RegisterHotKey(
            self._window.hwnd, self.HOTKEY_ID, mods, vk
        ):
            import ctypes

            # 1409 is ERROR_HOTKEY_ALREADY_REGISTERED: another application owns it.
            # Worth naming, because it is the one failure a user can act on.
            err = ctypes.get_last_error()
            if err == 1409:
                log.error("%s is already registered by another application", binding)
            else:
                log.error("RegisterHotKey failed for %s (error %d)", binding, err)
            return False
        self._registered = binding
        log.info("registered %s", binding)
        return True

    def uninstall(self) -> bool:
        if self._window.hwnd is None or self._registered is None:
            return False
        self._window._user32.UnregisterHotKey(self._window.hwnd, self.HOTKEY_ID)
        self._registered = None
        return True

    def installed(self) -> bool:
        return self._registered is not None

    def conflicts(self, binding: str) -> list[str]:
        """Windows cannot enumerate who owns a hotkey, only whether it is taken.

        So this reports the fact rather than a culprit, unlike the Linux binder
        which can name the offending gsettings key. Registering and immediately
        releasing is the only available probe.
        """
        if self._window.hwnd is None:
            return []
        parsed = parse_accelerator(binding)
        if parsed is None:
            return [f"{binding} cannot be parsed"]
        mods, vk = parsed
        probe_id = self.HOTKEY_ID + 100
        if self._window._user32.RegisterHotKey(self._window.hwnd, probe_id, mods, vk):
            self._window._user32.UnregisterHotKey(self._window.hwnd, probe_id)
            return []
        return [f"{binding} is already registered by another application"]


class ClipboardListener:
    """Event-driven clipboard monitoring via AddClipboardFormatListener.

    Strictly better than the sequence-number poll it replaces: the OS delivers
    WM_CLIPBOARDUPDATE when something changes, so there is no interval to trade
    latency against, and nothing runs at all while the clipboard is idle. The poll
    remains the fallback for a Windows service with no window.

    This wraps an existing monitor rather than reimplementing it, so own-write
    suppression, duplicate suppression and the reading all stay in one place.
    """

    def __init__(self, window: MessageWindow, monitor: Any) -> None:
        self._window = window
        self._monitor = monitor
        self._listening = False
        window.on_message(WM_CLIPBOARDUPDATE, self._handle)

    def _handle(self, _wparam: int, _lparam: int) -> None:
        # poll_once already compares the sequence number, so it is both correct and
        # cheap to call on notification: a spurious message costs one integer read.
        self._monitor.poll_once()

    def start(self) -> bool:
        if self._window.hwnd is None:
            return False
        if not self._window._user32.AddClipboardFormatListener(self._window.hwnd):
            import ctypes

            log.warning(
                "AddClipboardFormatListener failed (error %d); staying with polling",
                ctypes.get_last_error(),
            )
            return False
        self._listening = True
        log.info("clipboard monitor upgraded to WM_CLIPBOARDUPDATE notifications")
        return True

    def stop(self) -> None:
        if self._listening and self._window.hwnd is not None:
            self._window._user32.RemoveClipboardFormatListener(self._window.hwnd)
            self._listening = False

    @property
    def listening(self) -> bool:
        return self._listening
