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
        self._MSG: Any = None

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

        LRESULT = ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long
        UINT_PTR = ctypes.c_size_t
        WNDPROC = ctypes.WINFUNCTYPE(
            LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
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

        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM),
                ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD),
                ("pt_x", ctypes.c_long),
                ("pt_y", ctypes.c_long),
            ]

        self._MSG = MSG

        # Every signature is declared, all sixteen of them. Omitting argtypes is not
        # a shortcut: ctypes then guesses from the Python value and passes an int as
        # a 32-bit C int, so HWND_MESSAGE (-3) reaches CreateWindowExW -- which wants
        # a 64-bit HWND -- with garbage in the upper half. The window silently fails
        # to create and nothing says why. Learned from a windows-latest run.
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        ]
        user32.DefWindowProcW.restype = LRESULT
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, ctypes.c_void_p, wintypes.HINSTANCE, ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.SetTimer.argtypes = [wintypes.HWND, UINT_PTR, wintypes.UINT, ctypes.c_void_p]
        user32.SetTimer.restype = UINT_PTR
        user32.KillTimer.argtypes = [wintypes.HWND, UINT_PTR]
        user32.KillTimer.restype = wintypes.BOOL
        user32.PeekMessageW.argtypes = [
            ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT
        ]
        user32.PeekMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
        user32.DispatchMessageW.restype = LRESULT
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.PostQuitMessage.restype = None
        user32.PostMessageW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        ]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.RegisterHotKey.argtypes = [
            wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT
        ]
        user32.RegisterHotKey.restype = wintypes.BOOL
        user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.UnregisterHotKey.restype = wintypes.BOOL
        user32.AddClipboardFormatListener.argtypes = [wintypes.HWND]
        user32.AddClipboardFormatListener.restype = wintypes.BOOL
        user32.RemoveClipboardFormatListener.argtypes = [wintypes.HWND]
        user32.RemoveClipboardFormatListener.restype = wintypes.BOOL
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE

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
            # HWND_MESSAGE must be an actual pointer-width handle, not a Python int.
            wintypes.HWND(HWND_MESSAGE),
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
        PM_REMOVE = 0x0001
        WM_QUIT = 0x0012

        message = self._MSG()
        alive = True
        while self._user32.PeekMessageW(
            self._ctypes.byref(message), None, 0, 0, PM_REMOVE
        ):
            if message.message == WM_QUIT:
                alive = False
                break
            self._user32.TranslateMessage(self._ctypes.byref(message))
            self._user32.DispatchMessageW(self._ctypes.byref(message))
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


# --- tray ------------------------------------------------------------------

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

# Mouse messages arrive as the lParam of our WM_TRAY_CALLBACK.
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205

# Stock icons, so nothing has to be shipped or found on disk.
IDI_SHIELD = 32518
IDI_WARNING = 32515
IDI_INFORMATION = 32516

MF_STRING = 0x0000
MF_SEPARATOR = 0x0800
MF_GRAYED = 0x0001
MF_CHECKED = 0x0008
TPM_RIGHTALIGN = 0x0008
TPM_RETURNCMD = 0x0100
TPM_NONOTIFY = 0x0080


class Tray:
    """A notification-area icon, via Shell_NotifyIcon.

    Satisfies the same Tray protocol as the Linux StatusNotifierItem, so the shell
    treats them identically — but the mechanics are entirely different. Here the
    icon is bound to a window and reports clicks as a window message, and the menu
    is built on demand with TrackPopupMenu rather than exported over a bus. That is
    why 877 lines of hand-rolled dbusmenu on Linux is about a hundred here.

    Stock system icons are used deliberately (IDI_SHIELD and friends): shipping an
    .ico would mean a resource to locate at runtime, and a PyInstaller bundle makes
    that needlessly awkward.
    """

    def __init__(
        self,
        window: MessageWindow,
        *,
        on_mode: Callable[[str], None] | None = None,
        on_pause: Callable[[int], None] | None = None,
        on_resume: Callable[[], None] | None = None,
        on_safe_paste: Callable[[], None] | None = None,
        on_preferences: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
    ) -> None:
        self._window = window
        self._callbacks = {
            "mode": on_mode, "pause": on_pause, "resume": on_resume,
            "safe_paste": on_safe_paste, "preferences": on_preferences,
            "quit": on_quit,
        }
        self._added = False
        self._mode = "redact"
        self._paused = False
        self._alert: int | None = None
        self._nid: Any = None
        self._shell32: Any = None
        # Command ids for the popup menu, resolved back to actions on click.
        self._commands: dict[int, Callable[[], None]] = {}
        window.on_message(WM_TRAY_CALLBACK, self._on_click)

    # -- state -------------------------------------------------------------

    def set_state(self, mode: str, paused: bool) -> None:
        self._mode, self._paused, self._alert = mode, paused, None
        self._refresh()

    def set_alert(self, secrets: int) -> None:
        self._alert = secrets
        self._refresh()

    def clear_alert(self) -> None:
        self._alert = None
        self._refresh()

    def _icon_id(self) -> int:
        if self._alert is not None:
            return IDI_WARNING
        if self._paused or self._mode == "off":
            return IDI_INFORMATION
        return IDI_SHIELD

    def _tooltip(self) -> str:
        if self._alert is not None:
            noun = "secret" if self._alert == 1 else "secrets"
            verb = "removed from" if self._mode == "redact" else "still on"
            return f"SafePaste — {self._alert} {noun} {verb} the clipboard"
        if self._paused:
            return "SafePaste — paused"
        if self._mode == "off":
            return "SafePaste — protection off"
        return "SafePaste — protected"

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        if self._window.hwnd is None:
            log.info("no window, so no tray icon")
            return False
        import ctypes
        from ctypes import wintypes

        user32, shell32 = self._window._user32, ctypes.WinDLL("shell32", use_last_error=True)
        self._shell32 = shell32

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", wintypes.BYTE * 16),
                ("hBalloonIcon", wintypes.HICON),
            ]

        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        user32.LoadIconW.restype = wintypes.HICON
        user32.CreatePopupMenu.argtypes = []
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR
        ]
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.DestroyMenu.restype = wintypes.BOOL
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, wintypes.HWND, ctypes.c_void_p,
        ]
        user32.TrackPopupMenu.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.c_void_p]
        user32.GetCursorPos.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL

        self._NOTIFYICONDATAW = NOTIFYICONDATAW
        self._ctypes = ctypes

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._window.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY_CALLBACK
        # LoadIconW takes a resource *id* cast to a string pointer for stock icons.
        nid.hIcon = user32.LoadIconW(None, ctypes.c_wchar_p(self._icon_id()))
        nid.szTip = self._tooltip()
        self._nid = nid

        if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            log.warning(
                "Shell_NotifyIcon(NIM_ADD) failed (error %d); no tray icon. This is "
                "expected in a session with no Explorer shell, such as a CI runner.",
                ctypes.get_last_error(),
            )
            return False
        self._added = True
        log.info("tray icon added")
        return True

    def _refresh(self) -> None:
        if not self._added or self._nid is None:
            return
        self._nid.hIcon = self._window._user32.LoadIconW(
            None, self._ctypes.c_wchar_p(self._icon_id())
        )
        self._nid.szTip = self._tooltip()
        self._shell32.Shell_NotifyIconW(NIM_MODIFY, self._ctypes.byref(self._nid))

    def stop(self) -> None:
        if self._added and self._nid is not None:
            self._shell32.Shell_NotifyIconW(NIM_DELETE, self._ctypes.byref(self._nid))
            self._added = False

    # -- the menu ----------------------------------------------------------

    def _on_click(self, _wparam: int, lparam: int) -> None:
        # Either button opens the menu: a background service has no primary action
        # worth binding to left-click, and hiding the menu behind right-click only
        # is a common complaint about tray applications.
        if lparam in (WM_LBUTTONUP, WM_RBUTTONUP):
            self._show_menu()

    def build_menu_items(self) -> list[tuple[str, str, dict]]:
        """The menu as data: (kind, label, attrs). Pure, so it can be tested.

        Mirrors the Linux tray's structure deliberately -- same actions, same order,
        same wording -- so the product feels like one thing across platforms.
        """
        from ..config import MODES

        status = (
            f"{self._alert} secret{'s' if self._alert != 1 else ''} "
            f"{'removed' if self._mode == 'redact' else 'found'}"
            if self._alert is not None
            else "Paused" if self._paused
            else "Protection off" if self._mode == "off"
            else "Protected"
        )
        labels = {
            "redact": "Redact automatically", "ask": "Ask every time",
            "notify": "Notify only", "off": "Off",
        }
        items: list[tuple[str, str, dict]] = [
            ("status", status, {"enabled": False}),
            ("separator", "", {}),
            ("action", "Sanitise clipboard now", {"action": "safe_paste"}),
            ("separator", "", {}),
        ]
        for mode in MODES:
            items.append(
                ("mode", labels[mode], {"mode": mode, "checked": mode == self._mode})
            )
        items.append(("separator", "", {}))
        items.append(("action", "Pause 15 minutes", {"action": "pause", "arg": 900}))
        items.append(("action", "Pause 1 hour", {"action": "pause", "arg": 3600}))
        if self._paused:
            items.append(("action", "Resume protection", {"action": "resume"}))
        items.append(("separator", "", {}))
        items.append(("action", "Preferences…", {"action": "preferences"}))
        items.append(("action", "Quit", {"action": "quit"}))
        return items

    def _show_menu(self) -> None:
        if self._window.hwnd is None:
            return
        ctypes, user32 = self._ctypes, self._window._user32
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        self._commands.clear()
        next_id = 1000
        try:
            for kind, label, attrs in self.build_menu_items():
                if kind == "separator":
                    user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                    continue
                flags = MF_STRING
                if attrs.get("enabled") is False:
                    flags |= MF_GRAYED
                if attrs.get("checked"):
                    flags |= MF_CHECKED
                next_id += 1
                user32.AppendMenuW(menu, flags, next_id, label)
                self._commands[next_id] = self._resolve(kind, attrs)

            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

            point = POINT()
            user32.GetCursorPos(ctypes.byref(point))
            # Required by TrackPopupMenu, otherwise the menu will not dismiss when
            # the user clicks elsewhere.
            user32.SetForegroundWindow(self._window.hwnd)
            chosen = user32.TrackPopupMenu(
                menu, TPM_RIGHTALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                point.x, point.y, 0, self._window.hwnd, None,
            )
            handler = self._commands.get(int(chosen))
            if handler is not None:
                handler()
        finally:
            user32.DestroyMenu(menu)

    def _resolve(self, kind: str, attrs: dict) -> Callable[[], None]:
        if kind == "mode":
            mode = attrs["mode"]
            callback = self._callbacks["mode"]
            return (lambda: callback(mode)) if callback else (lambda: None)
        action = attrs.get("action")
        callback = self._callbacks.get(action or "")
        if callback is None:
            return lambda: None
        if action == "pause":
            seconds = attrs.get("arg", 900)
            return lambda: callback(seconds)
        return callback
