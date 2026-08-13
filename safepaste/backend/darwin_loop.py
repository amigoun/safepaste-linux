"""The macOS run loop, status item and hotkey.

The counterpart to `win32_loop`, and needed for the same reason: a status item and a
global hotkey both require a live run loop, so neither is possible until something
services one.

Three pieces:

* `RunLoop` — `NSApplication` with the *accessory* activation policy, so there is a
  menu-bar item and no Dock icon, plus a `pump()` that services the run loop
  briefly. That maps directly onto `Backend.pump()`, so the existing polling shell
  drives it with no changes.
* `Tray` — `NSStatusItem`, with an `NSMenu` whose items target a small Objective-C
  object. Roughly sixty lines, against 877 for the hand-rolled StatusNotifierItem
  on Linux, because macOS has an actual API for this.
* `HotkeyBinder` — Carbon's `RegisterEventHotKey` through ctypes, deliberately *not*
  `NSEvent.addGlobalMonitorForEventsMatchingMask:`. The monitor is easier but
  requires Accessibility permission; RegisterEventHotKey requires none, and asking
  for Accessibility merely to bind a shortcut would be an unreasonable trade.

Everything here is unverifiable off a Mac, so the same rule applies as elsewhere:
the framework surface is thin, the data-shaped parts are tested on Linux, and
scripts/verify-darwin.py exercises the real APIs on a macos-latest runner.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

# Carbon modifier masks (Events.h). Note these are *not* the Cocoa ones.
CARBON_CMD = 0x0100
CARBON_SHIFT = 0x0200
CARBON_OPTION = 0x0800
CARBON_CONTROL = 0x1000

# Virtual key codes (Events.h, kVK_*). Only what an accelerator might name; letters
# and digits come from the table below because macOS key codes are positional and
# bear no relation to the character.
_VK = {
    "a": 0x00, "b": 0x0B, "c": 0x08, "d": 0x02, "e": 0x0E, "f": 0x03, "g": 0x05,
    "h": 0x04, "i": 0x22, "j": 0x26, "k": 0x28, "l": 0x25, "m": 0x2E, "n": 0x2D,
    "o": 0x1F, "p": 0x23, "q": 0x0C, "r": 0x0F, "s": 0x01, "t": 0x11, "u": 0x20,
    "v": 0x09, "w": 0x0D, "x": 0x07, "y": 0x10, "z": 0x06,
    "0": 0x1D, "1": 0x12, "2": 0x13, "3": 0x14, "4": 0x15, "5": 0x17,
    "6": 0x16, "7": 0x1A, "8": 0x1C, "9": 0x19,
    "space": 0x31, "return": 0x24, "enter": 0x24, "tab": 0x30,
}

_MODIFIERS = {
    # <Control> means the Control key, as it does everywhere else in the config.
    # <Primary> is GTK's "the platform's main modifier", which on macOS is Command —
    # so the same config file gives Ctrl on Linux/Windows and Cmd here, which is
    # what a Mac user would expect.
    "<control>": CARBON_CONTROL,
    "<ctrl>": CARBON_CONTROL,
    "<primary>": CARBON_CMD,
    "<command>": CARBON_CMD,
    "<cmd>": CARBON_CMD,
    "<alt>": CARBON_OPTION,
    "<option>": CARBON_OPTION,
    "<shift>": CARBON_SHIFT,
    "<super>": CARBON_CMD,
    "<meta>": CARBON_CMD,
}


def parse_accelerator(accel: str) -> tuple[int, int] | None:
    """Turn a GTK-style accelerator into Carbon (modifiers, key code).

    Same spelling as every other platform, so one config file means one thing. See
    _MODIFIERS for why <Primary> deliberately maps to Command here.
    """
    lowered = accel.strip().lower()
    mods = 0
    while lowered.startswith("<"):
        end = lowered.find(">")
        if end == -1:
            return None
        token = lowered[: end + 1]
        if token not in _MODIFIERS:
            return None
        mods |= _MODIFIERS[token]
        lowered = lowered[end + 1 :]
    key = lowered.strip()
    if not key or key not in _VK or mods == 0:
        # A bare key would be taken from every application on the system.
        return None
    return mods, _VK[key]


class RunLoop:
    """NSApplication, configured as an accessory, plus a pump."""

    def __init__(self, slice_seconds: float = 0.05) -> None:
        # How long a single pump will service events for. Long enough to feel
        # responsive when a menu is clicked, short enough not to stall the polling
        # loop around it.
        self._slice = slice_seconds
        self._app: Any = None
        self._ok = False

    def start(self) -> bool:
        try:
            from AppKit import (  # noqa: PLC0415
                NSApplication,
                NSApplicationActivationPolicyAccessory,
            )
        except ImportError as exc:
            log.info("no AppKit (%s); no status item or hotkey", exc)
            return False
        try:
            self._app = NSApplication.sharedApplication()
            # Accessory: a menu-bar presence with no Dock icon and no menu bar of
            # its own, which is what a background utility should be.
            self._app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
            self._ok = True
        except Exception as exc:  # noqa: BLE001 - PyObjC raises assorted types
            log.warning("could not initialise NSApplication: %s", exc)
            return False
        log.info("AppKit run loop ready (accessory policy, no Dock icon)")
        return True

    def pump(self) -> bool:
        """Service the run loop briefly. Always True: nothing here asks us to stop.

        Menu tracking runs its own nested run loop once a click is delivered, so the
        only latency a user sees is in delivering that first click.
        """
        if not self._ok:
            return True
        try:
            from Foundation import NSDate, NSDefaultRunLoopMode, NSRunLoop

            NSRunLoop.currentRunLoop().runMode_beforeDate_(
                NSDefaultRunLoopMode,
                NSDate.dateWithTimeIntervalSinceNow_(self._slice),
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("run loop pump failed: %s", exc)
        return True

    @property
    def ready(self) -> bool:
        return self._ok


def _menu_target_class() -> Any:
    """Build the Objective-C object that NSMenuItem actions target.

    Defined inside a function because the class body needs Foundation imported, and
    importing that at module scope would make this module unloadable off a Mac —
    which the tests here depend on.
    """
    import objc  # noqa: PLC0415
    from Foundation import NSObject

    class SafePasteMenuTarget(NSObject):
        def initWithHandlers_(self, handlers):  # noqa: N802
            self = objc.super(SafePasteMenuTarget, self).init()
            if self is None:
                return None
            # Keyed by NSMenuItem tag, because that is what the sender carries back.
            self._handlers = dict(handlers)
            return self

        def invoke_(self, sender):  # noqa: N802
            handler = self._handlers.get(int(sender.tag()))
            if handler is not None:
                try:
                    handler()
                except Exception:  # noqa: BLE001 - never let a click kill the app
                    logging.getLogger(__name__).exception("menu action failed")

    return SafePasteMenuTarget


class Tray:
    """An NSStatusItem in the menu bar.

    Satisfies the same Tray protocol as the Linux and Windows implementations, and
    presents the same menu in the same order, so the product reads as one thing.
    """

    # SF Symbols, available from macOS 11 and drawn as template images so they
    # follow light and dark menu bars automatically. No asset to ship.
    SYMBOL_ACTIVE = "lock.shield"
    SYMBOL_ALERT = "exclamationmark.shield"
    SYMBOL_OFF = "shield.slash"

    def __init__(
        self,
        run_loop: RunLoop,
        *,
        on_mode: Callable[[str], None] | None = None,
        on_pause: Callable[[int], None] | None = None,
        on_resume: Callable[[], None] | None = None,
        on_safe_paste: Callable[[], None] | None = None,
        on_preferences: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
    ) -> None:
        self._loop = run_loop
        self._callbacks = {
            "mode": on_mode, "pause": on_pause, "resume": on_resume,
            "safe_paste": on_safe_paste, "preferences": on_preferences,
            "quit": on_quit,
        }
        self._item: Any = None
        self._target: Any = None
        self._mode = "redact"
        self._paused = False
        self._alert: int | None = None

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

    def _symbol(self) -> str:
        if self._alert is not None:
            return self.SYMBOL_ALERT
        if self._paused or self._mode == "off":
            return self.SYMBOL_OFF
        return self.SYMBOL_ACTIVE

    def _tooltip(self) -> str:
        if self._alert is not None:
            noun = "secret" if self._alert == 1 else "secrets"
            verb = "removed from" if self._mode == "redact" else "still on"
            return f"{self._alert} {noun} {verb} the clipboard"
        if self._paused:
            return "Paused"
        if self._mode == "off":
            return "Protection off"
        return "Protected"

    def build_menu_items(self) -> list[tuple[str, str, dict]]:
        """The menu as data, so its structure is testable off a Mac.

        Same items, order and wording as the Linux and Windows trays.
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
        items.append(("action", "Quit SafePaste", {"action": "quit"}))
        return items

    def _resolve(self, kind: str, attrs: dict) -> Callable[[], None]:
        if kind == "mode":
            mode = attrs["mode"]
            callback = self._callbacks["mode"]
            return (lambda: callback(mode)) if callback else (lambda: None)
        callback = self._callbacks.get(attrs.get("action") or "")
        if callback is None:
            return lambda: None
        if attrs.get("action") == "pause":
            seconds = attrs.get("arg", 900)
            return lambda: callback(seconds)
        return callback

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        if not self._loop.ready:
            log.info("no run loop, so no status item")
            return False
        try:
            from AppKit import NSStatusBar, NSVariableStatusItemLength

            self._item = NSStatusBar.systemStatusBar().statusItemWithLength_(
                NSVariableStatusItemLength
            )
            if self._item is None:
                log.warning("the system status bar refused an item")
                return False
            self._refresh()
        except Exception as exc:  # noqa: BLE001
            log.warning("could not create the status item: %s", exc)
            return False
        log.info("status item added to the menu bar")
        return True

    def _refresh(self) -> None:
        if self._item is None:
            return
        try:
            self._apply_icon()
            self._apply_menu()
        except Exception as exc:  # noqa: BLE001
            log.debug("status item refresh failed: %s", exc)

    def _apply_icon(self) -> None:
        from AppKit import NSImage

        button = self._item.button()
        if button is None:
            return
        image = None
        if hasattr(NSImage, "imageWithSystemSymbolName_accessibilityDescription_"):
            image = NSImage.imageWithSystemSymbolName_accessibilityDescription_(
                self._symbol(), "SafePaste"
            )
        if image is not None:
            # Template images invert automatically for light and dark menu bars.
            image.setTemplate_(True)
            button.setImage_(image)
        else:
            # An older macOS without SF Symbols: a short text glyph still reads.
            button.setTitle_("SP")
        button.setToolTip_(f"SafePaste — {self._tooltip()}")

    def _apply_menu(self) -> None:
        from AppKit import NSMenu, NSMenuItem

        menu = NSMenu.alloc().init()
        handlers: dict[int, Callable[[], None]] = {}
        tag = 1
        for kind, label, attrs in self.build_menu_items():
            if kind == "separator":
                menu.addItem_(NSMenuItem.separatorItem())
                continue
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(label, None, "")
            if attrs.get("enabled") is False:
                item.setEnabled_(False)
            else:
                item.setTag_(tag)
                item.setAction_("invoke:")
                handlers[tag] = self._resolve(kind, attrs)
                tag += 1
            if attrs.get("checked"):
                item.setState_(1)  # NSControlStateValueOn
            menu.addItem_(item)

        # Rebuilt each refresh, so the target is too -- and it must be retained, or
        # the menu ends up pointing at a collected object.
        self._target = _menu_target_class().alloc().initWithHandlers_(handlers)
        for index in range(menu.numberOfItems()):
            entry = menu.itemAtIndex_(index)
            if entry.action() is not None:
                entry.setTarget_(self._target)
        self._item.setMenu_(menu)

    def stop(self) -> None:
        if self._item is None:
            return
        try:
            from AppKit import NSStatusBar

            NSStatusBar.systemStatusBar().removeStatusItem_(self._item)
        except Exception as exc:  # noqa: BLE001
            log.debug("removing the status item failed: %s", exc)
        self._item = None


class HotkeyBinder:
    """Carbon RegisterEventHotKey, reached through ctypes.

    Chosen over NSEvent's global monitor specifically because it needs no
    Accessibility grant. The cost is Carbon's C API and an event handler callback,
    which is why the reference to that callback is held on the instance: letting it
    be collected leaves Carbon calling into freed memory.
    """

    SIGNATURE = 0x53414645  # 'SAFE', the four-char code identifying our hotkey
    HOTKEY_ID = 1

    def __init__(self, run_loop: RunLoop, on_pressed: Callable[[], None]) -> None:
        self._loop = run_loop
        self._on_pressed = on_pressed
        self._carbon: Any = None
        self._ref: Any = None
        self._handler_ref: Any = None
        self._installed: str | None = None

    def available(self) -> bool:
        return self._loop.ready and self._load() is not None

    def _load(self) -> Any:
        if self._carbon is not None:
            return self._carbon
        try:
            import ctypes

            self._carbon = ctypes.CDLL(
                "/System/Library/Frameworks/Carbon.framework/Carbon"
            )
        except Exception as exc:  # noqa: BLE001
            log.info("Carbon unavailable (%s); no global hotkey", exc)
            return None
        return self._carbon

    def install(self, binding: str) -> bool:
        carbon = self._load()
        if carbon is None or not self._loop.ready:
            return False
        parsed = parse_accelerator(binding)
        if parsed is None:
            log.error("cannot parse the accelerator %r", binding)
            return False
        mods, key_code = parsed

        import ctypes

        class EventTypeSpec(ctypes.Structure):
            _fields_ = [("eventClass", ctypes.c_uint32), ("eventKind", ctypes.c_uint32)]

        class EventHotKeyID(ctypes.Structure):
            _fields_ = [("signature", ctypes.c_uint32), ("id", ctypes.c_uint32)]

        HANDLER = ctypes.CFUNCTYPE(
            ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        )

        def handler(_next_handler, _event, _user_data):  # noqa: ANN001, ANN202
            try:
                self._on_pressed()
            except Exception:  # noqa: BLE001 - never propagate into Carbon
                log.exception("hotkey handler failed")
            return 0  # noErr

        self._handler_ref = HANDLER(handler)

        kEventClassKeyboard = 0x6B657962  # 'keyb'
        kEventHotKeyPressed = 5
        spec = EventTypeSpec(kEventClassKeyboard, kEventHotKeyPressed)

        carbon.GetApplicationEventTarget.restype = ctypes.c_void_p
        target = carbon.GetApplicationEventTarget()

        status = carbon.InstallEventHandler(
            ctypes.c_void_p(target), self._handler_ref, 1,
            ctypes.byref(spec), None, None,
        )
        if status != 0:
            log.error("InstallEventHandler failed (OSStatus %d)", status)
            return False

        hotkey_id = EventHotKeyID(self.SIGNATURE, self.HOTKEY_ID)
        ref = ctypes.c_void_p()
        status = carbon.RegisterEventHotKey(
            ctypes.c_uint32(key_code), ctypes.c_uint32(mods), hotkey_id,
            ctypes.c_void_p(target), 0, ctypes.byref(ref),
        )
        if status != 0:
            # -9878 is eventHotKeyExistsErr: another application owns the chord.
            if status == -9878:
                log.error("%s is already registered by another application", binding)
            else:
                log.error("RegisterEventHotKey failed for %s (OSStatus %d)", binding, status)
            return False
        self._ref = ref
        self._installed = binding
        log.info("registered %s", binding)
        return True

    def uninstall(self) -> bool:
        if self._ref is None or self._carbon is None:
            return False
        self._carbon.UnregisterEventHotKey(self._ref)
        self._ref = None
        self._installed = None
        return True

    def installed(self) -> bool:
        return self._installed is not None

    def conflicts(self, binding: str) -> list[str]:
        """macOS cannot say *who* owns a chord, only whether registering fails."""
        if parse_accelerator(binding) is None:
            return [f"{binding} cannot be parsed"]
        return []
