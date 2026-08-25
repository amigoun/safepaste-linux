"""The Linux front end: a GLib main loop and a D-Bus service around `Guard`.

Everything about *what to do* with a detected secret lives in `safepaste.guard`,
which has no desktop dependencies. This file supplies only the two things GLib and
D-Bus are here for: something to run the event loop, and an IPC surface.

That surface is also the seam for the optional GNOME Shell extension. An extension
cannot run a rule engine, but it can grab a real Ctrl+V inside the compositor and
see which window has focus, so it calls Inspect/Redact here and applies
per-application policy of its own — the one thing `org.gnome.Shell.Introspect`
refuses to make possible from outside.
"""

from __future__ import annotations

import json
import logging
import pathlib
from typing import Any

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from . import config as config_mod, hardening
from .backend import Backend, get_backend
from .guard import Guard

log = logging.getLogger(__name__)

BUS_NAME = "dev.safepaste.Daemon"
OBJECT_PATH = "/dev/safepaste/Daemon"

INTROSPECTION = f"""
<node>
  <interface name="{BUS_NAME}">
    <!-- Sanitise the clipboard now and, if enabled, complete the paste. -->
    <method name="SafePaste">
      <arg type="i" name="secrets_removed" direction="out"/>
    </method>
    <!-- Detection only. Returns a JSON summary; never echoes the input. -->
    <method name="Inspect">
      <arg type="s" name="text" direction="in"/>
      <arg type="s" name="summary_json" direction="out"/>
    </method>
    <!-- Redact arbitrary text without touching the clipboard. -->
    <method name="Redact">
      <arg type="s" name="text" direction="in"/>
      <arg type="s" name="redacted" direction="out"/>
      <arg type="i" name="secrets_removed" direction="out"/>
    </method>
    <!-- Restore the most recent pre-redaction value, if still held. -->
    <method name="RestoreOriginal">
      <arg type="b" name="restored" direction="out"/>
    </method>
    <method name="SetPaused">
      <arg type="b" name="paused" direction="in"/>
      <arg type="u" name="seconds" direction="in"/>
    </method>
    <method name="SetMode">
      <arg type="s" name="mode" direction="in"/>
    </method>
    <method name="ExcludeLastValue">
      <arg type="b" name="excluded" direction="out"/>
    </method>
    <method name="Reload"/>
    <property name="Mode" type="s" access="read"/>
    <property name="Paused" type="b" access="read"/>
    <property name="LastFindingCount" type="i" access="read"/>
    <property name="Version" type="s" access="read"/>
    <!-- Emitted after every scan that found something, for the tray. -->
    <signal name="SecretsDetected">
      <arg type="i" name="secrets"/>
      <arg type="s" name="summary_json"/>
    </signal>
  </interface>
</node>
"""


class _GLibTimer:
    """Guard's one-shot scheduler, backed by the GLib main loop."""

    def schedule(self, seconds: float, fn) -> Any:
        # GLib expects the callback to report whether it wants rescheduling;
        # Guard's contract is one-shot, so always stop.
        return GLib.timeout_add_seconds(int(seconds), lambda: (fn(), False)[1])

    def cancel(self, handle: Any) -> None:
        if handle is not None:
            GLib.source_remove(handle)


class Daemon:
    """GLib/D-Bus shell. Policy is delegated to Guard."""

    def __init__(
        self,
        cfg: config_mod.Config | None = None,
        *,
        on_detection=None,
        on_state_changed=None,
        backend: Backend | None = None,
    ) -> None:
        # Interposed rather than passed straight through: the bus signal must
        # fire for every detection regardless of whether a front end is attached,
        # and Guard should not know that D-Bus exists.
        self._forward_detection = on_detection
        # Fired after the mode or pause state changes by *any* route. Without it a
        # front end only learns about changes it made itself, so `gdbus ... SetPaused`
        # or `safepaste`'s own D-Bus surface would pause protection while the tray
        # went on claiming to be guarding.
        self._forward_state_change = on_state_changed
        self.guard = Guard(
            cfg,
            backend=backend or get_backend(),
            on_detection=self._on_detection,
            timer=_GLibTimer(),
        )
        self.loop = GLib.MainLoop()
        self._owner_id: int | None = None
        self._registration_id: int | None = None
        self._connection: Gio.DBusConnection | None = None

    # Delegation, so the D-Bus handlers and the GTK front end need no knowledge
    # of where the policy actually lives.
    @property
    def config(self) -> config_mod.Config:
        return self.guard.config

    @property
    def detector(self):
        return self.guard.detector

    @property
    def paused(self) -> bool:
        return self.guard.paused

    safe_paste = property(lambda self: self.guard.safe_paste)
    restore_original = property(lambda self: self.guard.restore_original)
    exclude_last_value = property(lambda self: self.guard.exclude_last_value)
    reload = property(lambda self: self.guard.reload)

    # Not delegating properties like the rest: every route into these -- the tray,
    # D-Bus, a future extension -- has to end in the same notification, and a
    # `property(lambda ...)` shortcut is exactly how the tray came to reflect only
    # the changes it made itself.
    def set_mode(self, mode: str) -> None:
        self.guard.set_mode(mode)
        self._notify_state_changed()

    def set_paused(self, paused: bool, seconds: int = 0) -> None:
        self.guard.set_paused(paused, seconds)
        self._notify_state_changed()

    def _notify_state_changed(self) -> None:
        if self._forward_state_change is None:
            return
        try:
            self._forward_state_change()
        except Exception:  # noqa: BLE001 - a repaint must not take the daemon down
            log.exception("state-change observer failed")

    def _on_detection(self, findings, result, event) -> None:
        from .detector import summarise

        self._emit_detected(summarise(findings))
        if self._forward_detection is not None:
            self._forward_detection(findings, result, event)

    # -- run ---------------------------------------------------------------

    def start(self) -> bool:
        if not self.guard.start():
            return False
        self._own_bus_name()
        return True

    def run(self) -> int:
        """Headless entry point: own the main loop ourselves."""
        if not self.start():
            return 1
        try:
            self.loop.run()
        except KeyboardInterrupt:
            log.info("interrupted")
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        self.guard.stop()
        if self._owner_id is not None:
            Gio.bus_unown_name(self._owner_id)
            self._owner_id = None
        if self.loop.is_running():
            self.loop.quit()

    # -- D-Bus -------------------------------------------------------------

    def _own_bus_name(self) -> None:
        self._owner_id = Gio.bus_own_name(
            Gio.BusType.SESSION,
            BUS_NAME,
            Gio.BusNameOwnerFlags.NONE,
            self._on_bus_acquired,
            None,
            self._on_name_lost,
        )

    def _on_bus_acquired(self, connection: Gio.DBusConnection, name: str) -> None:
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        self._connection = connection
        self._registration_id = connection.register_object(
            OBJECT_PATH,
            node.interfaces[0],
            self._handle_method_call,
            self._handle_get_property,
            None,
        )
        log.debug("registered %s at %s", name, OBJECT_PATH)

    def _on_name_lost(self, connection: Gio.DBusConnection | None, name: str) -> None:
        # Another instance already owns the name: exit rather than run a second
        # monitor that would fight the first over the clipboard.
        log.error("could not take the bus name %s; is safepaste already running?", name)
        self.shutdown()

    def _emit_detected(self, info: dict) -> None:
        if self._connection is None:
            return
        import json

        try:
            self._connection.emit_signal(
                None,
                OBJECT_PATH,
                BUS_NAME,
                "SecretsDetected",
                GLib.Variant("(is)", (int(info["secrets"]), json.dumps(info))),
            )
        except GLib.Error as exc:
            log.debug("could not emit SecretsDetected: %s", exc)

    def _handle_method_call(
        self,
        _connection,
        _sender,
        _path,
        _interface,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        import json

        try:
            if method == "SafePaste":
                invocation.return_value(GLib.Variant("(i)", (self.safe_paste(),)))
            elif method == "Inspect":
                (text,) = params.unpack()
                invocation.return_value(
                    GLib.Variant("(s)", (json.dumps(self.guard.inspect(text)),))
                )
            elif method == "Redact":
                (text,) = params.unpack()
                result = self.guard.redact_text(text)
                invocation.return_value(
                    GLib.Variant("(si)", (result.text, result.secrets_removed))
                )
            elif method == "RestoreOriginal":
                invocation.return_value(GLib.Variant("(b)", (self.restore_original(),)))
            elif method == "SetPaused":
                paused, seconds = params.unpack()
                self.set_paused(paused, seconds)
                invocation.return_value(None)
            elif method == "SetMode":
                (mode,) = params.unpack()
                self.set_mode(mode)
                invocation.return_value(None)
            elif method == "ExcludeLastValue":
                invocation.return_value(GLib.Variant("(b)", (self.exclude_last_value(),)))
            elif method == "Reload":
                self.reload()
                invocation.return_value(None)
            else:
                invocation.return_error_literal(
                    Gio.DBusError.quark(),
                    Gio.DBusError.UNKNOWN_METHOD,
                    f"unknown method {method}",
                )
        except Exception as exc:  # noqa: BLE001 - a bad call must not kill the daemon
            log.exception("D-Bus call %s failed", method)
            invocation.return_error_literal(
                Gio.DBusError.quark(), Gio.DBusError.FAILED, str(exc)
            )

    def _handle_get_property(
        self, _connection, _sender, _path, _interface, prop: str
    ) -> GLib.Variant | None:
        from . import __version__

        return {
            "Mode": lambda: GLib.Variant("s", self.config.mode),
            "Paused": lambda: GLib.Variant("b", self.paused),
            "LastFindingCount": lambda: GLib.Variant("i", self.guard.last_finding_count),
            "Version": lambda: GLib.Variant("s", __version__),
        }.get(prop, lambda: None)()


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="safepaste-daemon", description="Watch the clipboard for secrets."
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument(
        "--mode",
        choices=config_mod.MODES,
        help="override the configured protection mode for this run",
    )
    ap.add_argument("--config", type=pathlib.Path, help="alternative config file")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    cfg = config_mod.load(args.config)
    # Before anything reads a clipboard, after logging exists so a degraded
    # result is visible, and after the config because refusing ptrace is the
    # user's call -- it costs them the portal.
    hardening.harden(refuse_ptrace=cfg.refuse_ptrace)
    if args.mode:
        cfg.mode = args.mode
    return Daemon(cfg).run()


if __name__ == "__main__":
    raise SystemExit(main())
