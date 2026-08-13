"""The resident daemon: watch, detect, redact, and expose a D-Bus surface.

The fail-safe ordering in `redact` mode is deliberate and worth stating: the
clipboard is replaced with the redacted text *before* the dialog is shown, and
the original is held in memory only. If the user ignores the dialog entirely, or
it fails to appear, or the daemon is killed mid-decision, the clipboard is
already safe. The alternative — ask first, replace second — leaves the raw secret
sitting on the clipboard during exactly the window where the user is distracted.

The D-Bus interface is also the seam for the optional GNOME Shell extension. The
extension cannot itself run a rule engine, but it *can* see which window has
focus and grab a real Ctrl+V, so it calls Inspect/Redact here and applies
per-application policy of its own.
"""

from __future__ import annotations

import logging
import pathlib
import time
from collections.abc import Callable
from dataclasses import dataclass

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from . import config as config_mod
from .clipboard.monitor import ClipboardEvent, XFixesMonitor
from .clipboard.writer import ClipboardWriter
from .detector import Detector, load_default, summarise, value_hash
from .redactor import RedactionStyle, redact
from .session import LockWatcher

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


@dataclass
class HeldOriginal:
    """A pre-redaction clipboard value, kept in memory for a short window."""

    text: str
    digest: str
    expires_at: float
    labels: tuple[str, ...]

    @property
    def alive(self) -> bool:
        return time.monotonic() < self.expires_at


class Daemon:
    def __init__(
        self,
        cfg: config_mod.Config | None = None,
        *,
        on_detection: Callable[[list, object, object], None] | None = None,
    ) -> None:
        self.config = cfg or config_mod.load()
        for warning in self.config._warnings:
            log.warning("config: %s", warning)

        self.detector = self._build_detector()
        self.writer = ClipboardWriter()
        self.monitor = XFixesMonitor(on_change=self._on_clipboard_change)
        self.locks = LockWatcher()
        # Created lazily: building it would provoke a consent dialog at login
        # for a feature that is off by default.
        self._injector = None
        self.loop = GLib.MainLoop()

        self._paused_until = 0.0
        self._held: HeldOriginal | None = None
        self._held_timer: int | None = None
        self._last_finding_count = 0
        self._last_secret_hashes: tuple[str, ...] = ()
        # Injected by the UI layer; a headless daemon simply has no presenter.
        self.on_detection = on_detection
        self._owner_id: int | None = None
        self._registration_id: int | None = None
        self._connection: Gio.DBusConnection | None = None

    # -- setup -------------------------------------------------------------

    def _build_detector(self) -> Detector:
        extra = self.config.extra_rule_paths()
        if extra:
            log.info("loading %d extra rule file(s)", len(extra))
        ruleset = load_default(extra_paths=extra)
        return Detector(
            ruleset,
            categories=self.config.category_set,
            excluded_hashes=self.config.excluded_hash_set,
            regex_timeout=self.config.regex_timeout,
            max_scan_bytes=self.config.max_scan_bytes,
        )

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

    # -- run ---------------------------------------------------------------

    def start(self) -> bool:
        """Attach to the clipboard and the bus, without running a main loop.

        Split from `run` so the GTK front end can drive its own Adw.Application
        loop instead — two GLib main loops in one process would fight.
        """
        if not self.monitor.start():
            log.error("clipboard monitor failed to start; nothing to do")
            return False
        self.locks.start()
        self._own_bus_name()
        log.info(
            "safepaste running: mode=%s categories=%d rules=%d",
            self.config.mode,
            len(self.config.categories),
            len(self.detector.active_rules),
        )
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
        if self._injector is not None:
            self._injector.close()
        self.monitor.stop()
        self._forget_original()
        if self._owner_id is not None:
            Gio.bus_unown_name(self._owner_id)
            self._owner_id = None
        if self.loop.is_running():
            self.loop.quit()

    # -- clipboard pipeline -------------------------------------------------

    def _on_clipboard_change(self, event: ClipboardEvent) -> None:
        if self.config.mode == "off" or self.paused:
            return
        if self.locks.locked:
            # wl-clipboard cannot complete a transfer while the lock screen
            # holds keyboard focus, and nothing can paste anyway.
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
        self._last_secret_hashes = tuple(
            value_hash(event.text[f.start : f.end]) for f in findings
        )

        result = redact(event.text, findings, self.redaction_style)

        if self.config.mode == "redact":
            # Replace first. See the module docstring: this is what makes
            # ignoring the dialog safe.
            self.monitor.note_own_write(result.text)
            if self.writer.write(result.text):
                self._hold_original(event, result.labels)
            else:
                log.error("could not replace the clipboard; it still holds the secret")

        self._emit_detected(info)
        if self.on_detection is not None:
            self.on_detection(findings, result, event)

    def _hold_original(self, event: ClipboardEvent, labels: tuple[str, ...]) -> None:
        self._forget_original()
        ttl = self.config.restore_timeout_secs
        if ttl <= 0:
            return
        self._held = HeldOriginal(
            text=event.text,
            digest=event.digest,
            expires_at=time.monotonic() + ttl,
            labels=labels,
        )
        self._held_timer = GLib.timeout_add_seconds(ttl, self._on_hold_expired)

    def _on_hold_expired(self) -> bool:
        log.debug("retention window elapsed; dropping the held original")
        self._forget_original()
        return False  # one-shot

    def _forget_original(self) -> None:
        if self._held_timer is not None:
            GLib.source_remove(self._held_timer)
            self._held_timer = None
        if self._held is not None:
            # Best effort: rebind the attribute so the only strong reference to
            # the plaintext goes away promptly. Python cannot guarantee the bytes
            # are scrubbed from the heap, and with swap enabled they may already
            # have reached disk — the README says so rather than implying more.
            self._held.text = ""
            self._held = None

    def restore_original(self) -> bool:
        if self._held is None or not self._held.alive:
            log.info("no original available to restore")
            return False
        text = self._held.text
        self.monitor.note_own_write(text)
        ok = self.writer.write(text)
        if ok:
            log.info("restored the original clipboard value")
            self._forget_original()
        return ok

    def safe_paste(self) -> int:
        """Sanitise whatever is on the clipboard right now, on demand."""
        if self.locks.refresh():
            log.info("safe paste ignored: session is locked")
            return 0
        event = self.monitor.reader.read_text()
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
        self._hold_original(event, result.labels)
        log.info("safe paste: removed %d secret(s)", result.secrets_removed)
        self._complete_paste()
        return result.secrets_removed

    def _complete_paste(self) -> None:
        """Send the paste keystroke, if the user opted in.

        Failure here is deliberately quiet and non-fatal: the sanitised text is
        already on the clipboard, so the worst case is that the user presses
        Ctrl+V themselves — which is exactly the default behaviour anyway.
        """
        if not self.config.auto_paste:
            return
        if self._injector is None:
            from .inject import PasteInjector, available

            if not available():
                log.info("no keyboard injection portal; leaving the paste to you")
                return
            self._injector = PasteInjector(
                restore_token=self.config.portal_restore_token or None,
                on_restore_token=self._store_restore_token,
            )
        self._injector.paste()

    def _store_restore_token(self, token: str) -> None:
        self.config.portal_restore_token = token
        config_mod.save(self.config)
        log.debug("stored the portal restore token; consent will not be asked again")

    def exclude_last_value(self) -> bool:
        """Stop flagging the values from the most recent detection."""
        if not self._last_secret_hashes:
            return False
        merged = tuple(
            dict.fromkeys(self.config.excluded_hashes + self._last_secret_hashes)
        )
        self.config.excluded_hashes = merged
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
        self.detector = self._build_detector()
        log.info("reloaded: %d rules active", len(self.detector.active_rules))

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
                    GLib.Variant("(s)", (json.dumps(summarise(self.detector.scan(text))),))
                )
            elif method == "Redact":
                (text,) = params.unpack()
                result = redact(text, self.detector.scan(text), self.redaction_style)
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
            "LastFindingCount": lambda: GLib.Variant("i", self._last_finding_count),
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
    if args.mode:
        cfg.mode = args.mode
    return Daemon(cfg).run()


if __name__ == "__main__":
    raise SystemExit(main())
