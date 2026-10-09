"""The graphical front end.

This process owns the Adw.Application main loop and drives a `Daemon` inside it,
which is why Daemon.start() is separate from Daemon.run(): two GLib main loops in
one process would fight over the same file descriptors.

It is a background application with no primary window. `hold()` keeps it alive
without one, and the preferences window is created on demand. The
daemon remains fully usable headless — `python -m safepaste.daemon` needs none of
this — so a broken toolkit cannot take clipboard protection down with it.
"""

from __future__ import annotations

import logging
import pathlib

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib  # noqa: E402

from . import config as config_mod, hardening
from .daemon import Daemon
from .guard import NOT_REMOVED, PARTLY_CHECKED_BODY, PARTLY_CHECKED_TITLE, REMOVED

log = logging.getLogger(__name__)

APP_ID = "dev.safepaste.SafePaste"

# How long the "N secrets removed" notice stays up when there is no restore
# window to tie it to (retention switched off). Long enough to read and notice,
# short enough that it is never mistaken for the current protection state.
ALERT_FALLBACK_SECS = 20

# The redaction notice has an id of its own, so its expiry withdraws it without
# taking a warning ("could not be removed") down with it.
NOTICE_ID = "safepaste-redaction"
ALERT_ID = "safepaste-detection"


class SafePasteApp(Adw.Application):
    def __init__(self, cfg: config_mod.Config | None = None) -> None:
        super().__init__(
            application_id=APP_ID,
            # No window to open, and we must not exit when the last window closes.
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.config = cfg or config_mod.load()
        self.daemon = Daemon(
            self.config,
            on_detection=self._on_detection,
            on_incomplete=lambda _event: self._notify_simple(
                PARTLY_CHECKED_TITLE, PARTLY_CHECKED_BODY
            ),
            # So the tray follows the daemon's state rather than only the changes
            # made through the tray: a pause over D-Bus used to leave the menu
            # claiming to be guarding.
            on_state_changed=self._refresh_tray,
            # The notice reports a redaction and offers the undo; it has no form
            # that leaves the secret and asks, so `ask` redacts here too.
            can_ask=False,
        )
        self.tray = None
        self._prefs_window = None
        self._alert_timer: int | None = None

    # -- lifecycle ---------------------------------------------------------

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        # Keep running with no window on screen.
        self.hold()

        if not self.daemon.start():
            log.error("clipboard protection could not start")
            self.quit()
            return

        self._install_actions()
        self._start_tray()

    def do_activate(self) -> None:
        # Re-launching a background app should show its settings rather than
        # silently doing nothing.
        self.show_preferences()

    def do_shutdown(self) -> None:
        if self.tray is not None:
            self.tray.stop()
        self.daemon.shutdown()
        Adw.Application.do_shutdown(self)

    def _install_actions(self) -> None:
        for name, handler in (
            ("safe-paste", lambda *_: self.daemon.safe_paste()),
            ("preferences", lambda *_: self.show_preferences()),
            ("quit", lambda *_: self.quit()),
            # The redaction notice's buttons, and its body: a click on the body
            # would otherwise activate the app and open Preferences.
            ("restore-original", lambda *_: self._on_restore()),
            ("not-a-secret", lambda *_: self._on_not_a_secret()),
            ("dismiss-notice", lambda *_: None),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

    # -- tray --------------------------------------------------------------

    def _start_tray(self) -> None:
        # Asked of the backend rather than imported: a platform with no status-icon
        # mechanism returns None, and a desktop with the mechanism but no host
        # running returns False from start(). Neither may stop clipboard
        # protection, which is the part that matters.
        try:
            self.tray = self.daemon.guard.backend.tray(
                on_mode=self._set_mode,
                on_pause=lambda secs: self._set_paused(True, secs),
                on_resume=lambda: self._set_paused(False, 0),
                on_safe_paste=lambda: self.daemon.safe_paste(),
                on_preferences=self.show_preferences,
                on_about=self.show_about,
                on_quit=self.quit,
            )
            if self.tray is None:
                log.info("this platform offers no status icon; running without one")
                return
            if self.tray.start():
                self.tray.set_state(self.config.mode, self.daemon.paused)
            else:
                log.info("no status-notifier host; running without a status icon")
                self.tray = None
        except Exception as exc:  # noqa: BLE001 - the tray is strictly optional
            log.warning("tray failed to start: %s", exc)
            self.tray = None

    def _refresh_tray(self) -> None:
        if self.tray is None:
            return
        # A deliberate mode or pause change ends the previous detection's notice:
        # the user has moved on, and leaving it up is how "1 secret removed" came
        # to sit above a paused guard.
        self._clear_alert()
        self.tray.set_state(self.config.mode, self.daemon.paused)

    # -- the transient detection notice ------------------------------------

    def _show_alert(self, secrets: int, removed: bool) -> None:
        if self.tray is None:
            return
        self.tray.set_alert(secrets, removed=removed)
        # Expire it. `clear_alert()` had no caller anywhere, so one detection left
        # the tray reading "1 secret removed" -- and reporting NeedsAttention -- for
        # the rest of the session.
        #
        # The lifetime is the restore window, because that is exactly how long the
        # event stays actionable: while the original is still held, "1 secret
        # removed" is something you can still do something about. With retention
        # switched off there is no such window, so fall back to long enough to read.
        seconds = self.config.restore_timeout_secs or ALERT_FALLBACK_SECS
        self._cancel_alert_timer()
        self._alert_timer = GLib.timeout_add_seconds(seconds, self._on_alert_expired)

    def _on_alert_expired(self) -> bool:
        self._alert_timer = None
        if self.tray is not None:
            self.tray.clear_alert()
        # Its Restore button stops working when the window closes; a notice left
        # in the message list would offer it anyway.
        self.withdraw_notification(NOTICE_ID)
        return GLib.SOURCE_REMOVE

    def _cancel_alert_timer(self) -> None:
        # A newer detection restarts the clock rather than inheriting the old one,
        # which would otherwise clear the new notice early.
        if self._alert_timer is not None:
            GLib.source_remove(self._alert_timer)
            self._alert_timer = None

    def _clear_alert(self) -> None:
        self._cancel_alert_timer()
        if self.tray is not None:
            self.tray.clear_alert()

    def _set_mode(self, mode: str) -> None:
        # No explicit repaint: the daemon notifies on every state change, whatever
        # route it arrived by, and this is one of those routes.
        self.daemon.set_mode(mode)

    def _set_paused(self, paused: bool, seconds: int) -> None:
        self.daemon.set_paused(paused, seconds)
        if paused and seconds:
            # Come back and repaint once the pause lapses, so the icon does not
            # sit there claiming to be paused after protection has resumed.
            GLib.timeout_add_seconds(seconds + 1, self._on_pause_lapsed)

    def _on_pause_lapsed(self) -> bool:
        self._refresh_tray()
        return False

    # -- detection presentation --------------------------------------------

    def _on_detection(self, findings: list, result, event) -> None:
        """Called by the daemon after a scan that found something."""
        secrets = result.secrets_removed if result.changed else len(findings)
        outcome = self.daemon.guard.last_outcome
        self._show_alert(secrets, removed=outcome == REMOVED)

        if outcome == NOT_REMOVED:
            # The notice reports a completed redaction; this one did not happen.
            noun = "secret" if secrets == 1 else "secrets"
            self._notify_simple(
                f"{secrets} {noun} could not be removed",
                "The clipboard still holds the original. Do not paste it.",
            )
            return

        mode = self.config.mode
        if mode == "notify":
            self._notify(secrets, result.labels)
            return
        if mode == "off":
            return

        # In redact mode the clipboard has already been replaced; the notice
        # reports a completed action and offers the undo.
        self._present_notice(result, event)

    def _present_notice(self, result, event) -> None:
        """Say what was removed, without taking the keyboard.

        This used to be a dialog, and a dialog takes keyboard focus from the app
        the user was typing in. Their next keys landed on it: in a terminal,
        Tab, Tab, Enter (or Down, Down, Enter) pressed "Restore original" and a
        lone Enter ticked "Never flag this value again" -- the secret came back
        or was whitelisted by keystrokes meant for something else. A
        notification never takes focus, so both actions now need a click.

        One stable id, so a newer copy's notice replaces the older one rather
        than leaving a stale Restore button behind it.
        """
        secrets = result.secrets_removed
        noun = "secret" if secrets == 1 else "secrets"
        note = Gio.Notification.new(f"{secrets} {noun} removed from the clipboard")
        lines = [_label_summary(result.labels)]
        lines.append(f"{result.chars_kept:,} characters were kept.")
        if getattr(event, "has_rich_flavours", False):
            lines.append("Rich formatting was dropped; the clipboard holds plain text.")
        seconds = self.config.restore_timeout_secs
        if seconds > 0:
            lines.append(f"The original can be restored for {seconds} seconds.")
            note.add_button("Restore original", "app.restore-original")
        note.add_button("Not a secret", "app.not-a-secret")
        note.set_body("\n".join(lines))
        note.set_default_action("app.dismiss-notice")
        note.set_priority(Gio.NotificationPriority.HIGH)
        self.send_notification(NOTICE_ID, note)

    def _on_restore(self) -> None:
        if not self.daemon.restore_original():
            self._notify_simple(
                "Could not restore",
                "The original value is no longer being held.",
            )

    def _on_not_a_secret(self) -> None:
        """Stop flagging the value, and give it back where it is still held.

        Both, because a notice button is one click: the dialog had a checkbox
        to pair with Restore, and once the notice is clicked away nothing else
        offers the undo.
        """
        self.daemon.exclude_last_value()
        if self.config.restore_timeout_secs > 0:
            self._on_restore()

    def _notify(self, secrets: int, labels: tuple[str, ...]) -> None:
        noun = "secret" if secrets == 1 else "secrets"
        self._notify_simple(f"{secrets} {noun} on the clipboard", _label_summary(labels))

    def _notify_simple(self, title: str, body: str) -> None:
        note = Gio.Notification.new(title)
        note.set_body(body)
        note.set_priority(Gio.NotificationPriority.HIGH)
        # A stable id replaces the previous notification instead of stacking.
        self.send_notification(ALERT_ID, note)

    # -- preferences -------------------------------------------------------

    def show_preferences(self) -> None:
        if self._prefs_window is not None:
            self._prefs_window.present()
            return
        try:
            from .ui.prefs import PreferencesWindow
        except ImportError as exc:
            log.warning("preferences window unavailable: %s", exc)
            return
        self._prefs_window = PreferencesWindow(
            config=self.config, on_changed=self._on_config_changed
        )
        self._prefs_window.connect("close-request", self._on_prefs_closed)
        self._prefs_window.present()

    def _on_prefs_closed(self, *_args) -> bool:
        self._prefs_window = None
        return False

    # -- about -------------------------------------------------------------

    def show_about(self) -> None:
        """Open the project page in the browser.

        Deliberately not an about *dialog*: the same menu item exists on macOS
        and Windows, where the front end is `PollingShell` and there is no
        toolkit to draw one with (its Preferences item is a notification saying
        where the config file lives, for the same reason). A URL is the one
        thing all three platforms can honour identically.
        """
        from .about import HOMEPAGE, open_url

        if not open_url(HOMEPAGE):
            # Nothing took the URL, so put it where it can at least be read.
            self._notify_simple("SafePaste", HOMEPAGE)

    def _on_config_changed(self) -> None:
        config_mod.save(self.config)
        self.daemon.reload()
        self._refresh_tray()


def _label_summary(labels: tuple[str, ...]) -> str:
    body = ", ".join(labels[:3])
    if len(labels) > 3:
        body += f", and {len(labels) - 3} more"
    return body


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="safepaste", description="Guard the clipboard against pasted secrets."
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--config", type=pathlib.Path, help="alternative config file")
    args, rest = ap.parse_known_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    cfg = config_mod.load(args.config)
    # Before anything reads a clipboard, after logging exists so a degraded
    # result is visible, and after the config because refusing ptrace is the
    # user's call -- it costs them the portal.
    hardening.harden(refuse_ptrace=cfg.refuse_ptrace)
    return SafePasteApp(cfg).run([sys.argv[0], *rest])


if __name__ == "__main__":
    raise SystemExit(main())
