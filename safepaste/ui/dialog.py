"""The "what was detected" dialog.

Two things about the wording are deliberate. It says what *has already happened*
("2 secrets removed"), not what might happen, because in the default fail-safe
mode the clipboard was already replaced before this window appeared. And it
reports how much survived — "12,481 characters kept intact" — because the fear
this dialog has to answer is "did it mangle my document?".

The formatting-loss note only appears when there was formatting to lose. Telling
someone their rich text was dropped when they copied a line of shell is noise.
"""

from __future__ import annotations

import logging

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

log = logging.getLogger(__name__)

RESPONSE_OK = "ok"
RESPONSE_RESTORE = "restore"


class DetectionDialog(Adw.MessageDialog):
    """Reports a completed redaction and offers to undo it."""

    def __init__(
        self,
        *,
        secrets: int,
        labels: tuple[str, ...],
        chars_kept: int,
        can_restore: bool,
        restore_seconds: int,
        formatting_lost: bool = False,
        parent: Gtk.Window | None = None,
    ) -> None:
        noun = "secret" if secrets == 1 else "secrets"
        super().__init__(
            transient_for=parent,
            modal=parent is not None,
            heading=f"{secrets} {noun} removed from the clipboard",
        )

        self.set_body(self._body_text(chars_kept, formatting_lost))
        self.set_extra_child(self._detail_box(labels))

        self.add_response(RESPONSE_OK, "_OK")
        self.set_default_response(RESPONSE_OK)
        self.set_close_response(RESPONSE_OK)

        if can_restore:
            self.add_response(RESPONSE_RESTORE, "_Restore original")
            # Destructive rather than suggested: this puts the secret back.
            self.set_response_appearance(
                RESPONSE_RESTORE, Adw.ResponseAppearance.DESTRUCTIVE
            )
            if restore_seconds:
                self.set_body(
                    self.get_body()
                    + f"\n\nThe original can be restored for {restore_seconds} seconds."
                )

        self.exclude_check = Gtk.CheckButton(label="Never flag this value again")
        self.exclude_check.set_tooltip_text(
            "Stores a SHA-256 digest of the value, never the value itself."
        )
        self.get_extra_child().append(self.exclude_check)

    @property
    def exclude_requested(self) -> bool:
        return self.exclude_check.get_active()

    @staticmethod
    def _body_text(chars_kept: int, formatting_lost: bool) -> str:
        body = f"{chars_kept:,} characters were kept intact."
        if formatting_lost:
            body += (
                "\n\nRich formatting was dropped — the clipboard now holds plain "
                "text only."
            )
        return body

    @staticmethod
    def _detail_box(labels: tuple[str, ...]) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(6)
        box.set_margin_bottom(6)

        for label in labels:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
            icon.add_css_class("success")
            row.append(icon)
            text = Gtk.Label(label=label, xalign=0.0)
            text.set_wrap(True)
            text.set_max_width_chars(44)
            row.append(text)
            box.append(row)
        return box


def present_detection(
    *,
    secrets: int,
    labels: tuple[str, ...],
    chars_kept: int,
    can_restore: bool,
    restore_seconds: int,
    formatting_lost: bool,
    parent: Gtk.Window | None = None,
    on_restore=None,
    on_exclude=None,
) -> DetectionDialog:
    """Build, wire and show the dialog. Returns it so callers can close it.

    `parent` should be supplied even though the dialog works without one. GTK logs
    "AdwMessageDialog mapped without a transient parent. This is discouraged." for
    every parentless dialog -- nine times in one afternoon of real use -- and being
    discouraged today tends to become unsupported later. A never-presented window is
    enough to satisfy it; verified that the dialog still maps and is visible.
    """
    dialog = DetectionDialog(
        secrets=secrets,
        labels=labels,
        chars_kept=chars_kept,
        can_restore=can_restore,
        restore_seconds=restore_seconds,
        formatting_lost=formatting_lost,
        parent=parent,
    )

    def _on_response(dlg: DetectionDialog, response: str) -> None:
        # Read the checkbox before acting on the response: choosing to restore and
        # to stop flagging the value are independent, and both can be wanted.
        if dlg.exclude_requested and on_exclude is not None:
            on_exclude()
        if response == RESPONSE_RESTORE and on_restore is not None:
            on_restore()
        dlg.destroy()

    dialog.connect("response", _on_response)
    dialog.present()
    return dialog
