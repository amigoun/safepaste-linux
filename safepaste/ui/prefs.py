"""Preferences.

Mutates the live `Config` object and calls `on_changed` after each edit, so the
daemon picks changes up immediately rather than at the next restart. Every row
writes through on toggle — there is no Apply button, which matches how GNOME
settings behave everywhere else.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from ..config import MODES, Config
from ..detector.rules import CATEGORIES, CATEGORY_LABELS

log = logging.getLogger(__name__)

MODE_LABELS = {
    "redact": "Redact automatically",
    "ask": "Ask every time",
    "notify": "Notify only",
    "off": "Off",
}

MODE_DESCRIPTIONS = {
    "redact": "Replace secrets the moment they are copied, then offer to undo it.",
    "ask": "Leave the original in place and ask what to do.",
    "notify": "Send a notification, but never change the clipboard.",
    "off": "Stop checking the clipboard entirely.",
}

# Categories where switching off meaningfully lowers protection get a warning
# subtitle, so turning one off is a considered choice rather than a shrug.
CATEGORY_HINTS = {
    "private_keys": "SSH and PEM keys, kubeconfig client keys.",
    "connection_strings": "Database URLs that carry an inline password.",
    "high_entropy": "Catches unknown key formats. Expect false positives.",
}


class PreferencesWindow(Adw.PreferencesWindow):
    def __init__(
        self, *, config: Config, on_changed: Callable[[], None] | None = None
    ) -> None:
        super().__init__(title="SafePaste")
        self.set_default_size(560, 680)
        self.config = config
        self.on_changed = on_changed
        self._loading = True

        self.add(self._protection_page())
        self.add(self._detection_page())
        self._loading = False

    def _changed(self) -> None:
        if not self._loading and self.on_changed is not None:
            self.on_changed()

    # -- pages -------------------------------------------------------------

    def _protection_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Protection", icon_name="security-high-symbolic")

        group = Adw.PreferencesGroup(
            title="When a secret reaches the clipboard",
            description=(
                "Redacting automatically is the safe default: if you ignore the "
                "dialog and paste anyway, the secret is already gone."
            ),
        )
        self.mode_row = Adw.ComboRow(title="Protection")
        model = Gtk.StringList()
        for mode in MODES:
            model.append(MODE_LABELS[mode])
        self.mode_row.set_model(model)
        self.mode_row.set_selected(
            MODES.index(self.config.mode) if self.config.mode in MODES else 0
        )
        self.mode_row.set_subtitle(MODE_DESCRIPTIONS[self.config.mode])
        self.mode_row.connect("notify::selected", self._on_mode_changed)
        group.add(self.mode_row)

        self.restore_row = Adw.SpinRow.new_with_range(0, 600, 15)
        self.restore_row.set_title("Keep the original for")
        self.restore_row.set_subtitle(
            "Seconds during which Restore original still works. 0 disables undo."
        )
        self.restore_row.set_value(self.config.restore_timeout_secs)
        self.restore_row.connect("notify::value", self._on_restore_changed)
        group.add(self.restore_row)
        page.add(group)

        redaction = Adw.PreferencesGroup(
            title="Replacement text",
            description="What a removed secret is replaced with.",
        )
        self.placeholder_row = Adw.EntryRow(title="Placeholder")
        self.placeholder_row.set_text(self.config.placeholder)
        self.placeholder_row.connect("changed", self._on_placeholder_changed)
        redaction.add(self.placeholder_row)

        self.label_rules_row = Adw.SwitchRow(
            title="Name the detector",
            subtitle="Write [REDACTED:aws-access-token] instead of [REDACTED].",
        )
        self.label_rules_row.set_active(self.config.label_rules)
        self.label_rules_row.connect("notify::active", self._on_label_rules_changed)
        redaction.add(self.label_rules_row)
        page.add(redaction)

        paste = Adw.PreferencesGroup(
            title="Sanitise on demand",
            description=(
                f"Press {_pretty_accel(self.config.safe_paste_hotkey)} to clean the "
                "clipboard at any time."
            ),
        )
        self.auto_paste_row = Adw.SwitchRow(
            title="Complete the paste automatically",
            subtitle=(
                "Sends the keystroke for you. Needs one-time screen-sharing "
                "permission, because Wayland has no other way to type into "
                "another window."
            ),
        )
        self.auto_paste_row.set_active(self.config.auto_paste)
        self.auto_paste_row.connect("notify::active", self._on_auto_paste_changed)
        paste.add(self.auto_paste_row)
        page.add(paste)
        return page

    def _detection_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Detection", icon_name="edit-find-symbolic")

        group = Adw.PreferencesGroup(
            title="Secret types",
            description="Which kinds of secret to look for.",
        )
        enabled = self.config.category_set
        self.category_rows: dict[str, Adw.SwitchRow] = {}
        for category in CATEGORIES:
            row = Adw.SwitchRow(title=CATEGORY_LABELS[category])
            if category in CATEGORY_HINTS:
                row.set_subtitle(CATEGORY_HINTS[category])
            row.set_active(category in enabled)
            row.connect("notify::active", self._on_category_changed, category)
            group.add(row)
            self.category_rows[category] = row
        page.add(group)

        custom = Adw.PreferencesGroup(
            title="Custom rules",
            description=(
                "Drop Gitleaks-format TOML files in ~/.config/safepaste/rules/ to "
                "add your own patterns. Reusing an existing rule id replaces it."
            ),
        )
        page.add(custom)
        return page

    # -- handlers ----------------------------------------------------------

    def _on_mode_changed(self, row: Adw.ComboRow, _param) -> None:
        mode = MODES[row.get_selected()]
        self.config.mode = mode
        row.set_subtitle(MODE_DESCRIPTIONS[mode])
        self._changed()

    def _on_restore_changed(self, row: Adw.SpinRow, _param) -> None:
        self.config.restore_timeout_secs = int(row.get_value())
        self._changed()

    def _on_placeholder_changed(self, row: Adw.EntryRow) -> None:
        text = row.get_text().strip()
        if not text:
            return  # an empty placeholder would silently delete the secret's context
        self.config.placeholder = text
        self._changed()

    def _on_label_rules_changed(self, row: Adw.SwitchRow, _param) -> None:
        self.config.label_rules = row.get_active()
        self._changed()

    def _on_auto_paste_changed(self, row: Adw.SwitchRow, _param) -> None:
        self.config.auto_paste = row.get_active()
        self._changed()

    def _on_category_changed(
        self, row: Adw.SwitchRow, _param, category: str
    ) -> None:
        current = set(self.config.categories)
        if row.get_active():
            current.add(category)
        else:
            current.discard(category)
        # Preserve the canonical order rather than set order, so the config file
        # stays stable across edits and diffs cleanly.
        self.config.categories = tuple(c for c in CATEGORIES if c in current)
        self._changed()


def _pretty_accel(accel: str) -> str:
    """`<Control><Alt>v` -> `Ctrl+Alt+V`, for prose."""
    ok, key, mods = Gtk.accelerator_parse(accel)
    if not ok:
        return accel
    label = Gtk.accelerator_get_label(key, mods)
    return label or accel
