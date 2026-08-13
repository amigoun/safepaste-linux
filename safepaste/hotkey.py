"""Registering the on-demand "sanitise the clipboard" shortcut.

GNOME 46 does not implement the `org.freedesktop.portal.GlobalShortcuts` portal
(it arrived later), so the only route to a genuine system-wide shortcut on this
release is gnome-settings-daemon's custom-keybindings list. That is a compositor
level grab, which is what makes it work in every application.

Two deliberate choices:

* The binding is Ctrl+Alt+V, not Ctrl+Shift+V. The latter is already GNOME
  Terminal's paste (`org.gnome.Terminal.Legacy.Keybindings paste`), and a
  compositor grab outranks an application accelerator, so taking it would break
  pasting in the terminal.
* The command shells out to `gdbus`, a small C binary, rather than to Python. The
  keybinding spawns a fresh process on every press, and paying interpreter
  start-up on a keystroke is felt.

We never grab Ctrl+V itself. It would have to be re-injected for every paste
system-wide, and a daemon that died would leave the machine unable to paste at
all until the binding was removed by hand.
"""

from __future__ import annotations

import logging
import shutil

from gi.repository import Gio

from .daemon import BUS_NAME, OBJECT_PATH

log = logging.getLogger(__name__)

MEDIA_KEYS_SCHEMA = "org.gnome.settings-daemon.plugins.media-keys"
CUSTOM_SCHEMA = "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
CUSTOM_PATH_BASE = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"
OUR_PATH = f"{CUSTOM_PATH_BASE}safepaste/"
OUR_NAME = "SafePaste: sanitise clipboard"

DEFAULT_BINDING = "<Control><Alt>v"


def _command() -> str:
    gdbus = shutil.which("gdbus") or "gdbus"
    return (
        f"{gdbus} call --session --dest {BUS_NAME} "
        f"--object-path {OBJECT_PATH} --method {BUS_NAME}.SafePaste"
    )


def _schema_available(schema_id: str) -> bool:
    source = Gio.SettingsSchemaSource.get_default()
    return source is not None and source.lookup(schema_id, True) is not None


def available() -> bool:
    """True if this desktop exposes the custom-keybindings mechanism."""
    return _schema_available(MEDIA_KEYS_SCHEMA) and _schema_available(CUSTOM_SCHEMA)


def install(binding: str = DEFAULT_BINDING) -> bool:
    """Register the shortcut, leaving any other application's bindings alone."""
    if not available():
        log.warning(
            "this desktop has no %s schema; skipping shortcut registration",
            MEDIA_KEYS_SCHEMA,
        )
        return False

    entry = Gio.Settings.new_with_path(CUSTOM_SCHEMA, OUR_PATH)
    entry.set_string("name", OUR_NAME)
    entry.set_string("command", _command())
    entry.set_string("binding", binding)

    media = Gio.Settings.new(MEDIA_KEYS_SCHEMA)
    paths = list(media.get_strv("custom-keybindings"))
    if OUR_PATH not in paths:
        # Append rather than replace: this list is shared with every other
        # application-defined shortcut on the system.
        paths.append(OUR_PATH)
        media.set_strv("custom-keybindings", paths)
    Gio.Settings.sync()
    log.info("registered %s as %s", binding, OUR_NAME)
    return True


def uninstall() -> bool:
    """Remove our entry. Safe to call when it was never installed."""
    if not available():
        return False

    media = Gio.Settings.new(MEDIA_KEYS_SCHEMA)
    paths = [p for p in media.get_strv("custom-keybindings") if p != OUR_PATH]
    media.set_strv("custom-keybindings", paths)

    entry = Gio.Settings.new_with_path(CUSTOM_SCHEMA, OUR_PATH)
    for key in ("name", "command", "binding"):
        entry.reset(key)
    Gio.Settings.sync()
    log.info("removed the SafePaste shortcut")
    return True


def installed() -> bool:
    if not available():
        return False
    media = Gio.Settings.new(MEDIA_KEYS_SCHEMA)
    return OUR_PATH in media.get_strv("custom-keybindings")


def current_binding() -> str | None:
    if not installed():
        return None
    entry = Gio.Settings.new_with_path(CUSTOM_SCHEMA, OUR_PATH)
    return entry.get_string("binding") or None


def conflicts(binding: str) -> list[str]:
    """Report existing bindings that would fight the requested accelerator.

    Application-level accelerators lose to a compositor grab silently, so a
    conflict is worth naming before it is taken rather than after.
    """
    found: list[str] = []
    source = Gio.SettingsSchemaSource.get_default()
    if source is None:
        return found

    # Only the well-known shortcut schemas: enumerating every schema on the
    # system is slow and mostly noise. Relocatable ones are listed with the path
    # they actually live at, because Gio.Settings.new() on a relocatable schema
    # calls g_error() and *aborts the process* — it does not raise something
    # Python can catch, so the check has to happen before construction.
    for schema_id, path in (
        ("org.gnome.desktop.wm.keybindings", None),
        ("org.gnome.shell.keybindings", None),
        ("org.gnome.settings-daemon.plugins.media-keys", None),
        ("org.gnome.Terminal.Legacy.Keybindings", "/org/gnome/terminal/legacy/keybindings/"),
    ):
        schema = source.lookup(schema_id, True)
        if schema is None:
            continue
        relocatable = schema.get_path() is None
        if relocatable and path is None:
            continue
        settings = (
            Gio.Settings.new_with_path(schema_id, path)
            if relocatable
            else Gio.Settings.new(schema_id)
        )
        for key in schema.list_keys():
            try:
                value = settings.get_value(key)
            except Exception:  # noqa: BLE001
                continue
            kind = value.get_type_string()
            if kind == "s":
                values = [value.get_string()]
            elif kind == "as":
                values = list(value.unpack())
            else:
                continue
            if binding in values:
                found.append(f"{schema_id} {key}")
    return found


def main(argv: list[str] | None = None) -> int:
    """`python -m safepaste.hotkey install|remove|status`."""
    import argparse
    import logging as _logging

    ap = argparse.ArgumentParser(prog="safepaste-hotkey")
    ap.add_argument("action", choices=("install", "remove", "status"))
    ap.add_argument("--binding", default=DEFAULT_BINDING)
    args = ap.parse_args(argv)
    _logging.basicConfig(level=_logging.INFO, format="%(message)s")

    if args.action == "install":
        clashes = conflicts(args.binding)
        if clashes:
            log.warning(
                "%s is already bound by: %s\n"
                "A compositor grab wins, so those will stop working.",
                args.binding,
                ", ".join(clashes),
            )
        return 0 if install(args.binding) else 1
    if args.action == "remove":
        return 0 if uninstall() else 1

    if installed():
        print(f"installed: {current_binding()}")
        print(f"command:   {_command()}")
    else:
        print("not installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
