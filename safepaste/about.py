"""Where SafePaste points people, and how it gets them there.

The URL is a constant here rather than something read back from package
metadata, because on the platform this project started on there is no metadata
to read: the .deb copies the tree in and writes its own shims, so nothing ever
pip-installs itself and `importlib.metadata` has no distribution to find.
`tests/test_about.py` is what keeps this value and pyproject.toml's `Homepage`
from drifting apart.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

HOMEPAGE = "https://github.com/amigoun/safepaste-linux"


def _open_with_gio(url: str) -> bool:
    """Ask GLib's URI handler to open `url`. False where there is no GLib."""
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio
    except (ImportError, ValueError):
        return False  # not a GLib platform: macOS and Windows say so here
    try:
        return bool(Gio.AppInfo.launch_default_for_uri(url, None))
    except Exception:  # noqa: BLE001 - GLib.Error, or no handler installed
        log.debug("Gio would not open %s, falling back", url, exc_info=True)
        return False


def open_url(url: str) -> bool:
    """Hand a URL to the desktop's own handler. False if nothing took it."""
    # Gio first, wherever it exists, and `webbrowser` only as the fallback --
    # not the other way round. CPython registers `xdg-open` as a browser only
    # when DISPLAY or WAYLAND_DISPLAY is in the environment, and the daemon can
    # be started by a systemd user unit that came up before the session
    # exported either, in which case `webbrowser.open()` returns False having
    # tried nothing at all. Gio asks the desktop's URI handler and needs no
    # such variable.
    if _open_with_gio(url):
        return True

    import webbrowser

    if webbrowser.open(url):
        return True
    log.info("nothing on this session could open %s", url)
    return False


def open_homepage() -> bool:
    """Open the project page. This is all the tray's About item does."""
    return open_url(HOMEPAGE)
