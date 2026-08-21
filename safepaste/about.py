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


def _open_with_portal(url: str) -> bool:
    """Ask the desktop portal to open `url`. False where there is no portal.

    This is first choice, and the reason is not portability -- it is that the
    daemon runs under a deliberately hardened systemd user unit
    (`NoNewPrivileges=true`, `RestrictSUIDSGID=true`, `ProtectSystem=strict`).
    Those flags are inherited by anything the daemon spawns, and Chrome's SUID
    sandbox helper cannot gain privileges under `no_new_privs`, so a browser
    launched as our *child* dies with

        FATAL ... The SUID sandbox helper binary was found, but is not
        configured correctly ... I'm aborting now

    which lands in the unit's journal and nowhere the user will ever look. From
    their side, About simply does nothing. The portal runs in the session
    outside our unit, so it launches the browser with normal privileges; all we
    hand over is the URI. Measured: a process with `no_new_privs` set still gets
    a tab this way, and does not with the two fallbacks below.
    """
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib
    except (ImportError, ValueError):
        return False
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        bus.call_sync(
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.OpenURI",
            "OpenURI",
            # ("parent window", uri, options). No parent: the tray is not a window.
            GLib.Variant("(ssa{sv})", ("", url, {})),
            None,
            Gio.DBusCallFlags.NONE,
            5000,
            None,
        )
    except Exception:  # noqa: BLE001 - no portal, or it refused the request
        log.debug("portal would not open %s, falling back", url, exc_info=True)
        return False
    log.info("handed %s to the desktop portal", url)
    return True


def _open_with_gio(url: str) -> bool:
    """Ask GLib's URI handler to open `url`. False where there is no GLib.

    Second choice: this spawns the handler as a child of whoever calls it, which
    is exactly what `_open_with_portal` exists to avoid. Kept because it works
    where no portal is running -- a plain X session, a minimal container -- and
    because the CLI and any non-hardened front end are unaffected by the
    inheritance problem.
    """
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
    """Hand a URL to the desktop. False if nothing accepted it.

    Three mechanisms, in descending order of how well they survive the
    environment the daemon actually runs in: the portal (launched by the
    session), Gio (launched as our child), then `webbrowser`.

    `webbrowser` cannot be the only answer on Linux: CPython registers
    `xdg-open` as a browser only when DISPLAY or WAYLAND_DISPLAY is in the
    environment, and a systemd user unit that came up before the session
    exported either then has `webbrowser.open()` return False having tried
    nothing at all.

    True here means "something accepted the URI", which is not the same as "a
    window appeared" -- nothing at this layer can promise that, since the
    handler may still die after exec. That is what the FATAL above was.
    """
    if _open_with_portal(url):
        return True
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
