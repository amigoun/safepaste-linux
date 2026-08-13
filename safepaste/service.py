"""Platform-dispatching entry point for the background service.

`safepaste-daemon` points here rather than at either shell directly, because the
two are not interchangeable and neither can be imported everywhere:
`safepaste.daemon` needs GLib and offers a D-Bus surface, and importing it on a
Mac fails outright; `safepaste.shell` is a plain polling loop and cannot drive a
file-descriptor-based monitor.

Dispatching on the backend rather than on sys.platform directly keeps the decision
in one place, and means a future backend only has to say which shape it is.
"""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


# What to tell someone whose install is missing the platform bindings. Reached via
# `pip install safepaste` on a bare Linux box, where PyGObject is deliberately not
# a declared dependency (it needs system headers). The bare ImportError names the
# module -- "No module named 'gi'" -- and not one reader in ten knows that the apt
# package for `gi` is called python3-gi.
_MISSING = {
    "linux": (
        "the GTK bindings are missing. On Ubuntu/Debian:\n"
        "    sudo apt install python3-gi python3-xlib gir1.2-gtk-4.0 "
        "gir1.2-adw-1\n"
        "or install SafePaste from the .deb, which depends on them. The "
        "detection CLI (`safepaste scan` / `redact`) needs none of this."
    ),
    "darwin": (
        "the macOS bindings are missing:\n"
        "    pip install pyobjc-framework-Cocoa pyobjc-framework-Quartz\n"
        "or install SafePaste with `brew install`, which bundles them."
    ),
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    try:
        if sys.platform.startswith("linux"):
            # The GLib/D-Bus front end: the XFIXES monitor watches an fd, and the
            # tray and hotkey both need the bus.
            from .daemon import main as daemon_main

            return daemon_main(args)

        if sys.platform in ("darwin", "win32", "cygwin"):
            # Both backends detect changes by comparing an integer, so the plain
            # polling loop drives them; neither needs a run loop until it grows a
            # tray.
            from .shell import main as shell_main

            return shell_main(args)
    except ImportError as exc:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")
        advice = _MISSING.get(
            "linux" if sys.platform.startswith("linux") else sys.platform
        )
        log.error("safepaste-daemon cannot start: %s", exc)
        if advice:
            log.error("%s", advice)
        return 3

    logging.basicConfig(level=logging.ERROR, format="%(message)s")
    log.error(
        "no SafePaste service for platform %r. The detection CLI (`safepaste "
        "scan` / `redact`) is portable and should work anyway; see "
        "safepaste/backend/__init__.py for what a new backend must implement.",
        sys.platform,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
