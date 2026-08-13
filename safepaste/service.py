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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if sys.platform.startswith("linux"):
        # The GLib/D-Bus front end: the XFIXES monitor watches an fd, and the tray
        # and hotkey both need the bus.
        from .daemon import main as daemon_main

        return daemon_main(args)

    if sys.platform in ("darwin", "win32", "cygwin"):
        # Both backends detect changes by comparing an integer, so the plain
        # polling loop drives them; neither needs a run loop until it grows a tray.
        from .shell import main as shell_main

        return shell_main(args)

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
