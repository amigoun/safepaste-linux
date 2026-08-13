"""Putting text back on the clipboard.

Writes go through `wl-copy` rather than X11. Setting the Wayland selection is the
authoritative direction — Mutter mirrors it out to XWayland, so both native and
X11 applications see the result — whereas taking the X11 selection and hoping the
bridge propagates it inward is the long way round.

Known limitation, surfaced in the UI rather than hidden: `wl-copy` offers a single
MIME type per invocation, so replacing a rich clipboard with redacted text drops
the `text/html` flavour and any application-private ones. Safety wins here, but
the dialog says so plainly. Serving several flavours needs a resident selection
source of our own, which is a later change.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile

log = logging.getLogger(__name__)

WRITE_TIMEOUT = 3.0
DEFAULT_MIME = "text/plain;charset=utf-8"


def _run_wl_copy(args: list[str], payload: bytes | None) -> tuple[bool, str]:
    """Run wl-copy without deadlocking on its own daemonisation.

    `capture_output=True` is a trap here, and an expensive one to diagnose:
    wl-copy forks a background process to serve the selection and that child
    inherits our stdout/stderr, holding the pipes open for as long as it owns the
    clipboard. subprocess.run waits for EOF on those pipes, not merely for the
    parent to exit, so every write blocked until the timeout and was then
    reported as a failure — while having actually succeeded. Downstream, that
    meant "Restore original" never had anything to restore, plus a logged error
    claiming the clipboard still held the secret when it did not.

    Regular files instead of pipes fix it: there is no EOF to wait for, so run()
    returns as soon as wl-copy's parent exits, and we keep the diagnostics.
    """
    with tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(
                args,
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=err,
                timeout=WRITE_TIMEOUT,
                check=False,
                # The selection server should outlive us, exactly as it does for a
                # wl-copy run from a shell.
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        if proc.returncode != 0:
            err.seek(0)
            return False, err.read().decode("utf-8", "replace").strip()
    return True, ""


class ClipboardWriter:
    def __init__(self, mime: str = DEFAULT_MIME) -> None:
        self.mime = mime

    def write(self, text: str) -> bool:
        """Replace the clipboard contents. True on success."""
        ok, detail = _run_wl_copy(
            ["wl-copy", "--type", self.mime],
            text.encode("utf-8", "surrogatepass"),
        )
        if not ok:
            log.error("clipboard write failed: %s", detail)
            return False
        # Length only — never the content.
        log.debug("wrote %d chars to the clipboard", len(text))
        return True

    def clear(self) -> bool:
        ok, detail = _run_wl_copy(["wl-copy", "--clear"], None)
        if not ok:
            log.error("clipboard clear failed: %s", detail)
        return ok
