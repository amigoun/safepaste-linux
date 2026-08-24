"""Putting text back on the clipboard without putting a window on the screen.

The companion to `safepaste.clipboard.x11`, and the same argument. `wl-copy`
cannot set the Wayland selection on Mutter without keyboard focus, so it maps and
focuses a 1x1 window to get it -- which is the flash you see at the exact moment
a secret is redacted. Reads stopped doing that; this stops writes doing it.

Instead of asking Wayland to hold the value, SafePaste owns the **X11** CLIPBOARD
selection itself and serves conversion requests from the main loop. Mutter's
XWayland bridge mirrors an X11 owner out to the Wayland selection, so
Wayland-native applications see it -- that is the direction
`scripts/probe-clipboard.py` calls "X11 write visible to Wayland reader".
Owning a selection needs a window, but only as an address; it is never mapped.

**Large values go out as several appends, not as INCR.** ICCCM suggests INCR
above a size, and the honest reason this does not implement it is that it did not
need to: a ChangeProperty request here carries at most 262,140 bytes
(`max_request_length` is 65535 quads and python-xlib does not speak
BIG-REQUESTS), but a *property* has no such limit, so the value is appended in
chunks and announced once it is whole. The requestor never sees a partial
property, because SelectionNotify is only sent after the last append. Measured
byte-exact at 1 KB, 250 KB, 1 MiB and 5 MB, read back both by an X11 requestor
(`xclip`) and through Mutter's bridge (`wl-paste`). The residual risk is a
requestor that refuses a property above some size of its own and expects INCR;
none was found on GNOME 46, where nearly every consumer arrives via the bridge.

Two behaviour changes worth knowing about, both consequences of holding the value
in this process rather than handing it to a `wl-copy` that outlives us:

  * **If the daemon exits, a redacted clipboard goes empty** rather than keeping
    the redacted text. That is safe -- the secret is not what is left behind --
    but it is not what `wl-copy` did, and a user who copies, gets a redaction,
    then restarts SafePaste before pasting will find nothing to paste.
  * **The rich-flavour limitation is unchanged.** Owning the selection means we
    *could* offer several flavours, but the only thing we have to offer is
    redacted plain text; there is no HTML to reconstruct. The dialog still says
    so.
"""

from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger(__name__)

DEFAULT_MIME = "text/plain;charset=utf-8"

# Every flavour we will answer to, best first. All of them serve the same UTF-8
# bytes: ICCCM reserves STRING for Latin-1, but every modern requestor asks for
# UTF8_STRING or the MIME type first, and handing back mojibake to the ones that
# do not is worse than handing back UTF-8.
TEXT_TARGETS = (
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
    "TEXT",
)


class SelectionRequest(Protocol):
    """One "please convert the selection to this target" from another client."""

    requestor: object
    target: str
    property: str | None


class XOwnerConnection(Protocol):
    """Everything this module needs from an X server.

    A Protocol for the same reason as the reader's: the chunking, the target
    answers and the ownership handshake are the parts that carry bugs, and they
    should be testable without an X server.
    """

    def server_time(self) -> int: ...
    def take_ownership(self, timestamp: int) -> bool: ...
    def release_ownership(self, timestamp: int) -> None: ...
    def owns_selection(self) -> bool: ...
    def max_chunk(self) -> int: ...
    def put_atoms(self, req: SelectionRequest, prop: str, atoms: list[str]) -> None: ...
    def put_integer(self, req: SelectionRequest, prop: str, value: int) -> None: ...
    def put_bytes(
        self, req: SelectionRequest, prop: str, type_name: str, data: bytes
    ) -> None: ...
    def answer(self, req: SelectionRequest, prop: str | None) -> None: ...
    def close(self) -> None: ...


class X11SelectionOwner:
    """Holds the clipboard value and serves it. Nothing is ever shown on screen."""

    def __init__(self, connect=None, mime: str = DEFAULT_MIME) -> None:
        self._connect = connect
        self.mime = mime
        self._conn: XOwnerConnection | None = None
        self._data: bytes | None = None
        self._timestamp: int = 0
        # Set when the last write could not be made to stick, so a caller can
        # decide to fall back rather than believe the clipboard was replaced.
        self.last_error: str | None = None
        # Counters, for the live verification script and for tests.
        self.served = 0
        self.refused = 0

    # -- connection --------------------------------------------------------

    def _connection(self) -> XOwnerConnection | None:
        if self._conn is None:
            factory = self._connect
            if factory is None:
                from .x11_owner_conn import XlibOwnerConnection

                factory = XlibOwnerConnection
            try:
                self._conn = factory(self._dispatch, self._on_cleared)
            except Exception as exc:  # noqa: BLE001 - Xlib raises many shapes
                log.warning("cannot open an X connection to own the clipboard: %s", exc)
                self.last_error = f"no X connection: {exc}"
                return None
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
        self._data = None

    # -- the ClipboardWriter contract --------------------------------------

    def write(self, text: str) -> bool:
        """Replace the clipboard contents. True once we actually own it.

        True means the same thing it meant with `wl-copy`: the value is committed
        and will be served on request. It does not mean anybody has asked for it
        yet, which is equally true of a `wl-copy` that has forked and returned.
        """
        self.last_error = None
        conn = self._connection()
        if conn is None:
            return False
        payload = text.encode("utf-8", "surrogatepass")
        try:
            timestamp = conn.server_time()
            # Re-assert ownership even when we already hold it. Quietly swapping
            # the bytes underneath would leave every other client -- and our own
            # XFIXES watcher -- with no reason to believe anything changed.
            if not conn.take_ownership(timestamp):
                self.last_error = "another client refused to give up the selection"
                log.error("could not take ownership of the clipboard")
                return False
        except Exception as exc:  # noqa: BLE001 - Xlib raises many shapes
            self.last_error = str(exc)
            log.error("clipboard write failed: %s", exc)
            self.close()
            return False
        self._data = payload
        self._timestamp = timestamp
        # Length only -- never the content.
        log.debug("owning the clipboard with %d chars", len(text))
        return True

    def clear(self) -> bool:
        conn = self._conn
        self._data = None
        if conn is None:
            return True
        try:
            conn.release_ownership(self._timestamp)
        except Exception as exc:  # noqa: BLE001
            log.error("clipboard clear failed: %s", exc)
            return False
        return True

    # -- what we are holding -----------------------------------------------

    def owns_clipboard(self) -> bool:
        """Whether the clipboard's current value is one we are serving.

        Load-bearing, not informational. A conversion request is answered from
        the main loop, so anything that *blocks* the main loop waiting for an
        answer waits for itself: the read times out, and on a desktop where the
        Wayland side is bridged through us, `wl-paste` then times out too. Every
        caller that is about to read the clipboard has to ask this first and use
        `current_text` instead.
        """
        conn = self._conn
        if conn is None or self._data is None:
            return False
        try:
            return conn.owns_selection()
        except Exception:  # noqa: BLE001 - a dead connection owns nothing
            return False

    def current_text(self) -> str | None:
        """The value we are serving, without going through the X server for it."""
        if self._data is None or not self.owns_clipboard():
            return None
        return self._data.decode("utf-8", "surrogatepass")

    # -- serving -----------------------------------------------------------

    def _dispatch(self, req: SelectionRequest) -> None:
        """Answer one conversion request. Called from the main loop."""
        prop = req.property or req.target  # obsolete clients send no property
        data = self._data
        conn = self._conn
        if conn is None:
            return
        if data is None:
            # We own the selection but hold nothing -- refuse rather than serve
            # an empty string, which a requestor would paste as a blank.
            self.refused += 1
            conn.answer(req, None)
            return
        try:
            if req.target == "TARGETS":
                conn.put_atoms(req, prop, ["TARGETS", "TIMESTAMP", *TEXT_TARGETS])
            elif req.target == "TIMESTAMP":
                conn.put_integer(req, prop, self._timestamp)
            elif req.target in TEXT_TARGETS:
                conn.put_bytes(req, prop, req.target, data)
            else:
                # MULTIPLE, image flavours, application-private targets. Refusing
                # is the defined way to say "not from us".
                self.refused += 1
                conn.answer(req, None)
                return
        except Exception as exc:  # noqa: BLE001 - a bad requestor must not kill us
            log.warning("failed to serve clipboard target %s: %s", req.target, exc)
            self.refused += 1
            conn.answer(req, None)
            return
        self.served += 1
        conn.answer(req, prop)

    def _on_cleared(self) -> None:
        """Another client took the clipboard; stop claiming to hold anything."""
        log.debug("lost clipboard ownership")
        self._data = None
