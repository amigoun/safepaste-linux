"""Reading the clipboard without putting a window on the screen.

`wl-paste` cannot read the clipboard on Mutter unless it holds keyboard focus,
and Mutter offers no clipboard-management protocol that would exempt it —
measured on GNOME 46, the compositor advertises neither
`zwlr_data_control_manager_v1` nor `ext_data_control_manager_v1`. wl-clipboard's
answer is to *become* focusable. Every single read does this:

    -> wl_compositor.create_surface
    -> xdg_toplevel.set_title("wl-clipboard")
    -> wl_shm_pool.create_buffer(1, 1, 4)      # a real 1x1 pixel buffer
    -> wl_surface.attach + damage
    -> gtk_surface1.present(0)                 # "shell, focus me"
    -> wl_surface.commit                       # ... and it is now mapped

GNOME maps, focuses and unmaps that window for every read, and the monitor reads
twice per clipboard change (types, then content). So every copy flashed two
windows and bounced focus off whatever the user was working in.

Two consequences, and only the first one is cosmetic:

  * The flicker, which is what anybody actually notices.
  * A silent protection gap. That focus grab is not guaranteed — one desktop's
    journal held 65 `wl-paste --list-types` timeouts over eleven days. A timeout
    yields no types, `read_text` reads that as "the clipboard holds no text",
    and **that copy is never scanned**. A secret copied in that window goes
    unguarded, with nothing in the UI to say so.

X11 gates none of this. A selection read needs a window only as a mailbox for
SelectionNotify, and an *unmapped* window is a perfectly good mailbox: nothing
is drawn and nothing takes focus. Mutter's XWayland bridge mirrors the clipboard
in both directions — `scripts/probe-clipboard.py` asserts exactly that, and it is
already what makes XFIXES monitoring work — so this reads the bytes back over the
bridge we are already listening to, instead of going out to Wayland for them.

Measured on GNOME 46 against the path it replaces: 7.6-16.1 ms for a full read
including TARGETS, versus ~40 ms when wl-paste works and 2000 ms when it does
not; 6/6 reads correct when issued immediately on the XFIXES event with no settle
delay; and a 1 MiB clipboard round-tripped byte-exact through INCR.

Two traps worth keeping written down:

  * **This must not share the monitor's X connection.** `XFixesMonitor._drain`
    consumes everything on its connection with `next_event()`; a SelectionNotify
    arriving there would be swallowed before the reader ever saw it, and the read
    would time out instead. Hence a second connection, deliberately.
  * **X11 TARGETS is not a list of flavours.** It also advertises the ICCCM
    meta-targets (`TARGETS`, `TIMESTAMP`, `MULTIPLE`, ...), which describe the
    protocol rather than the content. Anything that treats an unrecognised name
    as "a richer representation we would destroy" — `_has_rich_flavours` does —
    then warns about dropping formatting on a clipboard holding nothing but
    plain text. `wl-paste --list-types` has the same wart: it lists `TARGETS`
    too, which is why that warning fires today on every plain-text redaction.
"""

from __future__ import annotations

import logging
import select
import time
from dataclasses import dataclass
from typing import Protocol

from ..backend import ClipboardEvent

log = logging.getLogger(__name__)

# Per selection conversion, matching the subprocess reader this replaces. A read
# runs on the GLib main loop, so this is also the longest the daemon can stall.
READ_TIMEOUT = 2.0

# Refuse rather than truncate above this. Truncating would be actively unsafe:
# the guard writes the redacted text back, so a short read would replace the
# user's clipboard with a prefix of itself. Far above any real clipboard, and far
# above the 1 MiB the detector scans.
MAX_SELECTION_BYTES = 64 * 1024 * 1024

# ICCCM meta-targets. These describe the protocol, not the content, and must not
# be mistaken for representations that a plain-text replacement would discard.
META_TARGETS = frozenset(
    {
        "TARGETS",
        "TIMESTAMP",
        "MULTIPLE",
        "SAVE_TARGETS",
        "DELETE",
        "INSERT_SELECTION",
        "INSERT_PROPERTY",
    }
)


# ---------------------------------------------------------------------------
# The seam over raw Xlib
# ---------------------------------------------------------------------------


@dataclass
class PropertyValue:
    """A property read back off our mailbox window."""

    type_name: str
    # bytes for 8-bit properties (text), a list of atom ids for 32-bit ones
    # (TARGETS). Kept untyped-ish on purpose: X says which via the format.
    value: bytes | list[int]


@dataclass
class SelectionEvent:
    """Either "the owner answered" or "a chunk landed"."""

    kind: str  # "selection" | "property"
    granted: bool = False


class XConnection(Protocol):
    """Everything this module needs from an X server.

    A Protocol so the INCR loop, the target filtering and the preference order
    can be tested without an X server, in the same spirit as the fakes behind the
    Windows and macOS backends.
    """

    def convert_selection(self, target: str) -> None: ...
    def read_property(self) -> PropertyValue | None: ...
    def delete_property(self) -> None: ...
    def next_event(self, timeout: float) -> SelectionEvent | None: ...
    def atom_names(self, atoms: list[int]) -> list[str]: ...
    def close(self) -> None: ...


class XlibConnection:
    """The real thing: one connection, one window, and the window is never mapped."""

    def __init__(self, selection: str = "CLIPBOARD") -> None:
        from Xlib import X, display as xdisplay

        self._X = X
        self._display = xdisplay.Display()
        self._window = self._display.screen().root.create_window(
            0,
            0,
            1,
            1,
            0,
            X.CopyFromParent,
            X.InputOutput,
            X.CopyFromParent,
            # Required for INCR: the owner signals each chunk with a PropertyNotify.
            event_mask=X.PropertyChangeMask,
        )
        # Deliberately no map_window(). An unmapped window still receives
        # SelectionNotify and still holds properties, and it is the entire reason
        # this path does not flicker.
        self._selection = self._display.get_atom(selection)
        self._property = self._display.get_atom("SAFEPASTE_SELECTION")
        self._incr = self._display.get_atom("INCR")

    def convert_selection(self, target: str) -> None:
        self._window.convert_selection(
            self._selection,
            self._display.get_atom(target),
            self._property,
            self._X.CurrentTime,
        )
        self._display.flush()

    def read_property(self) -> PropertyValue | None:
        prop = self._window.get_full_property(self._property, self._X.AnyPropertyType)
        if prop is None:
            return None
        value = prop.value
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value)
        else:
            value = list(value)
        return PropertyValue(
            type_name="INCR" if prop.property_type == self._incr else "",
            value=value,
        )

    def delete_property(self) -> None:
        self._window.delete_property(self._property)
        self._display.flush()

    def next_event(self, timeout: float) -> SelectionEvent | None:
        """Wait for the next event we care about, or None once `timeout` is up."""
        deadline = time.monotonic() + timeout
        while True:
            while self._display.pending_events():
                translated = self._translate(self._display.next_event())
                if translated is not None:
                    return translated
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            # pending_events() decodes only what has already been read; it does
            # not poll the socket. Wait on the fd, exactly as XFixesMonitor does.
            readable, _, _ = select.select([self._display.fileno()], [], [], remaining)
            if not readable:
                return None
            translated = self._translate(self._display.next_event())
            if translated is not None:
                return translated

    def _translate(self, event: object) -> SelectionEvent | None:
        etype = getattr(event, "type", None)
        if etype == self._X.SelectionNotify:
            return SelectionEvent(
                kind="selection",
                granted=getattr(event, "property", self._X.NONE) != self._X.NONE,
            )
        if (
            etype == self._X.PropertyNotify
            and getattr(event, "atom", None) == self._property
            and getattr(event, "state", None) == self._X.PropertyNewValue
        ):
            return SelectionEvent(kind="property", granted=True)
        return None

    def atom_names(self, atoms: list[int]) -> list[str]:
        names = []
        for atom in atoms:
            if not atom:
                continue
            try:
                names.append(self._display.get_atom_name(atom))
            except Exception:  # noqa: BLE001 - a stale atom is not worth dying for
                continue
        return names

    def close(self) -> None:
        try:
            self._display.close()
        except Exception:  # noqa: BLE001 - closing a dead connection
            pass


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


# Text flavours we are willing to scan, best first. X11 selections name these
# with a mix of MIME types and ICCCM atoms, and both appear in the wild.
TEXT_TARGET_PREFERENCE = (
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
    "TEXT",
)


def has_rich_targets(targets: list[str]) -> bool:
    """Whether a plain-text replacement would discard something.

    Drops the ICCCM meta-targets itself rather than trusting the caller to have
    done it. `list_types` already filters them, but this answer becomes a claim
    in the dialog about what a redaction destroyed, and there is more than one
    path into it -- the wl-paste fallback lists `TARGETS` too. One filter, in the
    one place that decides.
    """
    return any(
        t not in TEXT_TARGET_PREFERENCE
        and t not in META_TARGETS
        and not t.startswith("text/plain")
        for t in targets
    )


class X11SelectionReader:
    """Reads the CLIPBOARD selection over X11. Nothing is ever shown on screen."""

    def __init__(
        self,
        connect=None,
        timeout: float = READ_TIMEOUT,
        max_bytes: int = MAX_SELECTION_BYTES,
    ) -> None:
        self._connect = connect or XlibConnection
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._conn: XConnection | None = None
        # Why the last read produced nothing, or None if it produced nothing for
        # a legitimate reason (an empty clipboard, or one holding no text).
        # A caller uses this to decide whether a fallback is worth trying: a
        # failed read must never be mistaken for a clean clipboard, because that
        # is precisely the bug this module exists to remove.
        self.last_error: str | None = None

    # -- connection --------------------------------------------------------

    def _connection(self) -> XConnection | None:
        if self._conn is None:
            try:
                self._conn = self._connect()
            except Exception as exc:  # noqa: BLE001 - Xlib raises many shapes
                log.warning("cannot open an X connection for clipboard reads: %s", exc)
                self.last_error = f"no X connection: {exc}"
                return None
        return self._conn

    def _drop_connection(self) -> None:
        """Forget a connection that erred, so the next read reconnects.

        XWayland can restart underneath a long-lived daemon. The subprocess
        reader this replaces got a fresh connection every time and so never had
        to think about it; a resident connection does.
        """
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def close(self) -> None:
        self._drop_connection()

    # -- one conversion ----------------------------------------------------

    def _convert(self, target: str) -> PropertyValue | None:
        conn = self._connection()
        if conn is None:
            return None
        try:
            return self._convert_on(conn, target)
        except Exception as exc:  # noqa: BLE001 - Xlib raises many shapes
            log.warning("X11 clipboard read failed (%s): %s", target, exc)
            self.last_error = f"{target}: {exc}"
            self._drop_connection()
            return None

    def _await(self, conn: XConnection, kind: str, deadline: float):
        """Wait for the next event of `kind`, discarding the others.

        Both kinds turn up on this connection and the order is not ours to
        choose. An owner answering a conversion *writes the property first and
        sends SelectionNotify second*, and because the mailbox window carries
        PropertyChangeMask to make INCR work, that write arrives here as a
        PropertyNotify ahead of the reply. Treating the first event as the reply
        read every successful conversion as a refusal.

        The deadline spans the whole conversion rather than resetting per event,
        so a peer that keeps touching the property cannot hold the main loop
        open indefinitely.
        """
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            event = conn.next_event(remaining)
            if event is None:
                return None
            if event.kind == kind:
                return event

    def _convert_on(self, conn: XConnection, target: str) -> PropertyValue | None:
        conn.delete_property()
        conn.convert_selection(target)
        deadline = time.monotonic() + self._timeout

        event = self._await(conn, "selection", deadline)
        if event is None:
            log.debug("no SelectionNotify for %s within %.1fs", target, self._timeout)
            self.last_error = f"{target}: no SelectionNotify within {self._timeout}s"
            return None
        if not event.granted:
            # A refusal is normal and not an error: it is how an owner says it
            # cannot supply this target.
            log.debug("selection owner refused %s", target)
            return None

        prop = conn.read_property()
        if prop is None:
            return None
        if prop.type_name != "INCR":
            conn.delete_property()
            return prop
        return self._read_incr(conn, target, deadline)

    def _read_incr(
        self, conn: XConnection, target: str, deadline: float
    ) -> PropertyValue | None:
        """Collect a transfer too large for one property.

        Mutter uses this above roughly 256 KiB, so it is the normal path for the
        large pastes this program exists to protect, not an exotic corner.
        Deleting the property is what tells the owner to send the next chunk; a
        zero-length chunk ends the transfer.
        """
        chunks = bytearray()
        conn.delete_property()
        while True:
            # A large transfer legitimately outlives one conversion's budget, so
            # each chunk gets its own; the stall check below is what bounds it.
            deadline = time.monotonic() + self._timeout
            event = self._await(conn, "property", deadline)
            if event is None:
                log.warning(
                    "INCR transfer stalled after %d bytes of %s", len(chunks), target
                )
                self.last_error = f"{target}: INCR stalled at {len(chunks)} bytes"
                return None
            piece = conn.read_property()
            conn.delete_property()
            if piece is None or not piece.value:
                break
            data = piece.value
            if not isinstance(data, bytes):
                data = bytes(bytearray(data))
            if len(chunks) + len(data) > self._max_bytes:
                # Refuse, never truncate: the guard writes the redacted text
                # back, so a short read would overwrite the clipboard with a
                # prefix of itself.
                log.warning(
                    "clipboard exceeds %d bytes; not reading it", self._max_bytes
                )
                return None
            chunks += data
        return PropertyValue(type_name="", value=bytes(chunks))

    # -- the ClipboardReader contract --------------------------------------

    def list_types(self) -> list[str]:
        """Content targets on the clipboard, meta-targets removed."""
        self.last_error = None
        prop = self._convert("TARGETS")
        if prop is None or isinstance(prop.value, bytes):
            return []
        conn = self._conn
        if conn is None:
            return []
        names = conn.atom_names(list(prop.value))
        return [n for n in names if n not in META_TARGETS]

    def read_text(self) -> ClipboardEvent | None:
        """The clipboard as text, or None if it holds no text at all.

        On None, `last_error` says whether that was an answer or a failure.
        """
        targets = self.list_types()
        if not targets:
            return None
        target = next((t for t in TEXT_TARGET_PREFERENCE if t in targets), None)
        if target is None:
            # An image, a file list, or an application-private flavour. Nothing
            # for a secret scanner to do.
            log.debug("clipboard holds no text target (%d targets)", len(targets))
            return None
        prop = self._convert(target)
        if prop is None:
            return None
        data = prop.value
        if not isinstance(data, bytes):
            data = bytes(bytearray(data))
        text = data.decode("utf-8", "replace")
        if not text:
            return None
        return ClipboardEvent.of(
            text,
            flavour=target,
            has_rich_flavours=has_rich_targets(targets),
            flavours=tuple(targets),
        )
