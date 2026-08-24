"""The Xlib half of `X11SelectionOwner`, kept apart so the logic stays testable.

Nothing here decides anything. It opens a connection, holds the unmapped window
that gives the selection an address, turns X events into the small shapes
`X11SelectionOwner` understands, and pumps itself from the GLib main loop.

The one piece of real judgement is the timestamp. ICCCM requires SetSelectionOwner
to carry a *server* time and explicitly forbids CurrentTime, because two clients
racing for the selection are resolved by comparing timestamps and CurrentTime
carries no information. There is no call that simply asks for the time, so the
conventional trick is used: append zero bytes to a property on our own window and
read the time off the PropertyNotify that comes back.
"""

from __future__ import annotations

import logging
import select as _select
import time as _time

log = logging.getLogger(__name__)

# Leave the request header room inside max_request_length.
_CHUNK_HEADROOM = 1024
_TIME_TIMEOUT = 2.0


class _Request:
    """One SelectionRequest, in the shape X11SelectionOwner expects."""

    __slots__ = ("requestor", "target", "property", "time", "selection")

    def __init__(self, requestor, target, prop, when, selection):
        self.requestor = requestor
        self.target = target
        self.property = prop
        self.time = when
        self.selection = selection


class XlibOwnerConnection:
    def __init__(self, on_request, on_cleared=None, attach=True) -> None:
        from Xlib import X, Xatom, display as xdisplay

        self._X = X
        self._Xatom = Xatom
        self._on_request = on_request
        self._on_cleared = on_cleared
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
            event_mask=X.PropertyChangeMask,
        )
        # Deliberately never mapped: a selection owner needs an address, not a
        # window on screen. This is the whole reason writing stopped flickering.
        self._clipboard = self._display.get_atom("CLIPBOARD")
        self._time_prop = self._display.get_atom("SAFEPASTE_TIMESTAMP")
        self._watch_id = None
        if attach:
            self._attach()

    # -- main-loop integration --------------------------------------------

    def _attach(self) -> None:
        """Serve requests from the GLib loop the daemon is already running.

        Imported here rather than at module scope: the CLI must stay importable
        on a headless box with no GTK stack, and it reaches this file only by
        accident of packaging.
        """
        from gi.repository import GLib

        self._watch_id = GLib.unix_fd_add_full(
            GLib.PRIORITY_DEFAULT,
            self._display.fileno(),
            GLib.IOCondition.IN,
            self._on_fd_ready,
            None,
        )

    def _on_fd_ready(self, fd, condition, _data) -> bool:
        try:
            self.pump(blocking_first=True)
        except Exception as exc:  # noqa: BLE001 - never let the loop die
            log.exception("clipboard owner error: %s", exc)
        return True

    def pump(self, blocking_first: bool = False) -> None:
        """Drain and dispatch whatever the server has for us.

        The forced first `next_event()` mirrors XFixesMonitor._drain, and for the
        same reason: python-xlib's pending_events() reports only what it has
        already decoded and does not poll the socket.
        """
        if blocking_first:
            self._handle(self._display.next_event())
        while self._display.pending_events():
            self._handle(self._display.next_event())

    def _handle(self, event) -> None:
        if event.type == self._X.SelectionRequest:
            prop = event.property
            self._on_request(
                _Request(
                    requestor=event.requestor,
                    target=self._display.get_atom_name(event.target),
                    prop=self._display.get_atom_name(prop) if prop else None,
                    when=event.time,
                    selection=event.selection,
                )
            )
        elif event.type == self._X.SelectionClear and self._on_cleared is not None:
            self._on_cleared()

    # -- ownership ---------------------------------------------------------

    def server_time(self) -> int:
        self._window.change_property(
            self._time_prop,
            self._Xatom.STRING,
            8,
            b"",
            mode=self._X.PropModeAppend,
        )
        self._display.flush()
        deadline = _time.monotonic() + _TIME_TIMEOUT
        while True:
            while self._display.pending_events():
                event = self._display.next_event()
                if (
                    event.type == self._X.PropertyNotify
                    and event.atom == self._time_prop
                ):
                    return event.time
                # A conversion request can arrive while we are asking the time.
                # Dropping it would leave a requestor waiting forever.
                self._handle(event)
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError("the X server did not answer with a timestamp")
            readable, _, _ = _select.select(
                [self._display.fileno()], [], [], remaining
            )
            if not readable:
                continue
            event = self._display.next_event()
            if event.type == self._X.PropertyNotify and event.atom == self._time_prop:
                return event.time
            self._handle(event)

    def take_ownership(self, timestamp: int) -> bool:
        self._window.set_selection_owner(self._clipboard, timestamp)
        self._display.flush()
        # Asking rather than assuming: SetSelectionOwner has no reply, and a
        # write that silently did not stick would leave the guard believing the
        # secret had been replaced when it had not.
        return self.owns_selection()

    def release_ownership(self, timestamp: int) -> None:
        self._window.set_selection_owner(self._X.NONE, timestamp)
        self._display.flush()

    def owns_selection(self) -> bool:
        return self._display.get_selection_owner(self._clipboard) == self._window

    # -- writing properties on the requestor's window ----------------------

    def max_chunk(self) -> int:
        return self._display.display.info.max_request_length * 4 - _CHUNK_HEADROOM

    def put_atoms(self, req, prop: str, atoms: list[str]) -> None:
        req.requestor.change_property(
            self._display.get_atom(prop),
            self._Xatom.ATOM,
            32,
            [self._display.get_atom(a) for a in atoms],
        )

    def put_integer(self, req, prop: str, value: int) -> None:
        req.requestor.change_property(
            self._display.get_atom(prop), self._Xatom.INTEGER, 32, [value]
        )

    def put_bytes(self, req, prop: str, type_name: str, data: bytes) -> None:
        """Write the value, in as many appends as it takes.

        A ChangeProperty *request* is capped by max_request_length; the property
        it builds is not. The requestor is only told to look once the last chunk
        has landed, so it never observes a half-written value.
        """
        prop_atom = self._display.get_atom(prop)
        type_atom = self._display.get_atom(type_name)
        chunk = self.max_chunk()
        if len(data) <= chunk:
            req.requestor.change_property(prop_atom, type_atom, 8, data)
            return
        req.requestor.change_property(
            prop_atom, type_atom, 8, data[:chunk], mode=self._X.PropModeReplace
        )
        offset = chunk
        while offset < len(data):
            req.requestor.change_property(
                prop_atom,
                type_atom,
                8,
                data[offset : offset + chunk],
                mode=self._X.PropModeAppend,
            )
            offset += chunk

    def answer(self, req, prop: str | None) -> None:
        from Xlib.protocol import event as xevent

        self._display.send_event(
            req.requestor,
            xevent.SelectionNotify(
                time=req.time,
                requestor=req.requestor,
                selection=req.selection,
                target=self._display.get_atom(req.target),
                property=self._display.get_atom(prop) if prop else self._X.NONE,
            ),
            event_mask=0,
        )
        self._display.flush()

    def close(self) -> None:
        if self._watch_id is not None:
            try:
                from gi.repository import GLib

                GLib.source_remove(self._watch_id)
            except Exception:  # noqa: BLE001
                pass
            self._watch_id = None
        try:
            self._display.close()
        except Exception:  # noqa: BLE001 - closing a dead connection
            pass
