"""The X11 clipboard reader, exercised against a fake X server.

Same arrangement as tests/test_windows.py and tests/test_darwin.py: the parts
that need a real server sit behind a protocol, and everything that carries the
bugs -- the INCR loop, meta-target filtering, the preference order and the
fallback decision -- is tested here. The real path is verified by hand on a
GNOME desktop, because nothing in CI runs a compositor.

The fake mirrors the awkward parts of ICCCM selection transfer: an owner may
refuse a target outright, a large value arrives as an INCR header followed by
chunks that only appear once the requestor deletes the property, and a
zero-length chunk is what ends the transfer rather than any count.

It also mirrors the *ordering*, which is the part that actually broke: an owner
writes the property before it sends SelectionNotify, and since the mailbox window
must carry PropertyChangeMask for INCR, that write is delivered as a
PropertyNotify ahead of the reply. An earlier version of this fake emitted only
the reply, so the suite passed against a reader that read every successful
conversion on a real X server as a refusal.
"""

from __future__ import annotations

import pytest

from safepaste.clipboard.monitor import FallbackReader, _has_rich_flavours
from safepaste.clipboard.x11 import (
    META_TARGETS,
    PropertyValue,
    SelectionEvent,
    X11SelectionReader,
    has_rich_targets,
)

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore\n"


class FakeXConnection:
    """An X server that owns one selection.

    `targets` maps a target name to the bytes it serves. A target absent from
    the map is refused, exactly as a real owner refuses one it cannot supply.
    """

    def __init__(self, targets=None, chunk_size=None, atom_base=1000):
        self.targets = dict(targets or {})
        self.chunk_size = chunk_size          # None => single-property transfer
        self.closed = False
        self.convert_calls = []
        self.deletes = 0
        self._atoms = {}
        self._atom_base = atom_base
        # What the requestor would read right now, and what is still queued.
        self._property = None
        self._pending = []
        self._events = []
        self._fail_with = None

    # -- helpers used by tests --------------------------------------------
    def fail_next(self, exc):
        self._fail_with = exc

    def _atom(self, name):
        if name not in self._atoms:
            self._atoms[name] = self._atom_base + len(self._atoms)
        return self._atoms[name]

    # -- the XConnection protocol -----------------------------------------
    def convert_selection(self, target):
        if self._fail_with is not None:
            exc, self._fail_with = self._fail_with, None
            raise exc
        self.convert_calls.append(target)
        if target == "TARGETS":
            names = list(self.targets) + ["TARGETS", "TIMESTAMP"]
            self._property = PropertyValue("", [self._atom(n) for n in names])
            self._announce(granted=True)
            return
        if target not in self.targets:
            self._property = None
            self._events.append(SelectionEvent("selection", granted=False))
            return
        data = self.targets[target]
        if self.chunk_size is None:
            self._property = PropertyValue("", data)
        else:
            self._property = PropertyValue("INCR", [len(data)])
            self._pending = [
                data[i : i + self.chunk_size]
                for i in range(0, len(data), self.chunk_size)
            ] + [b""]
        self._announce(granted=True)

    def _announce(self, granted):
        """Write-then-reply, in that order, exactly as a real owner does."""
        self._events.append(SelectionEvent("property", granted=True))
        self._events.append(SelectionEvent("selection", granted=granted))

    def read_property(self):
        return self._property

    def delete_property(self):
        self.deletes += 1
        self._property = None
        # Deleting the property is the signal that unblocks the next chunk.
        if self._pending:
            self._property = PropertyValue("", self._pending.pop(0))
            self._events.append(SelectionEvent("property", granted=True))

    def next_event(self, timeout):
        return self._events.pop(0) if self._events else None

    def atom_names(self, atoms):
        by_id = {v: k for k, v in self._atoms.items()}
        return [by_id[a] for a in atoms if a in by_id]

    def close(self):
        self.closed = True


def reader_over(conn, **kw):
    return X11SelectionReader(connect=lambda: conn, **kw)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_reads_plain_text_in_one_property():
    conn = FakeXConnection({"UTF8_STRING": PAYLOAD.encode()})
    event = reader_over(conn).read_text()
    assert event is not None
    assert event.text == PAYLOAD
    assert event.flavour == "UTF8_STRING"
    assert event.has_rich_flavours is False


def test_prefers_the_best_text_target_available():
    conn = FakeXConnection(
        {
            "STRING": b"worst",
            "UTF8_STRING": b"better",
            "text/plain;charset=utf-8": b"best",
        }
    )
    event = reader_over(conn).read_text()
    assert event is not None and event.text == "best"
    assert event.flavour == "text/plain;charset=utf-8"


def test_large_value_is_reassembled_through_incr():
    body = (PAYLOAD * 400).encode()
    conn = FakeXConnection({"UTF8_STRING": body}, chunk_size=997)
    event = reader_over(conn).read_text()
    assert event is not None
    assert event.text.encode() == body, "INCR must round-trip byte-exact"


def test_incr_that_stalls_is_a_failure_not_an_empty_clipboard():
    conn = FakeXConnection({"UTF8_STRING": b"x" * 5000}, chunk_size=1000)
    # Drop the queued chunks: the owner has gone away mid-transfer.
    original = conn.delete_property

    def stalling_delete():
        conn.deletes += 1
        conn._property = None
        conn._pending = []

    conn.delete_property = stalling_delete
    reader = reader_over(conn)
    assert reader.read_text() is None
    assert reader.last_error is not None


def test_oversized_clipboard_is_refused_rather_than_truncated():
    conn = FakeXConnection({"UTF8_STRING": b"y" * 9000}, chunk_size=1000)
    reader = reader_over(conn, max_bytes=4096)
    # Refusing is the point: the guard writes the redacted text back, so a
    # truncated read would overwrite the clipboard with a prefix of itself.
    assert reader.read_text() is None


def test_non_text_clipboard_reads_as_no_text():
    conn = FakeXConnection({"image/png": b"\x89PNG"})
    reader = reader_over(conn)
    assert reader.read_text() is None
    assert reader.last_error is None, "an image is an answer, not a failure"


def test_empty_clipboard_is_not_reported_as_a_failure():
    conn = FakeXConnection({})
    reader = reader_over(conn)
    assert reader.read_text() is None
    assert reader.last_error is None


# ---------------------------------------------------------------------------
# Meta-targets
# ---------------------------------------------------------------------------


def test_meta_targets_are_not_reported_as_flavours():
    conn = FakeXConnection({"UTF8_STRING": b"hi"})
    types = reader_over(conn).list_types()
    assert "UTF8_STRING" in types
    assert not (set(types) & META_TARGETS), f"meta-targets leaked into {types}"


def test_plain_text_clipboard_does_not_claim_lost_formatting():
    # The bug this replaces: TARGETS in the list made every plain-text clipboard
    # look as though a redaction would destroy a richer representation.
    conn = FakeXConnection({"UTF8_STRING": b"hi"})
    event = reader_over(conn).read_text()
    assert event is not None and event.has_rich_flavours is False


def test_genuinely_rich_clipboard_still_reports_lost_formatting():
    conn = FakeXConnection({"UTF8_STRING": b"hi", "text/html": b"<b>hi</b>"})
    event = reader_over(conn).read_text()
    assert event is not None and event.has_rich_flavours is True


def test_a_property_notify_before_the_reply_is_not_read_as_a_refusal():
    """The bug that shipped past the first version of this fake.

    A real owner sets the property and only then sends SelectionNotify, so the
    PropertyNotify for its write arrives first. Taking the first event as the
    reply turned every successful read on a real X server into a refusal.
    """
    conn = FakeXConnection({"UTF8_STRING": PAYLOAD.encode()})
    conn.convert_selection("UTF8_STRING")
    assert [e.kind for e in conn._events][:2] == ["property", "selection"], (
        "the fake must emit the property write before the reply"
    )
    conn._events.clear()
    event = reader_over(conn).read_text()
    assert event is not None and event.text == PAYLOAD


def test_a_flood_of_property_events_cannot_hold_the_read_open():
    conn = FakeXConnection({"UTF8_STRING": b"hi"})
    real_convert = conn.convert_selection

    def noisy(target):
        real_convert(target)
        # An owner that keeps touching the property and never replies.
        conn._events[:] = [SelectionEvent("property", granted=True)] * 500

    conn.convert_selection = noisy
    reader = reader_over(conn, timeout=0.2)
    assert reader.read_text() is None
    assert reader.last_error is not None


@pytest.mark.parametrize("meta", sorted(META_TARGETS))
def test_has_rich_targets_ignores_each_meta_target(meta):
    assert has_rich_targets(["UTF8_STRING", meta]) is False


def test_wl_paste_path_also_ignores_meta_targets():
    # wl-paste --list-types reports TARGETS too, so the fallback needs the
    # same filtering as the X11 path.
    assert _has_rich_flavours(["text/plain;charset=utf-8", "UTF8_STRING", "TARGETS"]) is False
    assert _has_rich_flavours(["text/plain;charset=utf-8", "text/html"]) is True


# ---------------------------------------------------------------------------
# Connection handling and the fallback
# ---------------------------------------------------------------------------


def test_an_x_error_drops_the_connection_so_the_next_read_reconnects():
    conns = []

    def connect():
        conn = FakeXConnection({"UTF8_STRING": b"after"})
        conns.append(conn)
        return conn

    reader = X11SelectionReader(connect=connect)
    conns_first = connect()
    conns_first.fail_next(OSError("XWayland went away"))
    reader._conn = conns_first
    assert reader.read_text() is None
    assert reader.last_error is not None
    assert conns_first.closed is True
    # Second attempt gets a fresh connection and succeeds.
    event = reader.read_text()
    assert event is not None and event.text == "after"


class _StubPrimary:
    def __init__(self, event, error):
        self._event, self.last_error = event, error
        self.calls = 0

    def list_types(self):
        self.calls += 1
        return []

    def read_text(self):
        self.calls += 1
        return self._event

    def close(self):
        pass


class _StubFallback:
    def __init__(self, event):
        self._event = event
        self.calls = 0

    def list_types(self):
        self.calls += 1
        return ["UTF8_STRING"]

    def read_text(self):
        self.calls += 1
        return self._event


def test_a_failed_x11_read_falls_back_rather_than_missing_the_scan():
    from safepaste.backend import ClipboardEvent

    rescued = ClipboardEvent.of(PAYLOAD)
    primary = _StubPrimary(None, error="no SelectionNotify within 2.0s")
    fallback = _StubFallback(rescued)
    assert FallbackReader(primary, fallback).read_text() is rescued
    assert fallback.calls == 1


def test_an_empty_clipboard_does_not_wake_the_flickering_fallback():
    primary = _StubPrimary(None, error=None)
    fallback = _StubFallback(None)
    assert FallbackReader(primary, fallback).read_text() is None
    assert fallback.calls == 0, "wl-paste must not run when X11 gave a real answer"


def test_a_successful_x11_read_does_not_touch_the_fallback():
    from safepaste.backend import ClipboardEvent

    event = ClipboardEvent.of(PAYLOAD)
    primary = _StubPrimary(event, error=None)
    fallback = _StubFallback(None)
    assert FallbackReader(primary, fallback).read_text() is event
    assert fallback.calls == 0


def test_the_reader_satisfies_the_backend_contract():
    from safepaste.backend import ClipboardReader

    assert isinstance(X11SelectionReader(connect=lambda: FakeXConnection()), ClipboardReader)
    assert isinstance(FallbackReader(), ClipboardReader)
