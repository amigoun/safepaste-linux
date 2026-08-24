"""The X11 selection owner, exercised against a fake X server.

Same arrangement as tests/test_clipboard_x11.py. What is worth testing here is
not "does Xlib work" but the parts that decide something: which targets are
answered and which refused, that a value larger than one request is written in
several appends and announced only once it is whole, that ownership is verified
rather than assumed, and that losing the selection stops us claiming to hold it.

The fake models the ICCCM handshake the way a real requestor sees it: a property
appears on the requestor's window, and a reply names that property, or names
nothing at all to mean "refused".
"""

from __future__ import annotations

import pytest

from safepaste.clipboard.writer import FallbackWriter
from safepaste.clipboard.x11write import TEXT_TARGETS, X11SelectionOwner

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
REDACTED = "GITHUB_TOKEN=[REDACTED]\nand more text after it\n"


class FakeRequestor:
    def __init__(self, name="requestor"):
        self.name = name
        self.properties = {}   # prop -> (type_name, format, bytes-or-list)
        self.writes = 0        # how many ChangeProperty requests it took


class FakeOwnerConnection:
    def __init__(self, on_request, on_cleared=None, *, chunk=64, can_own=True):
        self.on_request = on_request
        self.on_cleared = on_cleared
        self._chunk = chunk
        self.can_own = can_own
        self.owns = False
        self.closed = False
        self.times = 0
        self.replies = []          # (requestor, prop-or-None)
        self.released = False
        self.fail_time_with = None

    # -- ownership
    def server_time(self):
        if self.fail_time_with is not None:
            exc, self.fail_time_with = self.fail_time_with, None
            raise exc
        self.times += 1
        return 1000 + self.times

    def take_ownership(self, timestamp):
        self.owns = bool(self.can_own)
        self.timestamp = timestamp
        return self.owns

    def release_ownership(self, timestamp):
        self.owns = False
        self.released = True

    def owns_selection(self):
        return self.owns

    def max_chunk(self):
        return self._chunk

    # -- writing on the requestor
    def put_atoms(self, req, prop, atoms):
        req.requestor.properties[prop] = ("ATOM", 32, list(atoms))
        req.requestor.writes += 1

    def put_integer(self, req, prop, value):
        req.requestor.properties[prop] = ("INTEGER", 32, [value])
        req.requestor.writes += 1

    def put_bytes(self, req, prop, type_name, data):
        chunk = self._chunk
        req.requestor.properties[prop] = (type_name, 8, b"")
        offset = 0
        while offset < len(data) or offset == 0:
            piece = data[offset : offset + chunk]
            t, f, existing = req.requestor.properties[prop]
            req.requestor.properties[prop] = (t, f, existing + piece)
            req.requestor.writes += 1
            offset += chunk
            if offset >= len(data):
                break

    def answer(self, req, prop):
        self.replies.append((req.requestor, prop))

    def close(self):
        self.closed = True


class Req:
    def __init__(self, requestor, target, prop="SAFEPASTE_SEL"):
        self.requestor = requestor
        self.target = target
        self.property = prop
        self.time = 1234
        self.selection = "CLIPBOARD"


def owner_over(conn_holder, **kw):
    """Build an owner whose connection is captured into conn_holder['conn']."""

    def connect(on_request, on_cleared=None):
        conn = FakeOwnerConnection(on_request, on_cleared, **kw)
        conn_holder["conn"] = conn
        return conn

    return X11SelectionOwner(connect=connect)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def test_a_write_takes_ownership_and_reports_success():
    h = {}
    owner = owner_over(h)
    assert owner.write(REDACTED) is True
    assert h["conn"].owns is True
    assert owner.last_error is None


def test_a_write_that_cannot_take_the_selection_reports_failure():
    h = {}
    owner = owner_over(h, can_own=False)
    assert owner.write(REDACTED) is False
    assert owner.last_error is not None


def test_ownership_is_reasserted_on_every_write():
    """Swapping the bytes quietly would leave nobody aware the value changed."""
    h = {}
    owner = owner_over(h)
    owner.write("first")
    first = h["conn"].timestamp
    owner.write("second")
    assert h["conn"].timestamp != first, "a second write must re-assert ownership"


def test_a_failure_to_get_a_timestamp_is_a_failed_write_not_a_silent_one():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    h["conn"].fail_time_with = TimeoutError("no timestamp")
    assert owner.write("later") is False
    assert owner.last_error is not None


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def test_text_is_served_for_every_text_target():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    for target in TEXT_TARGETS:
        who = FakeRequestor()
        owner._dispatch(Req(who, target))
        type_name, fmt, data = who.properties["SAFEPASTE_SEL"]
        assert data.decode("utf-8") == REDACTED, f"{target} served wrong bytes"
        assert (who, "SAFEPASTE_SEL") in h["conn"].replies


def test_targets_lists_what_we_will_actually_serve():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    who = FakeRequestor()
    owner._dispatch(Req(who, "TARGETS"))
    _, _, atoms = who.properties["SAFEPASTE_SEL"]
    assert set(TEXT_TARGETS) <= set(atoms)
    assert "TARGETS" in atoms and "TIMESTAMP" in atoms
    # Everything advertised must really be answerable.
    for target in atoms:
        if target in ("TARGETS", "TIMESTAMP"):
            continue
        fresh = FakeRequestor()
        owner._dispatch(Req(fresh, target))
        assert "SAFEPASTE_SEL" in fresh.properties, f"advertised {target} but refused it"


def test_an_unknown_target_is_refused_rather_than_answered_with_text():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    who = FakeRequestor()
    owner._dispatch(Req(who, "image/png"))
    assert who.properties == {}
    assert (who, None) in h["conn"].replies
    assert owner.refused == 1


def test_multiple_is_refused_not_mishandled():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    who = FakeRequestor()
    owner._dispatch(Req(who, "MULTIPLE"))
    assert (who, None) in h["conn"].replies


def test_a_requestor_that_names_no_property_gets_the_target_used_instead():
    """Obsolete clients send property=None; ICCCM says use the target."""
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    who = FakeRequestor()
    owner._dispatch(Req(who, "UTF8_STRING", prop=None))
    assert "UTF8_STRING" in who.properties
    assert (who, "UTF8_STRING") in h["conn"].replies


def test_a_value_larger_than_one_request_is_written_in_several_appends():
    h = {}
    owner = owner_over(h, chunk=64)
    big = "".join(chr(0x41 + (i % 26)) for i in range(5000))
    owner.write(big)
    who = FakeRequestor()
    owner._dispatch(Req(who, "UTF8_STRING"))
    _, _, data = who.properties["SAFEPASTE_SEL"]
    assert data.decode("utf-8") == big, "chunked write must reassemble byte-exact"
    assert who.writes > 1, "a 5000-byte value must not fit one 64-byte request"
    # And the reply comes after the last chunk, never before.
    assert h["conn"].replies[-1] == (who, "SAFEPASTE_SEL")


def test_unicode_survives_the_round_trip():
    h = {}
    owner = owner_over(h, chunk=8)
    text = "привет — ünïcode ✓ 日本語 " * 40
    owner.write(text)
    who = FakeRequestor()
    owner._dispatch(Req(who, "text/plain;charset=utf-8"))
    _, _, data = who.properties["SAFEPASTE_SEL"]
    assert data.decode("utf-8") == text


def test_a_request_before_anything_was_written_is_refused():
    h = {}
    owner = owner_over(h)
    owner._connection()
    who = FakeRequestor()
    owner._dispatch(Req(who, "UTF8_STRING"))
    assert who.properties == {}, "serving an empty string would paste as a blank"
    assert (who, None) in h["conn"].replies


def test_losing_the_selection_stops_us_claiming_to_hold_it():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    owner._on_cleared()
    who = FakeRequestor()
    owner._dispatch(Req(who, "UTF8_STRING"))
    assert (who, None) in h["conn"].replies


def test_clear_releases_the_selection():
    h = {}
    owner = owner_over(h)
    owner.write(REDACTED)
    assert owner.clear() is True
    assert h["conn"].released is True
    assert h["conn"].owns is False


# ---------------------------------------------------------------------------
# The fallback
# ---------------------------------------------------------------------------


class _StubPrimary:
    def __init__(self, ok):
        self.ok, self.calls, self.last_error = ok, 0, None if ok else "could not own"

    def write(self, text):
        self.calls += 1
        return self.ok

    def clear(self):
        return True

    def close(self):
        pass


class _StubFallback:
    def __init__(self):
        self.calls = 0
        self.written = None

    def write(self, text):
        self.calls += 1
        self.written = text
        return True

    def clear(self):
        return True


def test_a_failed_ownership_falls_back_rather_than_leaving_the_secret():
    primary, fallback = _StubPrimary(ok=False), _StubFallback()
    assert FallbackWriter(primary, fallback).write(REDACTED) is True
    assert fallback.calls == 1 and fallback.written == REDACTED


def test_a_successful_write_never_wakes_the_flickering_path():
    primary, fallback = _StubPrimary(ok=True), _StubFallback()
    assert FallbackWriter(primary, fallback).write(REDACTED) is True
    assert fallback.calls == 0


def test_the_writer_satisfies_the_backend_contract():
    from safepaste.backend import ClipboardWriter

    assert isinstance(FallbackWriter(_StubPrimary(True), _StubFallback()), ClipboardWriter)
    assert isinstance(X11SelectionOwner(), ClipboardWriter)
