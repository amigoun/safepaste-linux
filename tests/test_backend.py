"""The platform seam: does the contract hold, and does it fail helpfully?"""

from __future__ import annotations

import pytest

from safepaste.backend import (
    Backend,
    ClipboardEvent,
    ClipboardMonitor,
    ClipboardReader,
    ClipboardWriter,
    HotkeyBinder,
    content_hash,
    get_backend,
)


# --- the event type is portable -------------------------------------------


def test_clipboard_event_of_computes_its_own_digest() -> None:
    event = ClipboardEvent.of("hello")
    assert event.text == "hello"
    assert event.digest == content_hash("hello")
    # Defaults describe the least interesting clipboard: plain text, nothing lost.
    assert event.has_rich_flavours is False
    assert event.flavours == ()


def test_content_hash_is_stable_and_not_reversible() -> None:
    assert content_hash("abc") == content_hash("abc")
    assert content_hash("abc") != content_hash("abd")
    assert len(content_hash("abc")) == 64
    assert "abc" not in content_hash("abc")


def test_rich_flavour_flag_is_set_by_the_backend_not_parsed_here() -> None:
    """Portable code must never inspect MIME/UTI strings itself.

    Linux reports MIME types, macOS reports UTIs; the only portable statement is
    the boolean the backend already decided.
    """
    plain = ClipboardEvent.of("x", flavours=("text/plain",))
    rich = ClipboardEvent.of("x", has_rich_flavours=True, flavours=("text/html",))
    assert plain.has_rich_flavours is False
    assert rich.has_rich_flavours is True


# --- platform selection ----------------------------------------------------


def test_linux_backend_is_selected_on_linux() -> None:
    backend = get_backend("linux")
    assert backend.name == "linux"
    assert isinstance(backend, Backend)


def test_macos_fails_with_a_message_naming_what_is_missing() -> None:
    """An unimplemented platform must not look like a broken install."""
    with pytest.raises(NotImplementedError) as excinfo:
        get_backend("darwin")
    message = str(excinfo.value)
    assert "macOS" in message
    # Names the concrete APIs a port needs, so the error is a starting point.
    for expected in ("NSPasteboard", "backend.darwin", "detector"):
        assert expected in message


def test_unknown_platform_points_at_the_contract() -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        get_backend("plan9")
    assert "plan9" in str(excinfo.value)
    assert "backend" in str(excinfo.value)


# --- the Linux backend satisfies the protocols -----------------------------


def test_linux_clipboard_products_match_the_protocols() -> None:
    """Structural check only — nothing here talks to a real clipboard."""
    backend = get_backend("linux")

    writer = backend.clipboard_writer()
    assert isinstance(writer, ClipboardWriter)

    monitor = backend.clipboard_monitor(lambda _event: None)
    assert isinstance(monitor, ClipboardMonitor)
    assert isinstance(monitor.reader, ClipboardReader)


def test_linux_hotkey_binder_matches_the_protocol() -> None:
    binder = get_backend("linux").hotkey_binder()
    assert binder is not None
    assert isinstance(binder, HotkeyBinder)
    # available() must answer without raising even where the schema is absent.
    assert isinstance(binder.available(), bool)


def test_optional_capabilities_may_be_absent() -> None:
    """The base class returns None for everything optional.

    A backend inherits that, so a platform without a tray or an injector needs no
    stub implementations — and portable code has to cope with None either way.
    """
    bare = Backend()
    assert bare.lock_watcher() is None
    assert bare.hotkey_binder() is None
    assert bare.injector() is None
    assert bare.tray() is None
    # The two mandatory ones refuse rather than returning something useless.
    with pytest.raises(NotImplementedError):
        bare.clipboard_writer()
    with pytest.raises(NotImplementedError):
        bare.clipboard_monitor(lambda _e: None)
