"""The Windows backend, exercised on Linux against a fake Win32 clipboard.

Same arrangement as tests/test_darwin.py: the ctypes calls are unreachable here, so
they sit behind a protocol and everything around them is tested. The
windows-latest CI job covers the real API.

The fake mirrors documented Win32 behaviour, including the parts that make this
platform awkward: `OpenClipboard` can simply fail because another process holds the
clipboard, `EmptyClipboard` is mandatory before a write and discards every other
format, and `SetClipboardData` transfers memory ownership on success only.
"""

from __future__ import annotations

import pytest

from safepaste.backend import (
    ClipboardEvent,
    ClipboardMonitor,
    ClipboardReader,
    ClipboardWriter,
    Injector,
    get_backend,
)
from safepaste.backend.windows import (
    CF_LOCALE,
    CF_UNICODETEXT,
    OPEN_RETRIES,
    WindowsBackend,
    WindowsClipboardMonitor,
    WindowsClipboardReader,
    WindowsClipboardWriter,
    WindowsInjector,
    has_rich_formats,
)

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore\n"

CF_HTML = 49382  # a registered format id, standing in for "HTML Format"


class FakeWin32Clipboard:
    def __init__(self, text: str | None = None, formats: list[int] | None = None) -> None:
        self._text = text
        self._formats = list(formats if formats is not None else ([CF_UNICODETEXT, CF_LOCALE] if text else []))
        self._sequence = 1
        self.is_open = False
        self.open_calls = 0
        self.close_calls = 0
        self.empty_calls = 0
        # Number of initial open() attempts to refuse, simulating contention.
        self.busy_for = 0
        self.fail_empty = False
        self.fail_set = False

    # -- the Win32 slice ---------------------------------------------------

    def sequence_number(self) -> int:
        return self._sequence

    def open(self) -> bool:
        self.open_calls += 1
        if self.busy_for > 0:
            self.busy_for -= 1
            return False
        self.is_open = True
        return True

    def close(self) -> None:
        self.close_calls += 1
        self.is_open = False

    def empty(self) -> bool:
        assert self.is_open, "EmptyClipboard without owning the clipboard"
        self.empty_calls += 1
        if self.fail_empty:
            return False
        self._text = None
        self._formats = []
        self._sequence += 1
        return True

    def formats(self) -> list[int]:
        assert self.is_open, "EnumClipboardFormats without owning the clipboard"
        return list(self._formats)

    def get_text(self) -> str | None:
        assert self.is_open, "GetClipboardData without owning the clipboard"
        return self._text

    def set_text(self, text: str) -> bool:
        assert self.is_open, "SetClipboardData without owning the clipboard"
        if self.fail_set:
            return False
        self._text = text
        self._formats = [CF_UNICODETEXT, CF_LOCALE]
        self._sequence += 1
        return True

    # -- test helper -------------------------------------------------------

    def external_copy(self, text: str, formats: list[int] | None = None) -> None:
        self._text = text
        self._formats = list(formats or [CF_UNICODETEXT, CF_LOCALE])
        self._sequence += 1


def _nosleep(_seconds: float) -> None:
    """Retry backoff without the wait, so contention tests stay fast."""


@pytest.fixture
def api() -> FakeWin32Clipboard:
    return FakeWin32Clipboard("initial")


# --- format classification ------------------------------------------------


def test_cf_locale_is_not_treated_as_rich() -> None:
    """Windows synthesises CF_LOCALE next to any text.

    Counting it as rich would make every plain-text copy claim it carried
    formatting, and the dialog would apologise for losing something that was
    never there.
    """
    assert has_rich_formats([CF_UNICODETEXT, CF_LOCALE]) is False
    assert has_rich_formats([CF_UNICODETEXT]) is False
    assert has_rich_formats([CF_UNICODETEXT, CF_HTML]) is True
    assert has_rich_formats([]) is False


# --- the exclusive lock ----------------------------------------------------


def test_the_clipboard_is_always_released(api: FakeWin32Clipboard) -> None:
    """A clipboard left open blocks every other application on the desktop."""
    WindowsClipboardReader(api, _nosleep).read_text()
    assert api.is_open is False
    assert api.close_calls == api.open_calls

    WindowsClipboardWriter(api, _nosleep).write("x")
    assert api.is_open is False


def test_a_busy_clipboard_is_retried_not_failed(api: FakeWin32Clipboard) -> None:
    """OpenClipboard failing is routine, not exceptional.

    Another process holding the clipboard mid-copy is normal on Windows; treating
    the first refusal as an error would drop secrets on the floor.
    """
    api.busy_for = 3
    event = WindowsClipboardReader(api, _nosleep).read_text()
    assert event is not None and event.text == "initial"
    assert api.open_calls == 4  # three refusals, then success


def test_giving_up_is_reported_honestly(api: FakeWin32Clipboard) -> None:
    """If it never frees up, say so rather than claiming success.

    Note each operation gets its own budget: the reader below exhausts its
    OPEN_RETRIES attempts, so `busy_for` has to be reset before the writer is
    tested, or the writer finds a free clipboard and legitimately succeeds.
    """
    api.busy_for = OPEN_RETRIES + 1
    assert WindowsClipboardReader(api, _nosleep).read_text() is None
    assert api.is_open is False

    api.busy_for = OPEN_RETRIES + 1
    assert WindowsClipboardWriter(api, _nosleep).write("x") is False
    assert api.is_open is False


def test_no_clipboard_call_happens_without_ownership(api: FakeWin32Clipboard) -> None:
    """The fake asserts this internally; this test makes the intent explicit."""
    api.busy_for = OPEN_RETRIES + 1
    # Would raise AssertionError inside the fake if we read without acquiring.
    assert WindowsClipboardReader(api, _nosleep).read_text() is None


# --- reader ---------------------------------------------------------------


def test_reader_returns_the_contract_type(api: FakeWin32Clipboard) -> None:
    api.external_copy(PAYLOAD)
    event = WindowsClipboardReader(api, _nosleep).read_text()
    assert isinstance(event, ClipboardEvent)
    assert event.text == PAYLOAD
    assert event.flavour == "CF_UNICODETEXT"
    assert event.has_rich_flavours is False


def test_reader_flags_rich_content(api: FakeWin32Clipboard) -> None:
    api.external_copy("hi", [CF_UNICODETEXT, CF_LOCALE, CF_HTML])
    event = WindowsClipboardReader(api, _nosleep).read_text()
    assert event is not None and event.has_rich_flavours is True


def test_reader_returns_none_when_there_is_no_text() -> None:
    board = FakeWin32Clipboard(None, [CF_HTML])
    assert WindowsClipboardReader(board, _nosleep).read_text() is None


def test_reader_returns_none_for_an_empty_clipboard() -> None:
    assert WindowsClipboardReader(FakeWin32Clipboard(None, []), _nosleep).read_text() is None


# --- writer ---------------------------------------------------------------


def test_write_empties_first(api: FakeWin32Clipboard) -> None:
    """EmptyClipboard is mandatory before SetClipboardData; skipping it leaves
    stale representations, which for us would mean a stale secret."""
    assert WindowsClipboardWriter(api, _nosleep).write("clean") is True
    assert api.empty_calls == 1
    # Read it back through the reader rather than poking at the fake's internals.
    written = WindowsClipboardReader(api, _nosleep).read_text()
    assert written is not None and written.text == "clean"


def test_a_failed_empty_is_reported(api: FakeWin32Clipboard) -> None:
    api.fail_empty = True
    assert WindowsClipboardWriter(api, _nosleep).write("x") is False
    assert api.is_open is False


def test_a_failed_set_is_reported(api: FakeWin32Clipboard) -> None:
    api.fail_set = True
    assert WindowsClipboardWriter(api, _nosleep).write("x") is False
    assert api.is_open is False


# --- monitor: sequence-number polling ------------------------------------


def _monitor(api: FakeWin32Clipboard, seen: list[ClipboardEvent]) -> WindowsClipboardMonitor:
    monitor = WindowsClipboardMonitor(seen.append, api, sleep=_nosleep)
    assert monitor.start() is True
    return monitor


def test_no_change_means_no_callback(api: FakeWin32Clipboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    for _ in range(5):
        monitor.poll_once()
    assert seen == []


def test_a_change_is_reported_once(api: FakeWin32Clipboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    api.external_copy(PAYLOAD)
    monitor.poll_once()
    monitor.poll_once()
    assert [e.text for e in seen] == [PAYLOAD]


def test_our_own_write_is_not_reported_back(api: FakeWin32Clipboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    writer = WindowsClipboardWriter(api, _nosleep)
    monitor.note_own_write("[REDACTED]")
    writer.write("[REDACTED]")
    monitor.poll_once()
    assert seen == []


def test_identical_content_recopied_is_ignored(api: FakeWin32Clipboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    api.external_copy(PAYLOAD)
    monitor.poll_once()
    api.external_copy(PAYLOAD)  # sequence moves, content identical
    monitor.poll_once()
    assert len(seen) == 1


def test_monitor_uses_the_injected_scheduler(api: FakeWin32Clipboard) -> None:
    scheduled: list[tuple[float, object]] = []
    cancelled: list[object] = []
    monitor = WindowsClipboardMonitor(
        lambda _e: None, api,
        schedule_repeating=lambda i, fn: (scheduled.append((i, fn)), "h")[1],
        cancel=cancelled.append, interval=0.4, sleep=_nosleep,
    )
    assert monitor.start() is True
    assert scheduled and scheduled[0][0] == 0.4
    monitor.stop()
    assert cancelled == ["h"]


def test_a_failing_sequence_number_does_not_raise(api: FakeWin32Clipboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    api.sequence_number = lambda: (_ for _ in ()).throw(OSError("boom"))  # type: ignore[method-assign]
    monitor.poll_once()
    assert seen == []


def test_contention_during_a_poll_is_survivable(api: FakeWin32Clipboard) -> None:
    """The sequence number moved but the clipboard is locked: skip, do not crash.

    The next poll picks it up, because a failed read leaves the digest unset.
    """
    seen: list[ClipboardEvent] = []
    monitor = _monitor(api, seen)
    api.external_copy(PAYLOAD)
    api.busy_for = OPEN_RETRIES + 1
    monitor.poll_once()
    assert seen == []

    api.busy_for = 0
    api.external_copy(PAYLOAD)  # the application is still holding it out there
    monitor.poll_once()
    assert [e.text for e in seen] == [PAYLOAD]


# --- injector -------------------------------------------------------------


def test_injector_reports_honestly_on_either_platform() -> None:
    """Never raises, and never claims success it did not have.

    Off Windows there is no ctypes.WinDLL, which is the same code path as any
    SendInput failure: report False. On Windows SendInput needs no permission, so
    it must genuinely succeed — and asserting that is what caught ERROR_INVALID_
    PARAMETER (87) from an under-sized INPUT union. An earlier version of this test
    only checked "returns a result without raising", which False satisfied, so the
    bug slipped through until the CI log was read by eye.
    """
    import sys

    injector = WindowsInjector()
    results: list[bool] = []
    injector.paste(results.append)
    assert len(results) == 1
    if sys.platform == "win32":
        assert results == [True], (
            "SendInput needs no permission on Windows, so failure means the INPUT "
            "struct is wrong -- check cbSize against the real union"
        )
    else:
        assert results == [False]
    injector.close()


# --- protocol conformance and integration --------------------------------


def test_windows_products_satisfy_the_contract(api: FakeWin32Clipboard) -> None:
    backend = WindowsBackend(api=api, sleep=_nosleep)
    assert isinstance(backend.clipboard_writer(), ClipboardWriter)
    monitor = backend.clipboard_monitor(lambda _e: None)
    assert isinstance(monitor, ClipboardMonitor)
    assert isinstance(monitor.reader, ClipboardReader)
    assert isinstance(backend.injector(), Injector)


def test_get_backend_routes_win32_without_needing_windows() -> None:
    backend = get_backend("win32")
    assert backend.name == "windows"
    assert backend.hotkey_binder() is None  # RegisterHotKey needs a message pump
    assert backend.tray() is None  # Shell_NotifyIcon needs a window
    assert backend.lock_watcher() is None  # the Win32 clipboard does not block


def test_windows_config_lives_under_appdata() -> None:
    assert get_backend("win32").config_dir_name() == ("SafePaste",)


def test_the_whole_guard_pipeline_runs_on_the_windows_backend(tmp_path, monkeypatch) -> None:
    """Portable policy, driven by the Win32 backend."""
    import safepaste.config as config_mod
    from safepaste.guard import Guard

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    api = FakeWin32Clipboard("nothing interesting")
    guard = Guard(
        config_mod.Config(mode="redact", restore_timeout_secs=60).validated(),
        backend=WindowsBackend(api=api, sleep=_nosleep),
    )
    assert guard.start() is True

    api.external_copy(PAYLOAD)
    guard.monitor.poll_once()

    written = WindowsClipboardReader(api, _nosleep).read_text()
    assert written is not None
    assert SECRET not in written.text
    assert "[REDACTED]" in written.text
    assert written.text.startswith("notes\n") and written.text.endswith("more\n")

    seen_after: list[ClipboardEvent] = []
    guard.monitor.on_change = seen_after.append
    assert guard.restore_original() is True
    current = WindowsClipboardReader(api, _nosleep).read_text()
    assert current is not None and current.text == PAYLOAD
    guard.monitor.poll_once()
    assert seen_after == [], "restoring is our own write, not a new copy"

    guard.stop()


# ---------------------------------------------------------------------------
# Wide-char sizing.
#
# Found on a windows-latest runner as "20 chars in, 19 out": the buffer was sized
# from len(text), which counts code points, while UTF-16 counts code units. Any
# astral character is a surrogate pair and needs two.
# ---------------------------------------------------------------------------


def test_utf16_size_counts_code_units_not_code_points() -> None:
    from safepaste.backend.windows import utf16_size_with_nul

    # ASCII and BMP: code points and code units coincide, so the naive formula
    # happens to be right and the bug stays hidden.
    assert utf16_size_with_nul("") == 2
    assert utf16_size_with_nul("plain") == 12 == (len("plain") + 1) * 2
    assert utf16_size_with_nul("naïve") == 12

    # Astral characters do not. This is where the naive formula truncates.
    for text in ("🔐", "a🔐b", "naïve — 日本語 — 🔐 tail"):
        naive = (len(text) + 1) * 2
        correct = utf16_size_with_nul(text)
        assert correct > naive, f"{text!r} must need more than the naive size"
        assert correct == len(text.encode("utf-16-le")) + 2


def test_utf16_size_matches_what_ctypes_would_allocate() -> None:
    """The value we pass to GlobalAlloc must equal the buffer ctypes builds.

    create_unicode_buffer uses wchar_t, which is 2 bytes on Windows and 4 on Linux,
    so only the 2-byte case can be asserted portably — but the *relationship* is
    what matters and is checked with an assert in set_text at runtime.
    """
    import ctypes

    from safepaste.backend.windows import utf16_size_with_nul

    if ctypes.sizeof(ctypes.c_wchar) != 2:
        pytest.skip("wchar_t is not UTF-16 here, so ctypes sizing cannot be compared")
    for text in ("", "plain", "naïve", "a🔐b"):
        assert utf16_size_with_nul(text) == ctypes.sizeof(ctypes.create_unicode_buffer(text))
