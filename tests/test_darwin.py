"""The macOS backend, exercised on Linux against a fake pasteboard.

This is not a substitute for running on a Mac, and does not pretend to be. What it
does establish is that everything *except* the literal AppKit calls is correct:
change-count polling, own-write suppression, duplicate suppression, UTI handling,
multi-representation writes, AppleScript quoting, and — most usefully —
that the whole portable Guard pipeline works when driven by this backend.

The fake below mirrors documented NSPasteboard semantics: `changeCount` is
monotonic and moves on every mutation, `clearContents` must precede a write and
itself bumps the count, `stringForType_` returns None when the type is absent, and
`setString_forType_` returns a BOOL.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys

import pytest

from conftest import ABOUT_LABEL, QUIT_LABEL
from safepaste.backend import (
    ClipboardEvent,
    ClipboardMonitor,
    ClipboardReader,
    ClipboardWriter,
    Injector,
    get_backend,
)
from safepaste.backend.darwin import (
    UTI_HTML,
    UTI_RTF,
    UTI_STRING,
    DarwinBackend,
    DarwinClipboardMonitor,
    DarwinClipboardReader,
    DarwinClipboardWriter,
    DarwinInjector,
    _applescript_string,
    has_rich_representations,
)

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore\n"


class FakePasteboard:
    """Stands in for NSPasteboard.generalPasteboard()."""

    def __init__(self, contents: dict[str, str] | None = None) -> None:
        self._contents = dict(contents or {})
        self._change_count = 1
        self.refuse_write = False
        self.raise_on_write = False
        self.clear_calls = 0
        self.set_calls: list[tuple[str, str]] = []

    # -- the NSPasteboard slice we depend on --------------------------------

    def changeCount(self) -> int:  # noqa: N802 - PyObjC naming
        return self._change_count

    def types(self) -> list[str]:
        return list(self._contents)

    def stringForType_(self, uti: str) -> str | None:  # noqa: N802
        return self._contents.get(uti)

    def clearContents(self) -> int:  # noqa: N802
        self.clear_calls += 1
        self._contents.clear()
        self._change_count += 1
        return self._change_count

    def setString_forType_(self, text: str, uti: str) -> bool:  # noqa: N802
        if self.raise_on_write:
            raise RuntimeError("pasteboard exploded")
        self.set_calls.append((uti, text))
        if self.refuse_write:
            return False
        self._contents[uti] = text
        return True

    # -- test helper: an external application copies something -------------

    def external_copy(self, contents: dict[str, str]) -> None:
        self._contents = dict(contents)
        self._change_count += 1


@pytest.fixture
def board() -> FakePasteboard:
    return FakePasteboard({UTI_STRING: "initial"})


# --- UTI handling ----------------------------------------------------------


def test_rich_representation_detection() -> None:
    assert has_rich_representations([UTI_STRING]) is False
    assert has_rich_representations([UTI_STRING, "public.plain-text"]) is False
    assert has_rich_representations([UTI_STRING, UTI_HTML]) is True
    assert has_rich_representations(["public.tiff"]) is True
    assert has_rich_representations([]) is False


# --- reader ----------------------------------------------------------------


def test_reader_returns_a_contract_event(board: FakePasteboard) -> None:
    board.external_copy({UTI_STRING: PAYLOAD})
    event = DarwinClipboardReader(board).read_text()
    assert isinstance(event, ClipboardEvent)
    assert event.text == PAYLOAD
    assert event.flavour == UTI_STRING
    assert event.has_rich_flavours is False


def test_reader_flags_rich_content(board: FakePasteboard) -> None:
    board.external_copy({UTI_STRING: "hi", UTI_HTML: "<b>hi</b>"})
    event = DarwinClipboardReader(board).read_text()
    assert event is not None and event.has_rich_flavours is True
    assert UTI_HTML in event.flavours


def test_reader_returns_none_for_an_empty_pasteboard() -> None:
    assert DarwinClipboardReader(FakePasteboard({})).read_text() is None


def test_reader_returns_none_when_there_is_no_plain_text() -> None:
    """An image or a file promise is nothing for a secret scanner to do."""
    board = FakePasteboard({"public.tiff": "not really an image"})
    assert DarwinClipboardReader(board).read_text() is None


def test_reader_carries_the_text_bearing_representations() -> None:
    """HTML and RTF can hold what the plain text lacks, so both reach the guard."""
    html = '<a href="https://ci.example/?t=1">report</a>'
    board = FakePasteboard({UTI_STRING: "report", UTI_HTML: html, UTI_RTF: "{\\rtf1 report}"})
    event = DarwinClipboardReader(board).read_text()
    assert event is not None
    assert event.representations == {UTI_HTML: html, UTI_RTF: "{\\rtf1 report}"}


def test_an_html_only_pasteboard_is_still_read() -> None:
    """macOS synthesises plain text from RTF but not from HTML."""
    board = FakePasteboard({UTI_HTML: f"<p>GITHUB_TOKEN={SECRET}</p>"})
    event = DarwinClipboardReader(board).read_text()
    assert event is not None and event.text == ""
    assert UTI_HTML in event.representations


def test_same_text_over_different_markup_is_a_different_value() -> None:
    """Two links with the same visible text must not be deduplicated as one copy."""
    first = DarwinClipboardReader(
        FakePasteboard({UTI_STRING: "report", UTI_HTML: '<a href="/a">report</a>'})
    ).read_text()
    second = DarwinClipboardReader(
        FakePasteboard({UTI_STRING: "report", UTI_HTML: '<a href="/b">report</a>'})
    ).read_text()
    assert first is not None and second is not None
    assert first.digest != second.digest


# --- writer ---------------------------------------------------------------


def test_writer_clears_before_setting(board: FakePasteboard) -> None:
    """NSPasteboard requires clearContents() before a write; skipping it silently
    leaves stale representations behind, which for us would mean a stale secret."""
    assert DarwinClipboardWriter(board).write("clean") is True
    assert board.clear_calls == 1
    assert board.set_calls == [(UTI_STRING, "clean")]


def test_writer_reports_refusal_honestly(board: FakePasteboard) -> None:
    board.refuse_write = True
    assert DarwinClipboardWriter(board).write("x") is False


def test_writer_survives_a_raising_pasteboard(board: FakePasteboard) -> None:
    board.raise_on_write = True
    assert DarwinClipboardWriter(board).write("x") is False


def test_multi_flavour_write_keeps_both_representations(board: FakePasteboard) -> None:
    """The capability Linux lacks: wl-copy serves one MIME type per invocation, so
    redacting a rich selection there drops the HTML. Here both survive."""
    writer = DarwinClipboardWriter(board)
    assert writer.write_flavours({UTI_STRING: "[REDACTED]", UTI_HTML: "<b>[REDACTED]</b>"})
    assert board.stringForType_(UTI_STRING) == "[REDACTED]"
    assert board.stringForType_(UTI_HTML) == "<b>[REDACTED]</b>"
    assert board.clear_calls == 1, "one transaction, not one per representation"


def test_multi_flavour_write_rejects_nothing_to_write(board: FakePasteboard) -> None:
    assert DarwinClipboardWriter(board).write_flavours({}) is False


def test_rich_representations_are_written_as_ascii() -> None:
    """Pasted HTML without a charset is read as Latin-1, and RTF is 7-bit, so the
    placeholder's ellipsis would arrive as mojibake. Measured on a real Mac."""
    from safepaste.backend.darwin import pasteboard_form

    assert pasteboard_form(UTI_HTML, "<b>a\u2026b</b>") == "<b>a&#8230;b</b>"
    assert pasteboard_form(UTI_RTF, "{\\rtf1 a\u2026b}") == "{\\rtf1 a{\\uc1\\u8230?}b}"
    # Outside the BMP, RTF wants a surrogate pair of signed 16-bit values.
    assert pasteboard_form(UTI_RTF, "\U0001F511") == "{\\uc1\\u-10179?\\u-8943?}"
    assert pasteboard_form(UTI_STRING, "a\u2026b") == "a\u2026b"
    assert pasteboard_form(UTI_HTML, "<p>plain ascii</p>") == "<p>plain ascii</p>"


# --- monitor: change-count polling ---------------------------------------


def _monitor(board: FakePasteboard, seen: list[ClipboardEvent]) -> DarwinClipboardMonitor:
    monitor = DarwinClipboardMonitor(seen.append, board)
    assert monitor.start() is True
    return monitor


def test_no_change_means_no_callback(board: FakePasteboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    for _ in range(5):
        monitor.poll_once()
    assert seen == [], "polling an unchanged pasteboard must be silent"


def test_a_change_is_reported_once(board: FakePasteboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    board.external_copy({UTI_STRING: PAYLOAD})
    monitor.poll_once()
    monitor.poll_once()  # count has not moved again
    assert len(seen) == 1
    assert seen[0].text == PAYLOAD


def test_our_own_write_is_not_reported_back(board: FakePasteboard) -> None:
    """Without this a redaction is rescanned, and a restore is instantly
    re-redacted — which is what makes an undo button look broken."""
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    writer = DarwinClipboardWriter(board)

    monitor.note_own_write("[REDACTED]")
    writer.write("[REDACTED]")  # bumps changeCount twice (clear + set)
    monitor.poll_once()
    assert seen == []


def test_identical_content_recopied_is_ignored(board: FakePasteboard) -> None:
    """changeCount moves when an application reasserts the same content."""
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    board.external_copy({UTI_STRING: PAYLOAD})
    monitor.poll_once()
    board.external_copy({UTI_STRING: PAYLOAD})  # same text, new count
    monitor.poll_once()
    assert len(seen) == 1


def test_a_reassert_of_what_we_wrote_is_not_reported(board: FakePasteboard) -> None:
    """Clipboard managers re-assert the value we wrote; that is not a new copy."""
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    writer = DarwinClipboardWriter(board)
    writer.write(PAYLOAD)
    monitor.note_own_write(PAYLOAD)
    monitor.poll_once()

    board.external_copy({UTI_STRING: PAYLOAD})
    monitor.poll_once()
    assert seen == []


def test_a_genuinely_new_value_is_reported(board: FakePasteboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    board.external_copy({UTI_STRING: "first"})
    monitor.poll_once()
    board.external_copy({UTI_STRING: "second"})
    monitor.poll_once()
    assert [e.text for e in seen] == ["first", "second"]


def test_monitor_uses_the_injected_scheduler(board: FakePasteboard) -> None:
    """The run loop belongs to the shell, not to the monitor."""
    scheduled: list[tuple[float, object]] = []
    cancelled: list[object] = []
    monitor = DarwinClipboardMonitor(
        lambda _e: None,
        board,
        schedule_repeating=lambda interval, fn: (scheduled.append((interval, fn)), "h")[1],
        cancel=cancelled.append,
        interval=0.25,
    )
    assert monitor.start() is True
    assert scheduled and scheduled[0][0] == 0.25
    monitor.stop()
    assert cancelled == ["h"]


def test_a_failing_change_count_does_not_raise(board: FakePasteboard) -> None:
    seen: list[ClipboardEvent] = []
    monitor = _monitor(board, seen)
    board.changeCount = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    monitor.poll_once()  # must swallow and carry on
    assert seen == []


# --- injector -------------------------------------------------------------


def test_injector_declines_without_accessibility_permission(monkeypatch) -> None:
    """A process without Accessibility permission must decline, never raise.

    The ungranted state is forced rather than assumed. This test used to pass
    for the wrong reason -- ApplicationServices is not a dependency, so the
    import failed and _trusted returned False on every machine, granted or
    not. Asking Quartz fixed that, and promptly showed why the assumption was
    unsafe: GitHub's macOS runners *do* have post-event access, so
    CGPreflightPostEventAccess returns True there and an unconditional
    "ready is False" fails. What this test is about is the refusal path, so it
    pins the permission answer and leaves the machine's own TCC state out of
    it. Whether a granted process reports True is
    test_accessibility_trust_does_not_depend_on_applicationservices' job.
    """
    for module_name, attr in (
        ("Quartz", "CGPreflightPostEventAccess"),
        ("ApplicationServices", "AXIsProcessTrusted"),
    ):
        if importlib.util.find_spec(module_name) is not None:
            monkeypatch.setattr(
                importlib.import_module(module_name), attr, lambda: False, raising=False
            )

    injector = DarwinInjector()
    assert injector.ready is False
    results: list[bool] = []
    injector.paste(results.append)
    assert results == [False]
    injector.close()


# --- notifications --------------------------------------------------------


def test_applescript_quoting_escapes_quotes_and_backslashes() -> None:
    """Labels are interpolated into an AppleScript string; a stray quote would
    otherwise change the meaning of the script."""
    assert _applescript_string('say "hi"') == '"say \\"hi\\""'
    assert _applescript_string("back\\slash") == '"back\\\\slash"'
    assert _applescript_string("plain") == '"plain"'


# --- protocol conformance and integration --------------------------------


def test_darwin_products_satisfy_the_contract(board: FakePasteboard) -> None:
    backend = DarwinBackend(pasteboard=board)
    assert isinstance(backend.clipboard_writer(), ClipboardWriter)
    monitor = backend.clipboard_monitor(lambda _e: None)
    assert isinstance(monitor, ClipboardMonitor)
    assert isinstance(monitor.reader, ClipboardReader)
    assert isinstance(backend.injector(), Injector)


def test_get_backend_routes_darwin_without_needing_a_mac() -> None:
    """Routing works anywhere; capabilities depend on the platform.

    Deliberately conditioned rather than asserting None flatly: the same mistake
    broke the Windows suite the moment its tray was implemented, and these two
    would have broken here for exactly the same reason.
    """
    backend = get_backend("darwin")
    assert backend.name == "darwin"
    # Permanently true: NSPasteboard does not block on a locked screen, so there is
    # nothing for a lock watcher to do.
    assert backend.lock_watcher() is None

    if sys.platform != "darwin":
        # No AppKit, so no run loop, so neither capability can exist.
        assert backend.run_loop() is None
        assert backend.tray() is None
        assert backend.hotkey_binder(on_pressed=lambda: None) is None


def test_macos_config_lives_under_application_support() -> None:
    assert get_backend("darwin").config_dir_name() == (
        "Application Support",
        "SafePaste",
    )


def test_the_whole_guard_pipeline_runs_on_the_darwin_backend(tmp_path, monkeypatch) -> None:
    """The integration that matters: portable policy driven by the macOS backend.

    Proves the seam holds — the same fail-safe ordering, redaction and undo work
    with NSPasteboard semantics underneath instead of XFIXES and wl-copy.
    """
    import safepaste.config as config_mod
    from safepaste.guard import Guard

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    board = FakePasteboard({UTI_STRING: "nothing interesting"})
    backend = DarwinBackend(pasteboard=board)
    guard = Guard(
        config_mod.Config(mode="redact", restore_timeout_secs=60).validated(),
        backend=backend,
    )
    assert guard.start() is True

    # An application copies a secret; the monitor notices on the next poll.
    board.external_copy({UTI_STRING: PAYLOAD})
    guard.monitor.poll_once()

    written = board.stringForType_(UTI_STRING)
    assert written is not None
    assert SECRET not in written, "the secret must be gone from the pasteboard"
    assert "[REDACTED]" in written
    assert written.startswith("notes\n") and written.endswith("more\n")

    # And the undo restores it, without the monitor treating that as a new copy.
    seen_after: list[ClipboardEvent] = []
    guard.monitor.on_change = seen_after.append
    assert guard.restore_original() is True
    assert board.stringForType_(UTI_STRING) == PAYLOAD
    guard.monitor.poll_once()
    assert seen_after == [], "restoring is our own write, not a new copy to redact"

    guard.stop()


def test_restore_does_not_overwrite_a_newer_copy(tmp_path, monkeypatch) -> None:
    import safepaste.config as config_mod
    from safepaste.guard import Guard

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = Guard(
        config_mod.Config(mode="redact", restore_timeout_secs=60).validated(),
        backend=DarwinBackend(pasteboard=board),
    )
    guard.start()
    board.external_copy({UTI_STRING: PAYLOAD})
    guard.monitor.poll_once()

    board.external_copy({UTI_STRING: "the user's newer copy"})
    assert guard.restore_original() is False, "unseen yet, but the pasteboard moved"
    guard.monitor.poll_once()
    assert guard.restore_original() is False
    assert board.stringForType_(UTI_STRING) == "the user's newer copy"


def test_a_clipboard_manager_reasserting_our_write_changes_nothing(
    tmp_path, monkeypatch
) -> None:
    """Re-asserting the redaction must not drop the undo or the never-flag
    target, and re-asserting a restore must not redact it again."""
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = _darwin_guard(tmp_path, monkeypatch, board)
    board.external_copy({UTI_STRING: PAYLOAD})
    guard.monitor.poll_once()
    redacted = board.stringForType_(UTI_STRING)
    assert SECRET not in redacted
    hashes = guard._last_secret_hashes

    board.external_copy({UTI_STRING: redacted})
    guard.monitor.poll_once()
    assert guard._last_secret_hashes == hashes
    assert guard.restore_original() is True
    guard.monitor.poll_once()

    board.external_copy({UTI_STRING: PAYLOAD})
    guard.monitor.poll_once()
    assert board.stringForType_(UTI_STRING) == PAYLOAD


def _darwin_guard(tmp_path, monkeypatch, board: FakePasteboard, **cfg):
    import safepaste.config as config_mod
    from safepaste.guard import Guard

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")
    cfg.setdefault("mode", "redact")
    cfg.setdefault("restore_timeout_secs", 60)
    guard = Guard(config_mod.Config(**cfg).validated(), backend=DarwinBackend(pasteboard=board))
    assert guard.start() is True
    return guard


def _holds_secret(board: FakePasteboard) -> list[str]:
    return [uti for uti in board.types() if SECRET in (board.stringForType_(uti) or "")]


def test_a_secret_only_in_the_html_is_removed(tmp_path, monkeypatch) -> None:
    """The plain text is a link's label; the token is in its URL.

    Scanning the plain text alone called this clean and left the token on the
    pasteboard for any application that pastes HTML.
    """
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = _darwin_guard(tmp_path, monkeypatch, board)
    html = f'<a href="https://ci.example/api?token={SECRET}">Download report</a>'
    board.external_copy({UTI_STRING: "Download report", UTI_HTML: html})
    guard.monitor.poll_once()

    assert _holds_secret(board) == []
    assert board.stringForType_(UTI_STRING) == "Download report"
    assert "[REDACTED]" in (board.stringForType_(UTI_HTML) or ""), "the link is kept"


def test_an_html_only_copy_is_scanned(tmp_path, monkeypatch) -> None:
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = _darwin_guard(tmp_path, monkeypatch, board)
    board.external_copy({UTI_HTML: f"<p>GITHUB_TOKEN={SECRET}</p>"})
    guard.monitor.poll_once()

    assert _holds_secret(board) == []
    assert "[REDACTED]" in (board.stringForType_(UTI_HTML) or "")


def test_formatting_survives_a_redaction(tmp_path, monkeypatch) -> None:
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = _darwin_guard(tmp_path, monkeypatch, board)
    board.external_copy(
        {UTI_STRING: PAYLOAD, UTI_HTML: f"<pre>{PAYLOAD}</pre>", UTI_RTF: f"{{\\rtf1 {PAYLOAD}}}"}
    )
    guard.monitor.poll_once()

    assert _holds_secret(board) == []
    assert set(board.types()) == {UTI_STRING, UTI_HTML, UTI_RTF}
    assert (board.stringForType_(UTI_HTML) or "").startswith("<pre>notes")

    # The undo puts every representation back, and is not mistaken for a copy.
    assert guard.restore_original() is True
    assert board.stringForType_(UTI_HTML) == f"<pre>{PAYLOAD}</pre>"
    guard.monitor.poll_once()
    assert board.stringForType_(UTI_STRING) == PAYLOAD


def test_markup_that_hides_the_secret_from_its_own_scan_is_dropped(
    tmp_path, monkeypatch
) -> None:
    """Split by a tag, the token renders whole but scans as two harmless halves.

    The plain text proves it is there, so a representation whose own scan cannot
    account for it is dropped rather than trusted.
    """
    board = FakePasteboard({UTI_STRING: "quiet"})
    guard = _darwin_guard(tmp_path, monkeypatch, board)
    html = f"<p>GITHUB_TOKEN={SECRET[:12]}<b></b>{SECRET[12:]}</p>"
    board.external_copy({UTI_STRING: PAYLOAD, UTI_HTML: html})
    guard.monitor.poll_once()

    assert board.types() == [UTI_STRING], "the HTML could not be shown clean"
    assert SECRET not in (board.stringForType_(UTI_STRING) or "")


# --- the polling shell ----------------------------------------------------
#
# The macOS run loop. Tested here because it is only used by poll-driven
# backends, and the fake pasteboard is what makes it drivable off a Mac.


def test_polling_shell_redacts_and_notifies(tmp_path, monkeypatch) -> None:
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    board = FakePasteboard({UTI_STRING: "quiet"})
    notes: list[tuple[str, str]] = []
    shell = PollingShell(
        config_mod.Config(mode="redact").validated(),
        backend=DarwinBackend(pasteboard=board),
        notify=lambda title, body: (notes.append((title, body)), True)[1],
    )
    assert shell.guard.start() is True

    board.external_copy({UTI_STRING: PAYLOAD})
    shell.guard.monitor.poll_once()

    assert SECRET not in (board.stringForType_(UTI_STRING) or "")
    assert len(notes) == 1
    title, body = notes[0]
    assert "removed from the clipboard" in title
    assert "GitHub PAT" in body
    # The notification itself must never carry the secret.
    assert SECRET not in title and SECRET not in body


def test_polling_shell_ask_mode_swaps_first_and_holds_nothing(tmp_path, monkeypatch) -> None:
    """There is no dialog here, so `ask` can only run as `redact`.

    Leaving the secret in place while asking nobody is the outcome the fail-safe
    default exists to prevent. And with no "Restore original" anywhere on this
    shell, the plaintext is not kept around for one.
    """
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    board = FakePasteboard({UTI_STRING: "quiet"})
    notes: list[tuple[str, str]] = []
    shell = PollingShell(
        config_mod.Config(mode="ask", restore_timeout_secs=60).validated(),
        backend=DarwinBackend(pasteboard=board),
        notify=lambda t, b: (notes.append((t, b)), True)[1],
    )
    shell.guard.start()
    board.external_copy({UTI_STRING: PAYLOAD})
    shell.guard.monitor.poll_once()

    assert SECRET not in (board.stringForType_(UTI_STRING) or "")
    assert "removed from the clipboard" in notes[0][0]
    assert shell.guard._held is None


def test_polling_shell_does_not_claim_a_removal_that_failed(tmp_path, monkeypatch) -> None:
    """A redaction the pasteboard refused leaves the secret where it was."""
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    board = FakePasteboard({UTI_STRING: "quiet"})
    notes: list[tuple[str, str]] = []
    shell = PollingShell(
        config_mod.Config(mode="redact").validated(),
        backend=DarwinBackend(pasteboard=board),
        notify=lambda t, b: (notes.append((t, b)), True)[1],
    )
    shell.guard.start()
    board.external_copy({UTI_STRING: PAYLOAD})
    board.clearContents = lambda: (_ for _ in ()).throw(RuntimeError("denied"))  # type: ignore[method-assign]
    shell.guard.monitor.poll_once()

    assert board.stringForType_(UTI_STRING) == PAYLOAD
    title, body = notes[0]
    assert "could not be removed" in title
    assert "removed from" not in title
    assert "still holds" in body


def test_polling_shell_says_when_a_copy_was_only_partly_checked(
    tmp_path, monkeypatch
) -> None:
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    class PartialScan(list):
        incomplete = True
        skipped_rules = ("generic-api-key",)
        truncated = False

    class PartialDetector:
        def scan(self, _text: str) -> PartialScan:
            return PartialScan()

    board = FakePasteboard({UTI_STRING: "quiet"})
    notes: list[tuple[str, str]] = []
    shell = PollingShell(
        config_mod.Config(mode="redact").validated(),
        backend=DarwinBackend(pasteboard=board),
        notify=lambda t, b: (notes.append((t, b)), True)[1],
    )
    shell.guard.start()
    shell.guard.detector = PartialDetector()
    board.external_copy({UTI_STRING: "a very large paste"})
    shell.guard.monitor.poll_once()

    assert board.stringForType_(UTI_STRING) == "a very large paste"
    assert len(notes) == 1
    title, body = notes[0]
    assert "not fully checked" in title and "may still contain a secret" in body


def test_polling_shell_does_not_claim_removal_in_notify_mode(tmp_path, monkeypatch) -> None:
    """In notify mode the clipboard is untouched, so "removed" would be a lie."""
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    board = FakePasteboard({UTI_STRING: "quiet"})
    notes: list[tuple[str, str]] = []
    shell = PollingShell(
        config_mod.Config(mode="notify").validated(),
        backend=DarwinBackend(pasteboard=board),
        notify=lambda t, b: (notes.append((t, b)), True)[1],
    )
    shell.guard.start()
    board.external_copy({UTI_STRING: PAYLOAD})
    shell.guard.monitor.poll_once()

    assert board.stringForType_(UTI_STRING) == PAYLOAD, "notify mode must not modify"
    assert "on the clipboard" in notes[0][0]
    assert "removed" not in notes[0][0]


@pytest.mark.skipif(
    importlib.util.find_spec("gi") is None,
    reason="python3-gi absent, so the Linux backend cannot be constructed here",
)
def test_polling_shell_refuses_a_non_poll_backend(tmp_path, monkeypatch) -> None:
    """Linux's fd-based monitor cannot be driven by a sleep loop; say so clearly."""
    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    with pytest.raises(TypeError, match="poll-driven"):
        PollingShell(
            config_mod.Config().validated(),
            backend=get_backend("linux"),
            notify=lambda _t, _b: True,
        )


def test_a_raising_clipboard_check_does_not_stop_the_shell(
    tmp_path, monkeypatch, caplog
) -> None:
    """One copy that breaks the guard must not end protection for every later one.

    And a fault that recurs on every tick is logged once, not three times a second.
    """
    import logging

    import safepaste.config as config_mod
    import safepaste.shell as shell_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(shell_mod.signal, "signal", lambda *_a: None)

    shell = PollingShell(
        config_mod.Config(mode="redact").validated(),
        backend=DarwinBackend(pasteboard=FakePasteboard({UTI_STRING: "quiet"})),
        interval=0,
        notify=lambda _t, _b: True,
    )
    monkeypatch.setattr(shell, "_attach_platform_extras", lambda: None)
    polls: list[int] = []

    def poll_once() -> None:
        polls.append(1)
        if len(polls) == 4:
            shell.stop()
        raise ValueError("exclusion key is not valid UTF-8")

    monkeypatch.setattr(shell.guard.monitor, "poll_once", poll_once)
    caplog.set_level(logging.ERROR, logger="safepaste.shell")

    assert shell.run() == 0
    assert len(polls) == 4, "the loop kept polling after the first failure"
    assert len(caplog.records) == 1


class _RecordingTray:
    def __init__(self, **_callbacks) -> None:
        self.states: list[tuple[str, bool]] = []

    def start(self) -> bool:
        return True

    def stop(self) -> None:
        pass

    def set_state(self, mode: str, paused: bool) -> None:
        self.states.append((mode, paused))

    def set_alert(self, secrets: int, removed: bool | None = None) -> None:
        pass

    def clear_alert(self) -> None:
        pass


def test_the_tray_stops_saying_paused_when_the_pause_lapses(tmp_path, monkeypatch) -> None:
    import time

    import safepaste.config as config_mod
    from safepaste.shell import PollingShell

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    tray = _RecordingTray()
    backend = DarwinBackend(pasteboard=FakePasteboard({UTI_STRING: "quiet"}))
    monkeypatch.setattr(backend, "tray", lambda **_cb: tray)
    monkeypatch.setattr(backend, "hotkey_binder", lambda on_pressed=None: None)
    shell = PollingShell(
        config_mod.Config(mode="redact").validated(),
        backend=backend,
        notify=lambda _t, _b: True,
    )
    shell._attach_platform_extras()
    shell._set_paused(True, 900)
    assert tray.states[-1] == ("redact", True)

    later = time.monotonic() + 901
    monkeypatch.setattr(time, "monotonic", lambda: later)
    shell.timer.run_due()
    assert tray.states[-1] == ("redact", False)


def test_sleep_timer_fires_due_callbacks_only() -> None:
    from safepaste.shell import _SleepTimer

    timer = _SleepTimer()
    fired: list[str] = []
    timer.schedule(0, lambda: fired.append("now"))
    handle = timer.schedule(3600, lambda: fired.append("later"))
    timer.run_due()
    assert fired == ["now"]

    timer.cancel(handle)
    timer.run_due()
    assert fired == ["now"]


def test_sleep_timer_survives_a_raising_callback() -> None:
    from safepaste.shell import _SleepTimer

    timer = _SleepTimer()
    fired: list[str] = []
    timer.schedule(0, lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    timer.schedule(0, lambda: fired.append("second"))
    timer.run_due()  # must not propagate
    assert fired == ["second"]


def test_service_dispatches_by_platform(monkeypatch) -> None:
    """One command, two shells: importing the wrong one fails outright per platform."""
    import safepaste.service as service

    monkeypatch.setattr(service.sys, "platform", "sunos5")
    assert service.main([]) == 2  # unknown platform, reported not crashed


# ---------------------------------------------------------------------------
# The macOS run loop, status item and hotkey.
#
# AppKit and Carbon are unreachable here, so what is tested is the data: the menu
# structure (which must match the other two platforms) and accelerator translation
# (which is where a config file meets three different key-code conventions).
# ---------------------------------------------------------------------------


def test_accelerator_translates_to_carbon_modifiers() -> None:
    from safepaste.backend.darwin_loop import (
        CARBON_CMD,
        CARBON_CONTROL,
        CARBON_OPTION,
        CARBON_SHIFT,
        parse_accelerator,
    )

    mods, key = parse_accelerator("<Control><Alt>v")
    assert mods & CARBON_CONTROL and mods & CARBON_OPTION
    # macOS key codes are positional: 'v' is 0x09 and bears no relation to the
    # character, unlike Windows where the virtual-key code *is* the ASCII value.
    assert key == 0x09

    assert parse_accelerator("<Shift><Control>a")[0] & CARBON_SHIFT
    assert parse_accelerator("<Command>v")[0] & CARBON_CMD


def test_primary_means_command_on_macos() -> None:
    """<Primary> is GTK's "the platform's main modifier".

    Ctrl on Linux and Windows, Command here -- so one config file gives each
    platform the chord its users expect, rather than Ctrl+Alt+V on a Mac.
    """
    from safepaste.backend.darwin_loop import CARBON_CMD, CARBON_CONTROL, parse_accelerator

    mods, _key = parse_accelerator("<Primary>v")
    assert mods & CARBON_CMD
    assert not mods & CARBON_CONTROL


def test_accelerator_rejects_what_it_cannot_bind() -> None:
    from safepaste.backend.darwin_loop import parse_accelerator

    assert parse_accelerator("v") is None  # bare key: would grab it everywhere
    assert parse_accelerator("<Shift>v") is None  # every capital V, everywhere
    assert parse_accelerator("") is None
    assert parse_accelerator("<Control>") is None
    assert parse_accelerator("<Nonsense>v") is None
    assert parse_accelerator("<Control>F13") is None  # not in the key-code table


def test_the_default_hotkey_is_bindable_here_too() -> None:
    from safepaste.backend.darwin_loop import parse_accelerator
    from safepaste.config import Config

    assert parse_accelerator(Config().safe_paste_hotkey) is not None


def _darwin_tray():
    from safepaste.backend.darwin_loop import RunLoop, Tray

    return Tray(RunLoop())


def test_the_macos_menu_matches_the_other_platforms() -> None:
    tray = _darwin_tray()
    labels = [label for _k, label, _a in tray.build_menu_items() if label]
    for expected in (
        "Sanitise clipboard now",
        "Redact automatically",
        "Pause 15 minutes",
        "Pause 1 hour",
        "Preferences…",
        ABOUT_LABEL,
        QUIT_LABEL,
    ):
        assert expected in labels
    # "Quit SafePaste" used to be a deliberate macOS-only spelling, following
    # Apple's convention of naming the application in Quit. The other two now
    # match it rather than the reverse, so the convention is kept and the
    # wording is shared.
    assert QUIT_LABEL in labels


def test_the_macos_menu_does_not_offer_ask() -> None:
    """With no dialog to ask in, the choice would only ever redact."""
    tray = _darwin_tray()
    modes = [a["mode"] for k, _l, a in tray.build_menu_items() if k == "mode"]
    assert modes == ["redact", "notify", "off"]


def test_exactly_one_mode_is_checked_on_macos() -> None:
    tray = _darwin_tray()
    for mode in ("redact", "notify", "off"):
        tray.set_state(mode, False)
        checked = [a for k, _l, a in tray.build_menu_items() if k == "mode" and a.get("checked")]
        assert len(checked) == 1 and checked[0]["mode"] == mode


def test_macos_status_line_does_not_claim_removal_in_other_modes() -> None:
    tray = _darwin_tray()
    tray.set_state("redact", False)
    tray.set_alert(2)
    assert "removed" in tray.build_menu_items()[0][1]
    tray.set_state("notify", False)
    tray.set_alert(2)
    assert "found" in tray.build_menu_items()[0][1]


def test_macos_status_line_does_not_claim_a_failed_removal() -> None:
    tray = _darwin_tray()
    tray.set_state("redact", False)
    tray.set_alert(1, removed=False)
    assert "found" in tray.build_menu_items()[0][1]
    assert "still on" in tray._tooltip()


def test_macos_symbol_follows_state() -> None:
    tray = _darwin_tray()
    tray.set_state("redact", False)
    assert tray._symbol() == tray.SYMBOL_ACTIVE
    tray.set_state("redact", True)
    assert tray._symbol() == tray.SYMBOL_OFF
    tray.set_state("off", False)
    assert tray._symbol() == tray.SYMBOL_OFF
    tray.set_state("redact", False)
    tray.set_alert(1)
    assert tray._symbol() == tray.SYMBOL_ALERT
    assert "1 secret removed" in tray._tooltip()


def test_macos_menu_actions_resolve() -> None:
    from safepaste.backend.darwin_loop import RunLoop, Tray

    calls: list[tuple] = []
    tray = Tray(
        RunLoop(),
        on_mode=lambda m: calls.append(("mode", m)),
        on_pause=lambda s: calls.append(("pause", s)),
        on_resume=lambda: calls.append(("resume",)),
        on_safe_paste=lambda: calls.append(("safe_paste",)),
        on_preferences=lambda: calls.append(("preferences",)),
        on_about=lambda: calls.append(("about",)),
        on_quit=lambda: calls.append(("quit",)),
    )
    tray.set_state("redact", True)
    for kind, _label, attrs in tray.build_menu_items():
        if kind in ("mode", "action"):
            tray._resolve(kind, attrs)()
    assert ("mode", "redact") in calls and ("pause", 3600) in calls
    assert ("resume",) in calls and ("quit",) in calls
    assert ("about",) in calls


def test_a_run_loop_that_never_started_pumps_harmlessly() -> None:
    from safepaste.backend.darwin_loop import RunLoop

    loop = RunLoop()
    assert loop.ready is False
    assert loop.pump() is True  # must not raise off a Mac


# --- macOS-only regressions ----------------------------------------------
#
# These three need the real AppKit, because each bug lived precisely in the part
# the fake pasteboard cannot stand in for. All three shipped in 0.8.1 and none of
# them was visible to the suite above.

macos_only = pytest.mark.skipif(
    sys.platform != "darwin", reason="needs the real AppKit, not a fake pasteboard"
)


@macos_only
def test_menu_target_class_may_be_built_more_than_once() -> None:
    """An Objective-C class name is a process-wide registration.

    Evaluating the class body twice raises "overriding existing Objective-C
    class". _apply_menu calls this on every refresh, and the raise landed before
    setMenu_, so every refresh after the first silently left the old menu in
    place -- no mode checkmark, no status line, no Resume item.
    """
    from safepaste.backend.darwin_loop import _menu_target_class

    first = _menu_target_class()
    assert _menu_target_class() is first
    assert _menu_target_class() is first


@macos_only
def test_every_refresh_reattaches_the_menu() -> None:
    """The menu must track the guard's state, not freeze at startup."""
    from safepaste.backend.darwin_loop import Tray

    class StubItem:
        def __init__(self) -> None:
            self.menu_obj = None
            self.calls = 0

        def setMenu_(self, menu):  # noqa: N802
            self.menu_obj = menu
            self.calls += 1

        def button(self):
            return None

    class StubLoop:
        ready = True

    tray = Tray(StubLoop())
    tray._item = StubItem()

    tray._refresh()
    tray.set_state("redact", False)
    tray.set_alert(2)
    tray.set_state("notify", False)

    assert tray._item.calls == 4, "a refresh that does not reattach is a frozen menu"

    titles = [
        tray._item.menu_obj.itemAtIndex_(i).title()
        for i in range(tray._item.menu_obj.numberOfItems())
    ]
    checked = [
        tray._item.menu_obj.itemAtIndex_(i).title()
        for i in range(tray._item.menu_obj.numberOfItems())
        if tray._item.menu_obj.itemAtIndex_(i).state()
    ]
    assert "Notify only" in titles
    assert checked == ["Notify only"], "the tick must follow the mode"


@macos_only
def test_pump_dispatches_queued_application_events() -> None:
    """A click on the status item is an NSEvent in NSApplication's queue.

    NSRunLoop.runMode_beforeDate_ services run-loop sources and timers and never
    touches that queue, so the icon drew and every click on it was discarded.
    Only nextEventMatchingMask/sendEvent_ delivers them.

    Asserted against a stub NSApplication rather than the real one on purpose.
    Whether a posted event is *visible* to a peek depends on the run loop having
    turned, which makes "is the queue empty" a timing-dependent signal that
    passes against the bug about as often as it fails. What is not timing
    dependent is whether pump asks the application for its events at all: the
    released implementation never called either method.
    """
    from safepaste.backend.darwin_loop import RunLoop

    class StubApp:
        def __init__(self, queued: int) -> None:
            self.pending = [f"event-{i}" for i in range(queued)]
            self.sent: list[str] = []

        def nextEventMatchingMask_untilDate_inMode_dequeue_(  # noqa: N802
            self, _mask, _until, _mode, dequeue
        ):
            if not (dequeue and self.pending):
                return None
            return self.pending.pop(0)

        def sendEvent_(self, event):  # noqa: N802
            self.sent.append(event)

    loop = RunLoop(slice_seconds=0.01)
    app = StubApp(queued=3)
    loop._app = app
    loop._ok = True

    assert loop.pump() is True
    assert app.sent == ["event-0", "event-1", "event-2"], (
        "pump must drain and dispatch the application's event queue; "
        "servicing the run loop alone discards every click"
    )
    assert app.pending == []


@macos_only
def test_accessibility_trust_does_not_depend_on_applicationservices(monkeypatch) -> None:
    """ApplicationServices is a PyObjC distribution this package does not depend on.

    While _trusted imported it, the import failed on every install that followed
    the declared dependencies, so auto-paste refused forever regardless of what
    the user granted in System Settings. Quartz is a real dependency.
    """
    import Quartz

    monkeypatch.setattr(Quartz, "CGPreflightPostEventAccess", lambda: True)
    assert DarwinInjector().ready is True

    monkeypatch.setattr(Quartz, "CGPreflightPostEventAccess", lambda: False)
    assert DarwinInjector().ready is False
