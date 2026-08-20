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

import importlib.util

import pytest

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


def test_injector_declines_without_accessibility_permission() -> None:
    """On this machine ApplicationServices is absent, which is the same code path
    as a Mac that has not granted Accessibility: decline, never raise."""
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
    import sys

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

    assert parse_accelerator("<Shift>a")[0] & CARBON_SHIFT
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
        "About SafePaste",
    ):
        assert expected in labels
    # The one deliberate difference: Mac convention names the application in Quit.
    assert "Quit SafePaste" in labels


def test_exactly_one_mode_is_checked_on_macos() -> None:
    from safepaste.config import MODES

    tray = _darwin_tray()
    for mode in MODES:
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
