"""Policy, tested without a desktop.

Before the platform seam existed, every one of these behaviours could only be
checked by running a real daemon against the real clipboard
(scripts/verify-live.py). That is still worth doing, but it is slow, it needs an
unlocked graphical session, and it cannot easily provoke the failure cases — a
clipboard write that fails is exactly the case that broke in practice and the
hardest to stage for real.
"""

from __future__ import annotations

import pytest

from safepaste.backend import Backend, ClipboardEvent
from safepaste.config import Config
from safepaste.guard import Guard

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore notes\n"


# --- doubles ---------------------------------------------------------------


class FakeWriter:
    def __init__(self, succeed: bool = True) -> None:
        self.succeed = succeed
        self.writes: list[str] = []

    def write(self, text: str) -> bool:
        self.writes.append(text)
        return self.succeed

    def clear(self) -> bool:
        return True


class FakeReader:
    def __init__(self, event: ClipboardEvent | None = None) -> None:
        self.event = event

    def read_text(self) -> ClipboardEvent | None:
        return self.event


class FakeMonitor:
    def __init__(self, on_change, reader: FakeReader) -> None:
        self.on_change = on_change
        self.reader = reader
        self.own_writes: list[str] = []
        self.started = False

    def start(self) -> bool:
        self.started = True
        return True

    def stop(self) -> None:
        self.started = False

    def note_own_write(self, text: str) -> None:
        self.own_writes.append(text)


class FakeLocks:
    def __init__(self, locked: bool = False) -> None:
        self.locked = locked

    def start(self) -> bool:
        return True

    def refresh(self) -> bool:
        return self.locked


class FakeBackend(Backend):
    """A platform that does nothing but record what was asked of it."""

    name = "fake"

    def __init__(self, *, write_succeeds: bool = True, locked: bool = False) -> None:
        self.writer = FakeWriter(write_succeeds)
        self.reader = FakeReader()
        self.monitor: FakeMonitor | None = None
        self.locks = FakeLocks(locked)

    def clipboard_writer(self):
        return self.writer

    def clipboard_monitor(self, on_change):
        self.monitor = FakeMonitor(on_change, self.reader)
        return self.monitor

    def lock_watcher(self):
        return self.locks


@pytest.fixture
def guard_factory(tmp_path, monkeypatch):
    """Build a Guard whose config writes land in tmp_path, never the real home."""
    import safepaste.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    def build(**cfg_kwargs):
        backend_kwargs = {
            k: cfg_kwargs.pop(k)
            for k in ("write_succeeds", "locked")
            if k in cfg_kwargs
        }
        backend = FakeBackend(**backend_kwargs)
        events: list[tuple] = []
        guard = Guard(
            Config(**cfg_kwargs).validated(),
            backend=backend,
            on_detection=lambda f, r, e: events.append((f, r, e)),
        )
        return guard, backend, events

    return build


# --- the fail-safe ordering ------------------------------------------------


def test_clipboard_is_replaced_before_the_user_is_told(guard_factory) -> None:
    """The whole safety argument: redact first, notify second.

    If the notification came first, the raw secret would sit on the clipboard for
    exactly as long as the user took to read it.
    """
    guard, backend, events = guard_factory(mode="redact")
    order: list[str] = []
    backend.writer.write = lambda text: (order.append("write"), True)[1]  # type: ignore[method-assign]
    guard.on_detection = lambda *_: order.append("notify")

    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert order == ["write", "notify"], "the user must never be asked before the swap"


def test_only_the_secret_is_replaced(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))

    written = backend.writer.writes[-1]
    assert SECRET not in written
    assert "[REDACTED]" in written
    assert written.startswith("notes\n") and written.endswith("more notes\n")


def test_a_failed_write_does_not_pretend_to_hold_an_original(guard_factory) -> None:
    """Regression: a write that silently 'succeeded' broke the undo in practice.

    wl-copy daemonises and holds its inherited stdout, so capture_output made
    subprocess.run block until timeout and report failure *after* the write had
    actually landed. Restore then had nothing to offer. Whatever the platform, if
    write() reports failure the guard must not claim an original is retained.
    """
    guard, _, _ = guard_factory(mode="redact", write_succeeds=False)
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert guard.restore_original() is False


def test_successful_write_retains_a_restorable_original(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert guard.restore_original() is True
    assert backend.writer.writes[-1] == PAYLOAD


def test_restoring_is_announced_as_our_own_write(guard_factory) -> None:
    """Otherwise the restore is instantly re-redacted and the button looks broken."""
    guard, backend, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.restore_original()

    assert PAYLOAD in backend.monitor.own_writes


def test_the_original_can_only_be_restored_once(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert guard.restore_original() is True
    assert guard.restore_original() is False


def test_zero_retention_means_no_undo_at_all(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact", restore_timeout_secs=0)
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert SECRET not in backend.writer.writes[-1]  # still protected
    assert guard.restore_original() is False  # but nothing retained


def test_an_expired_original_is_not_restored(guard_factory, monkeypatch) -> None:
    guard, _, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))

    import safepaste.guard as guard_mod

    later = guard_mod.time.monotonic() + 3600
    monkeypatch.setattr(guard_mod.time, "monotonic", lambda: later)
    assert guard.restore_original() is False


def test_forgetting_drops_the_retained_plaintext(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    held = guard._held
    assert held is not None and SECRET in held.text

    guard.forget_original()
    assert guard._held is None
    assert SECRET not in held.text, "the retained copy should be cleared, not merely dropped"


# --- modes and gating -----------------------------------------------------


def test_notify_mode_leaves_the_clipboard_alone(guard_factory) -> None:
    guard, backend, events = guard_factory(mode="notify")
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert backend.writer.writes == [], "notify mode must not modify the clipboard"
    assert len(events) == 1, "but it must still report the detection"


def test_off_mode_does_nothing_at_all(guard_factory) -> None:
    guard, backend, events = guard_factory(mode="off")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert backend.writer.writes == []
    assert events == []


def test_pausing_suppresses_everything_until_it_lapses(guard_factory) -> None:
    guard, backend, events = guard_factory(mode="redact")
    guard.set_paused(True, 900)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert backend.writer.writes == [] and events == []

    guard.set_paused(False)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert backend.writer.writes and events


def test_a_locked_session_is_skipped(guard_factory) -> None:
    """On GNOME/Wayland a clipboard call would block until timeout while locked."""
    guard, backend, events = guard_factory(mode="redact", locked=True)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert backend.writer.writes == [] and events == []


def test_clean_text_is_left_untouched(guard_factory) -> None:
    guard, backend, events = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of("an entirely ordinary sentence"))
    assert backend.writer.writes == [] and events == []
    assert guard.last_finding_count == 0


def test_a_backend_without_a_lock_watcher_still_works(guard_factory) -> None:
    """`lock_watcher()` is optional; None must read as 'not locked'."""
    guard, backend, _ = guard_factory(mode="redact")
    guard.locks = None
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert SECRET not in backend.writer.writes[-1]


# --- on-demand path -------------------------------------------------------


def test_safe_paste_sanitises_the_current_clipboard(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact")
    backend.reader.event = ClipboardEvent.of(PAYLOAD)

    assert guard.safe_paste() == 1
    assert SECRET not in backend.writer.writes[-1]


def test_safe_paste_on_clean_text_writes_nothing(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact")
    backend.reader.event = ClipboardEvent.of("nothing to see")
    assert guard.safe_paste() == 0
    assert backend.writer.writes == []


def test_safe_paste_with_an_empty_clipboard_is_harmless(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact")
    backend.reader.event = None
    assert guard.safe_paste() == 0


def test_safe_paste_refuses_while_locked(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact", locked=True)
    backend.reader.event = ClipboardEvent.of(PAYLOAD)
    assert guard.safe_paste() == 0
    assert backend.writer.writes == []


# --- exclusions -----------------------------------------------------------


def test_excluding_the_last_value_stops_it_being_flagged(guard_factory) -> None:
    guard, backend, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert guard.exclude_last_value() is True

    before = len(backend.writer.writes)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert len(backend.writer.writes) == before, "the excluded value must be ignored now"


def test_exclusions_store_digests_never_plaintext(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.exclude_last_value()

    for digest in guard.config.excluded_hashes:
        assert len(digest) == 64
        assert SECRET not in digest


def test_excluding_with_nothing_detected_is_a_no_op(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact")
    assert guard.exclude_last_value() is False


# --- reading a value we are serving ourselves ------------------------------
#
# On Linux the writer can hold the clipboard itself and answer conversion
# requests from the main loop. Anything that blocks that loop waiting for an
# answer waits for itself. These pin the two places that must not.


class OwningWriter(FakeWriter):
    """A writer that holds the clipboard, as the X11 selection owner does."""

    def __init__(self, succeed: bool = True) -> None:
        super().__init__(succeed)
        self.held: str | None = None
        self.owns_queries = 0

    def write(self, text: str) -> bool:
        ok = super().write(text)
        if ok:
            self.held = text
        return ok

    def owns_clipboard(self) -> bool:
        self.owns_queries += 1
        return self.held is not None

    def current_text(self) -> str | None:
        return self.held


def test_no_clipboard_read_while_we_are_serving_the_value(guard_factory) -> None:
    """Reading here would block the loop that has to answer the read."""
    guard, backend, _ = guard_factory()
    owning = OwningWriter()
    guard.writer = owning
    assert guard._wants_clipboard() is True, "nothing held yet, so reading is fine"
    owning.write("something we now serve")
    assert guard._wants_clipboard() is False
    assert owning.owns_queries > 0


def test_a_value_we_serve_is_read_from_the_writer_not_the_x_server(
    guard_factory,
) -> None:
    guard, backend, _ = guard_factory()
    owning = OwningWriter()
    guard.writer = owning
    backend.reader.event = ClipboardEvent.of("what the X server would say")
    owning.write("what we are actually serving")
    event = guard._read_clipboard()
    assert event is not None
    assert event.text == "what we are actually serving"


def test_safe_paste_on_a_restored_original_still_finds_the_secret(
    guard_factory,
) -> None:
    """The case that makes the held value load-bearing rather than an optimisation.

    "Restore original" puts the secret back, and we are the ones serving it. If
    safe_paste read through the X server it would deadlock; if it skipped the
    read because we own the clipboard it would report a clean clipboard. It has
    to ask the writer what it is holding.
    """
    guard, backend, _ = guard_factory()
    owning = OwningWriter()
    guard.writer = owning
    backend.reader.event = None  # the X server would answer nothing, or hang
    owning.write(PAYLOAD)  # the restored original, secret and all
    assert guard.safe_paste() > 0, "the secret in the restored original must be found"
    assert SECRET not in owning.held
    assert "REDACTED" in owning.held


def test_a_writer_that_holds_nothing_still_reads_normally(guard_factory) -> None:
    """The macOS and Windows writers have no such notion; nothing may assume it."""
    guard, backend, _ = guard_factory()
    backend.reader.event = ClipboardEvent.of(PAYLOAD)
    assert guard._wants_clipboard() is True
    event = guard._read_clipboard()
    assert event is not None and event.text == PAYLOAD
