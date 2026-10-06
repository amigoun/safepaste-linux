"""Policy, tested without a desktop.

Before the platform seam existed, every one of these behaviours could only be
checked by running a real daemon against the real clipboard
(scripts/verify-live.py). That is still worth doing, but it is slow, it needs an
unlocked graphical session, and it cannot easily provoke the failure cases — a
clipboard write that fails is exactly the case that broke in practice and the
hardest to stage for real.
"""

from __future__ import annotations

import hashlib

import pytest

from safepaste.backend import Backend, ClipboardEvent
from safepaste.config import Config, EXCLUSION_KEY_NAME
from safepaste.detector import EXCLUSION_SCHEME, is_keyed_digest
from safepaste.guard import Guard

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore notes\n"


# --- doubles ---------------------------------------------------------------


class FakeWriter:
    def __init__(self, succeed: bool = True, reader: FakeReader | None = None) -> None:
        self.succeed = succeed
        self.writes: list[str] = []
        # Where a successful write becomes visible, as on a real clipboard.
        self.reader = reader

    def write(self, text: str) -> bool:
        self.writes.append(text)
        if self.succeed and self.reader is not None:
            self.reader.event = ClipboardEvent.of(text)
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
        self.reader = FakeReader()
        self.writer = FakeWriter(write_succeeds, self.reader)
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
        guard_kwargs = {
            k: cfg_kwargs.pop(k) for k in ("can_ask", "can_restore") if k in cfg_kwargs
        }
        backend = FakeBackend(**backend_kwargs)
        events: list[tuple] = []
        guard = Guard(
            Config(**cfg_kwargs).validated(),
            backend=backend,
            on_detection=lambda f, r, e: events.append((f, r, e)),
            **guard_kwargs,
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


def test_a_failed_write_is_not_reported_as_a_removal(guard_factory) -> None:
    """The front end words its notice from this; "removed" would be a lie."""
    from safepaste.guard import LEFT, NOT_REMOVED, REMOVED

    guard, _, events = guard_factory(mode="redact", write_succeeds=False)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert events and guard.last_outcome == NOT_REMOVED

    guard, _, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert guard.last_outcome == REMOVED

    guard, _, _ = guard_factory(mode="notify")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert guard.last_outcome == LEFT


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


def test_restore_does_not_overwrite_a_newer_value(guard_factory) -> None:
    """Paused, the guard never sees the next copy; the clipboard still says so."""
    guard, backend, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    backend.reader.event = ClipboardEvent.of("something copied since")
    writes = len(backend.writer.writes)

    assert guard.restore_original() is False
    assert len(backend.writer.writes) == writes, "the newer value must survive"
    assert guard._held is None, "and the secret is not kept for a later attempt"


def test_a_new_copy_drops_the_held_original(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert guard._held is not None

    guard.handle(ClipboardEvent.of("an unrelated, clean copy"))
    assert guard._held is None


def test_a_failed_restore_does_not_excuse_the_secret(guard_factory) -> None:
    """The monitor skips values announced as our own, so announcing the secret
    before a write that then failed would let the next copy of it through."""
    guard, backend, _ = guard_factory(mode="redact", restore_timeout_secs=60)
    guard.handle(ClipboardEvent.of(PAYLOAD))
    backend.writer.succeed = False

    assert guard.restore_original() is False
    assert PAYLOAD not in backend.monitor.own_writes


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


def test_ask_with_nobody_to_ask_runs_as_redact(guard_factory) -> None:
    """A front end with no dialog cannot ask, so leaving the secret would be the
    worst of both: still on the clipboard, and nobody told it needs a decision."""
    guard, backend, events = guard_factory(mode="ask")
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert backend.writer.writes and SECRET not in backend.writer.writes[-1]
    assert guard.effective_mode == "redact"
    assert len(events) == 1


def test_ask_leaves_the_clipboard_to_a_front_end_that_can_ask(guard_factory) -> None:
    guard, backend, events = guard_factory(mode="ask", can_ask=True)
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert backend.writer.writes == []
    assert guard.effective_mode == "ask"
    assert len(events) == 1


def test_no_plaintext_is_held_where_nothing_can_restore_it(guard_factory) -> None:
    """Retention exists for "Restore original"; without that, it is only exposure."""
    guard, backend, _ = guard_factory(
        mode="redact", restore_timeout_secs=60, can_restore=False
    )
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert SECRET not in backend.writer.writes[-1]
    assert guard._held is None
    assert guard.restore_original() is False


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


def test_a_secret_in_a_rich_representation_alone_is_still_removed(guard_factory) -> None:
    """A link's label can be clean while its URL carries the token.

    This writer can offer plain text only, so the redaction replaces the rich
    representation with that rather than leaving it behind.
    """
    guard, backend, events = guard_factory(mode="redact")
    html = f'<a href="https://ci.example/?token={SECRET}">report</a>'
    guard.handle(ClipboardEvent.of("report", representations={"text/html": html}))

    assert backend.writer.writes == ["report"]
    assert len(events) == 1
    _findings, result, _event = events[0]
    assert result.secrets_removed == 1 and "GitHub PAT" in result.labels


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


class _PartialScan(list):
    """What a detector returns when it could not scan the whole input."""

    incomplete = True
    skipped_rules: tuple[str, ...] = ()
    truncated = True


class _PartialDetector:
    def scan(self, _text: str) -> _PartialScan:
        return _PartialScan()


def test_a_partly_scanned_clean_copy_is_reported_not_passed(guard_factory) -> None:
    """Saying nothing would read as "checked and clean", which it was not."""
    guard, backend, events = guard_factory(mode="redact")
    told: list[ClipboardEvent] = []
    guard.on_incomplete = told.append
    guard.detector = _PartialDetector()
    guard.handle(ClipboardEvent.of("a very large paste"))

    assert len(told) == 1
    assert backend.writer.writes == [], "nothing was found, so nothing is redacted"
    assert events == []


def test_a_partly_scanned_representation_is_not_kept(guard_factory) -> None:
    """Its unscanned tail could hold anything, so it cannot be shown clean."""
    guard, _, _ = guard_factory(mode="redact")
    real = guard.detector

    class HtmlPartly:
        def scan(self, text: str):
            found = real.scan(text)
            return _PartialScan(found) if text.startswith("<") else found

    guard.detector = HtmlPartly()
    html = f"<pre>{PAYLOAD}</pre>"
    clean, _ = guard._sanitise(ClipboardEvent.of(PAYLOAD, representations={"text/html": html}))

    assert clean is not None and clean.representations == {}


def test_a_fully_scanned_clean_copy_says_nothing(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact")
    told: list[ClipboardEvent] = []
    guard.on_incomplete = told.append
    guard.handle(ClipboardEvent.of("an entirely ordinary sentence"))
    assert told == []


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


OTHER_SECRET = "ghp_Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8c"


def test_excluding_after_a_safe_paste_excludes_what_it_redacted(guard_factory) -> None:
    """The most recent detection is the safe paste's, not the copy before it."""
    guard, backend, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(f"TOKEN={OTHER_SECRET}"))
    backend.reader.event = ClipboardEvent.of(PAYLOAD)
    assert guard.safe_paste() == 1

    assert guard.exclude_last_value() is True
    assert guard.detector.scan(PAYLOAD) == []
    assert guard.detector.scan(f"TOKEN={OTHER_SECRET}"), "the older value is not excluded"


def test_a_newer_copy_leaves_nothing_to_exclude(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.handle(ClipboardEvent.of("an unrelated, clean copy"))

    assert guard.exclude_last_value() is False
    assert guard.detector.scan(PAYLOAD)


def test_exclusions_store_digests_never_plaintext(guard_factory) -> None:
    guard, _, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.exclude_last_value()

    assert guard.config.excluded_hashes
    for digest in guard.config.excluded_hashes:
        assert is_keyed_digest(digest)
        assert len(digest.split(":", 1)[1]) == 64
        assert SECRET not in digest


def test_the_exclusion_file_gives_nothing_away_without_the_key(
    guard_factory, tmp_path
) -> None:
    """config.toml alone must not confirm a guess at an excluded value.

    A bare SHA-256 would: the reader hashes their candidate and compares. This is
    the leak the keyed digest closes, so it is worth asserting on the bytes that
    actually land on disk rather than on the digest in memory.
    """
    guard, _, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.exclude_last_value()

    written = (tmp_path / "config.toml").read_text()
    assert EXCLUSION_SCHEME in written
    assert SECRET not in written
    assert hashlib.sha256(SECRET.encode("utf-8")).hexdigest() not in written

    key_file = tmp_path / EXCLUSION_KEY_NAME
    assert key_file.exists(), "the key is a file of its own, minted on first use"
    assert key_file.read_text().strip() not in written


def test_a_key_lost_after_an_exclusion_flags_the_value_again(
    guard_factory, tmp_path
) -> None:
    """Losing the key must fail towards protection, not towards silence."""
    guard, backend, _ = guard_factory(mode="redact")
    guard.handle(ClipboardEvent.of(PAYLOAD))
    guard.exclude_last_value()

    (tmp_path / EXCLUSION_KEY_NAME).unlink()
    reborn, reborn_backend, _ = guard_factory(
        mode="redact", excluded_hashes=guard.config.excluded_hashes
    )
    reborn.handle(ClipboardEvent.of(PAYLOAD))
    assert reborn_backend.writer.writes, "with no key to check against, flag it"


def test_a_key_that_cannot_be_written_still_leaves_us_protected(
    guard_factory, monkeypatch
) -> None:
    """Minting the key is file I/O on the detection path. It must not be fatal."""
    import safepaste.config as config_mod

    guard, backend, _ = guard_factory(mode="redact")
    monkeypatch.setattr(
        config_mod,
        "ensure_exclusion_key",
        lambda *a, **k: (_ for _ in ()).throw(OSError("read-only file system")),
    )

    guard.handle(ClipboardEvent.of(PAYLOAD))
    assert backend.writer.writes, "the redaction is what matters; it still happened"
    assert guard.exclude_last_value() is False, "no key, so nothing to exclude with"


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


# --- redaction style reaches the redactor ---------------------------------


def test_kept_edges_are_configurable_and_reach_the_clipboard(guard_factory) -> None:
    """[redaction] keep_prefix/keep_suffix must survive the trip to the writer.

    Worth pinning at this level rather than only in test_redactor: the style is
    assembled in Guard.redaction_style, so a field added to RedactionStyle and
    to Config but not wired through here would pass every redactor test and
    still put the old text on the clipboard.
    """
    guard, backend, _ = guard_factory(keep_prefix=4, keep_suffix=4)
    guard.start()
    guard.handle(ClipboardEvent.of(PAYLOAD))

    written = backend.writer.writes[-1]
    assert f"{SECRET[:4]}…[REDACTED]…{SECRET[-4:]}" in written
    assert SECRET not in written
    assert SECRET[4:-4] not in written


def test_zero_edges_restore_whole_value_replacement(guard_factory) -> None:
    guard, backend, _ = guard_factory(keep_prefix=0, keep_suffix=0)
    guard.start()
    guard.handle(ClipboardEvent.of(PAYLOAD))

    assert "GITHUB_TOKEN=[REDACTED]" in backend.writer.writes[-1]


def test_a_negative_edge_count_is_clamped_not_honoured(guard_factory) -> None:
    """A negative slice index would count from the end and leak the tail."""
    guard, backend, _ = guard_factory(keep_prefix=-3, keep_suffix=-3)
    guard.start()
    guard.handle(ClipboardEvent.of(PAYLOAD))

    written = backend.writer.writes[-1]
    assert "GITHUB_TOKEN=[REDACTED]" in written
    assert SECRET not in written


def test_a_custom_placeholder_reaches_the_detector(guard_factory) -> None:
    """Config's placeholder must reach detection, not only redaction.

    Wiring it into RedactionStyle alone would leave the detector looking for
    "[REDACTED]" in text that now says something else, so a user who changed
    the placeholder would get their own sanitised clipboard flagged straight
    back at them -- the exact bug this fixes, reintroduced for anyone who
    customised it.
    """
    guard, backend, _ = guard_factory(placeholder="<<HIDDEN>>")
    guard.start()
    guard.handle(ClipboardEvent.of(PAYLOAD))

    written = backend.writer.writes[-1]
    assert "<<HIDDEN>>" in written
    assert guard.detector.scan(written) == [], "the guard flags its own output"
