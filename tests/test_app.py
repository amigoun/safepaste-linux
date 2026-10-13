"""Tests for safepaste.app, the GTK front end. Skipped where GTK cannot load."""

from __future__ import annotations

import pytest

pytest.importorskip("gi", reason="python3-gi not installed; the GTK front end cannot exist")

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    try:
        from safepaste.app import SafePasteApp
    except (ImportError, ValueError) as exc:
        pytest.skip(f"GTK4/libadwaita typelibs not installed: {exc}")
    import safepaste.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    def build(background=False, **cfg):
        app = SafePasteApp(config_mod.Config(**cfg).validated(), background=background)
        sent: list[str] = []
        withdrawn: list[str] = []
        # Unregistered, the app cannot reach the notification service; record
        # what it would have sent instead.
        app.send_notification = lambda id_, _note: sent.append(id_)
        app.withdraw_notification = lambda id_: withdrawn.append(id_)
        return app, sent, withdrawn

    return build


def _detect(app) -> None:
    from safepaste.backend import ClipboardEvent

    guard = app.daemon.guard
    # Nothing here may reach the real desktop's clipboard.
    guard.writer.write = lambda _text: True
    guard.monitor.note_own_write = lambda *_: None
    guard._read_clipboard = lambda: None
    guard.primary = None
    guard.handle(ClipboardEvent.of(f"GITHUB_TOKEN={SECRET}\n"))


def test_ask_mode_redacts_because_the_notice_cannot_ask(make_app) -> None:
    """The notice says the secrets were removed and offers Restore; in `ask`
    mode the guard left them on the clipboard, under that message."""
    app, _, _ = make_app(mode="ask")
    assert app.daemon.guard.effective_mode == "redact"


def test_a_redaction_is_reported_without_a_window(make_app) -> None:
    """The dialog took keyboard focus, and the keys meant for the terminal
    pressed its buttons: Tab, Tab, Enter restored the secret. A notification
    takes no focus."""
    from gi.repository import Gtk

    from safepaste.app import NOTICE_ID

    app, sent, _ = make_app(mode="redact")
    before = len(Gtk.Window.list_toplevels())
    _detect(app)

    assert sent == [NOTICE_ID]
    assert len(Gtk.Window.list_toplevels()) == before


def test_the_notice_buttons_reach_the_guard(make_app) -> None:
    app, _, _ = make_app(mode="redact", restore_timeout_secs=60)
    app._install_actions()
    calls: list[str] = []
    app.daemon.guard.restore_original = lambda: calls.append("restore") or True
    app.daemon.guard.exclude_last_value = lambda: calls.append("exclude") or True

    app.lookup_action("restore-original").activate(None)
    assert calls == ["restore"]

    calls.clear()
    app.lookup_action("not-a-secret").activate(None)
    assert calls == ["exclude", "restore"]

    calls.clear()
    app.lookup_action("dismiss-notice").activate(None)
    assert calls == [], "clicking the notice body must not restore anything"


def test_not_a_secret_without_a_restore_window_only_excludes(make_app) -> None:
    app, sent, _ = make_app(mode="redact", restore_timeout_secs=0)
    app._install_actions()
    calls: list[str] = []
    app.daemon.guard.restore_original = lambda: calls.append("restore") or False
    app.daemon.guard.exclude_last_value = lambda: calls.append("exclude") or True

    app.lookup_action("not-a-secret").activate(None)
    assert calls == ["exclude"]
    assert sent == [], "no 'Could not restore' for a restore nobody offered"


def test_the_notice_is_withdrawn_when_restore_ends(make_app) -> None:
    """Its Restore button stops working then; a warning must stay up."""
    from safepaste.app import ALERT_ID, NOTICE_ID

    app, _, withdrawn = make_app(mode="redact")
    app._on_alert_expired()
    assert withdrawn == [NOTICE_ID]
    assert ALERT_ID != NOTICE_ID


# --- start-up --------------------------------------------------------------


def _record_preferences(app) -> list[int]:
    opened: list[int] = []
    app.show_preferences = lambda: opened.append(1)
    return opened


def test_a_login_start_opens_no_window_and_welcomes_once(make_app) -> None:
    """The unit starts the app at every login. Preferences opened there took the
    keyboard from whatever the user was already typing in."""
    from safepaste.app import WELCOME_ID

    app, sent, _ = make_app(background=True)
    opened = _record_preferences(app)
    app.do_activate()
    assert (opened, sent) == ([], [WELCOME_ID])

    app.do_activate()  # a later launch, from the app grid
    assert opened == [1]

    next_login, sent_again, _ = make_app(background=True)
    _record_preferences(next_login)
    next_login.do_activate()
    assert sent_again == []


def test_an_existing_config_means_no_welcome(make_app, tmp_path) -> None:
    """Someone upgrading has seen SafePaste before."""
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    app, sent, _ = make_app(background=True)
    _record_preferences(app)
    app.do_activate()
    assert sent == []


def test_a_launch_by_hand_opens_preferences(make_app) -> None:
    app, sent, _ = make_app()
    opened = _record_preferences(app)
    app.do_activate()
    assert (opened, sent) == ([1], [])


def test_the_unit_starts_it_in_the_background() -> None:
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    unit = (root / "packaging" / "systemd" / "safepaste.service").read_text()
    assert "\nExecStart=/usr/bin/safepaste-gui --background\n" in unit
    # install.sh rewrites the path; replacing the whole line would drop the flag.
    assert "s|^ExecStart=.*|" not in (root / "install.sh").read_text()


# --- one config, and an open window that follows it ------------------------


def test_an_open_window_follows_the_tray_and_cannot_revert_it(make_app) -> None:
    """A Preferences window keeps its rows. After a tray change it showed the
    old mode, and before the reload fix its next edit wrote the old mode back."""
    from gi.repository import Adw

    import safepaste.config as config_mod
    from safepaste.ui.prefs import SHOWN_MODES, PreferencesWindow

    Adw.init()
    app, _, _ = make_app(mode="redact")
    window = PreferencesWindow(config=app.config, on_changed=app._on_config_changed)
    app._prefs_window = window
    try:
        window.label_rules_row.set_active(True)  # an edit: save, then reload
        app.daemon.set_mode("notify")  # the tray
        assert SHOWN_MODES[window.mode_row.get_selected()] == "notify"

        window.auto_paste_row.set_active(True)  # the next edit
        assert config_mod.load().mode == app.daemon.config.mode == "notify"
        assert app.config is app.daemon.config
    finally:
        app._prefs_window = None
        window.destroy()


def test_nothing_claims_protection_when_it_could_not_start(
    make_app, monkeypatch
) -> None:
    """GApplication activates even after quit() in startup."""
    from gi.repository import Adw

    # GTK's own startup needs a registered application; ours is not.
    monkeypatch.setattr(Adw.Application, "do_startup", lambda _self: None)
    app, sent, _ = make_app(background=True)
    opened = _record_preferences(app)
    app.daemon.start = lambda: False
    app.do_startup()
    app.do_activate()
    assert (opened, sent) == ([], [])
