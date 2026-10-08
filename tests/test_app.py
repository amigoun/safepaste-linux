"""Tests for safepaste.app, the GTK front end. Skipped where GTK cannot load."""

from __future__ import annotations

import pytest

pytest.importorskip("gi", reason="python3-gi not installed; the GTK front end cannot exist")


def test_ask_mode_redacts_because_the_dialog_cannot_ask(tmp_path, monkeypatch) -> None:
    """The dialog says the secrets were removed and offers Restore; in `ask`
    mode the guard left them on the clipboard, under that message."""
    try:
        from safepaste.app import SafePasteApp
    except (ImportError, ValueError) as exc:
        pytest.skip(f"GTK4/libadwaita typelibs not installed: {exc}")
    import safepaste.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    app = SafePasteApp(config_mod.Config(mode="ask").validated())
    assert app.daemon.guard.effective_mode == "redact"
