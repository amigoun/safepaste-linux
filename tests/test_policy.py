"""Per-application policy.

The feature that is possible on Windows and macOS and impossible on GNOME, because
org.gnome.Shell.Introspect refuses to name the focused window. Everything here is
portable, so it is tested properly rather than left to a CI runner.

Note what it applies to today: the on-demand path, which is the one place that
already knows where a paste is going. Automatic interception at Ctrl+V needs a
keyboard hook and comes separately.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from safepaste import config as config_mod
from safepaste.backend import Backend, ClipboardEvent
from safepaste.guard import Guard

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"notes\nGITHUB_TOKEN={SECRET}\nmore\n"


# --- resolution ------------------------------------------------------------


def _cfg(**kwargs) -> config_mod.Config:
    return config_mod.Config(**kwargs).validated()


def test_unknown_target_falls_back_to_the_global_mode() -> None:
    """What makes this safe to consult unconditionally.

    A platform that cannot identify the target passes None, and every lookup then
    returns the global mode -- so the same code path works on GNOME, where the
    answer is permanently unknowable.
    """
    cfg = _cfg(mode="redact", app_modes=(("1password.exe", "off"),))
    assert cfg.app_mode(None) == "redact"
    assert cfg.app_mode("") == "redact"
    assert cfg.app_mode("firefox.exe") == "redact"


def test_a_matching_rule_overrides_the_global_mode() -> None:
    cfg = _cfg(mode="redact", app_modes=(("1password.exe", "off"),))
    assert cfg.app_mode("1password.exe") == "off"


def test_matching_ignores_case() -> None:
    """Neither Windows executables nor macOS bundle ids are case-consistent."""
    cfg = _cfg(mode="redact", app_modes=(("1Password.exe", "off"),))
    for spelling in ("1password.exe", "1PASSWORD.EXE", "1Password.EXE"):
        assert cfg.app_mode(spelling) == "off"


def test_bundle_identifiers_work_as_identities() -> None:
    cfg = _cfg(
        mode="redact",
        app_modes=(("com.agilebits.onepassword7", "off"), ("com.google.chrome", "ask")),
    )
    assert cfg.app_mode("com.agilebits.onepassword7") == "off"
    assert cfg.app_mode("com.google.Chrome") == "ask"


def test_an_unknown_mode_is_rejected_with_a_warning() -> None:
    """A typo in a hand-edited policy must not silently apply something else."""
    cfg = _cfg(mode="redact", app_modes=(("a.exe", "nonsense"), ("b.exe", "off")))
    assert cfg.app_modes == (("b.exe", "off"),)
    assert any("nonsense" in w for w in cfg._warnings)
    # And the rejected entry falls back to the global mode rather than to "off".
    assert cfg.app_mode("a.exe") == "redact"


def test_blank_identities_are_dropped() -> None:
    cfg = _cfg(app_modes=((" ", "off"), ("real.exe", "off")))
    assert cfg.app_modes == (("real.exe", "off"),)


# --- persistence -----------------------------------------------------------


def test_policy_survives_a_config_round_trip() -> None:
    path = pathlib.Path(tempfile.mkdtemp()) / "config.toml"
    cfg = _cfg(mode="redact", app_modes=(("1Password.exe", "off"), ("firefox.exe", "ask")))
    config_mod.save(cfg, path)

    text = path.read_text()
    assert "[policy]" in text
    assert '"1Password.exe" = "off"' in text

    back = config_mod.load(path)
    assert back.app_modes == (("1Password.exe", "off"), ("firefox.exe", "ask"))
    assert back.app_mode("1password.exe") == "off"


def test_no_policy_section_is_written_when_there_is_none() -> None:
    """An empty section would invite confusion about whether the feature exists."""
    path = pathlib.Path(tempfile.mkdtemp()) / "config.toml"
    config_mod.save(_cfg(), path)
    assert "[policy]" not in path.read_text()


def test_a_hand_written_policy_section_is_read() -> None:
    path = pathlib.Path(tempfile.mkdtemp()) / "config.toml"
    path.write_text(
        '[protection]\nmode = "redact"\n\n'
        '[policy]\n"1password.exe" = "off"\n"code.exe" = "notify"\n'
    )
    cfg = config_mod.load(path)
    assert cfg.app_mode("1password.exe") == "off"
    assert cfg.app_mode("code.exe") == "notify"


# --- behaviour through Guard ----------------------------------------------


class _Reader:
    def __init__(self) -> None:
        self.event = ClipboardEvent.of(PAYLOAD)

    def read_text(self) -> ClipboardEvent | None:
        return self.event


class _Monitor:
    def __init__(self, on_change) -> None:
        self.on_change = on_change
        self.reader = _Reader()
        self.should_read = None

    def start(self) -> bool:
        return True

    def stop(self) -> None:
        pass

    def note_own_write(self, text: str) -> None:
        pass


class _Writer:
    def __init__(self) -> None:
        self.writes: list[str] = []

    def write(self, text: str) -> bool:
        self.writes.append(text)
        return True

    def clear(self) -> bool:
        return True


class _Backend(Backend):
    name = "fake"

    def __init__(self, identity: str | None) -> None:
        self.identity = identity
        self.writer = _Writer()

    def clipboard_monitor(self, on_change):
        return _Monitor(on_change)

    def clipboard_writer(self):
        return self.writer

    def foreground_app(self) -> str | None:
        return self.identity


@pytest.fixture
def guard_for(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")

    def build(identity, **cfg_kwargs):
        backend = _Backend(identity)
        guard = Guard(_cfg(**cfg_kwargs), backend=backend)
        guard.start()
        return guard, backend

    return build


def test_target_mode_reports_the_resolved_mode_and_identity(guard_for) -> None:
    guard, _ = guard_for("1password.exe", mode="redact",
                         app_modes=(("1password.exe", "off"),))
    assert guard.target_mode() == ("off", "1password.exe")


def test_the_shortcut_does_nothing_where_policy_says_off(guard_for) -> None:
    """Pressing the shortcut inside a password manager should be a no-op.

    The whole point of the feature: the clipboard is left exactly as it was.
    """
    guard, backend = guard_for("1password.exe", mode="redact",
                               app_modes=(("1password.exe", "off"),))
    assert guard.safe_paste() == 0
    assert backend.writer.writes == []


def test_the_shortcut_still_works_elsewhere(guard_for) -> None:
    guard, backend = guard_for("firefox.exe", mode="redact",
                               app_modes=(("1password.exe", "off"),))
    assert guard.safe_paste() == 1
    assert SECRET not in backend.writer.writes[-1]


def test_an_unidentifiable_target_uses_the_global_mode(guard_for) -> None:
    """The permanent situation on GNOME, and it must simply work."""
    guard, backend = guard_for(None, mode="redact",
                               app_modes=(("1password.exe", "off"),))
    assert guard.safe_paste() == 1
    assert SECRET not in backend.writer.writes[-1]
