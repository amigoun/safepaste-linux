"""Startup hardening: swap, core dumps and same-user ptrace.

Nothing here calls the real mlockall. `MCL_FUTURE` applies to every later
allocation in the calling process, so a test that succeeded would lock the whole
pytest run's memory for the rest of the session -- and one that failed would say
nothing about the logic. The syscalls are behind a tiny libc wrapper for exactly
this reason, and every test below hands in a fake.
"""

from __future__ import annotations

import errno
import logging
import pathlib
import sys

import pytest

from safepaste import hardening
from safepaste.hardening import (
    MCL_CURRENT,
    MCL_FUTURE,
    MCL_ONFAULT,
    PR_SET_DUMPABLE,
    Hardening,
    harden,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="no resource module on Windows"
)


class FakeLibc:
    """Records what was asked of libc and returns what the test lines up."""

    def __init__(self, *, prctl_rc: int = 0, mlockall_rc=0, err: int = 0) -> None:
        self.prctl_calls: list[tuple] = []
        self.mlockall_calls: list[int] = []
        self._prctl_rc = prctl_rc
        # An int for every call, or a list to answer differently each time.
        self._mlockall_rc = mlockall_rc
        self._err = err

    def prctl(self, *args: int) -> int:
        self.prctl_calls.append(args)
        return self._prctl_rc

    def mlockall(self, flags: int) -> int:
        self.mlockall_calls.append(flags)
        if isinstance(self._mlockall_rc, list):
            i = min(len(self.mlockall_calls) - 1, len(self._mlockall_rc) - 1)
            return self._mlockall_rc[i]
        return self._mlockall_rc

    def errno(self) -> int:
        return self._err


@pytest.fixture(autouse=True)
def _on_linux(monkeypatch):
    """Default every test to the Linux path; the exceptions say so themselves."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv(hardening.ESCAPE_HATCH, raising=False)


# ---------------------------------------------------------------------------
# the happy path
# ---------------------------------------------------------------------------


def test_all_three_protections_are_applied() -> None:
    libc = FakeLibc()
    report = harden(libc=libc)

    assert report.memory_locked
    assert report.undumpable
    assert libc.prctl_calls == [(PR_SET_DUMPABLE, 0, 0, 0, 0)]
    assert libc.mlockall_calls == [MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT]


def test_on_fault_is_retried_without_it_on_a_pre_4_4_kernel() -> None:
    """MCL_ONFAULT is EINVAL before Linux 4.4; locking still has to happen."""
    libc = FakeLibc(mlockall_rc=[-1, 0], err=errno.EINVAL)
    report = harden(libc=libc)

    assert report.memory_locked
    assert libc.mlockall_calls == [
        MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT,
        MCL_CURRENT | MCL_FUTURE,
    ]


# ---------------------------------------------------------------------------
# degrading, loudly, without taking the daemon down
# ---------------------------------------------------------------------------


def test_a_low_memlock_ceiling_is_named_along_with_the_fix(caplog) -> None:
    libc = FakeLibc(mlockall_rc=-1, err=errno.ENOMEM)
    with caplog.at_level(logging.WARNING):
        report = harden(libc=libc)

    assert not report.memory_locked
    assert report.undumpable, "one failure must not skip the others"
    said = " ".join(r.getMessage() for r in caplog.records)
    assert "RLIMIT_MEMLOCK" in said and "LimitMEMLOCK" in said
    assert "swap" in said or "disk" in said


def test_a_refused_prctl_still_leaves_the_rest_applied(caplog) -> None:
    libc = FakeLibc(prctl_rc=-1, err=errno.EPERM)
    with caplog.at_level(logging.WARNING):
        report = harden(libc=libc)

    assert not report.undumpable
    assert report.memory_locked
    assert any("ptrace" in r.getMessage() for r in caplog.records)


def test_a_libc_without_the_symbols_is_survivable(caplog) -> None:
    class Empty:
        def errno(self) -> int:
            return 0

    with caplog.at_level(logging.WARNING):
        report = harden(libc=Empty())

    assert report == Hardening(core_dumps_off=report.core_dumps_off)
    assert not report.undumpable and not report.memory_locked


# ---------------------------------------------------------------------------
# where it deliberately does less
# ---------------------------------------------------------------------------


def test_the_cli_refuses_dumps_but_does_not_lock_memory() -> None:
    """A process that lives for milliseconds; locking it buys little."""
    libc = FakeLibc()
    report = harden(lock_memory=False, libc=libc)

    assert report.undumpable
    assert not report.memory_locked
    assert libc.mlockall_calls == []


def test_ptrace_refusal_waits_to_be_asked_for(caplog) -> None:
    """The default, because PR_SET_DUMPABLE=0 costs the desktop portal.

    An undumpable process cannot have /proc/self/root opened, and that is how
    xdg-desktop-portal identifies its caller -- so About SafePaste and auto-paste
    both stop working. Measured against a live GNOME 46 session.
    """
    libc = FakeLibc()
    with caplog.at_level(logging.INFO):
        report = harden(refuse_ptrace=False, libc=libc)

    assert libc.prctl_calls == [], "must not touch PR_SET_DUMPABLE unasked"
    assert not report.undumpable
    assert report.memory_locked, "the protections without a downside still apply"
    assert any("refuse_ptrace is off" in r.getMessage() for r in caplog.records)


def test_nothing_linux_specific_is_attempted_elsewhere(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    libc = FakeLibc()
    report = harden(libc=libc)

    assert libc.prctl_calls == [] and libc.mlockall_calls == []
    assert not report.undumpable and not report.memory_locked


def test_the_escape_hatch_skips_everything(monkeypatch, caplog) -> None:
    """Set it to attach a debugger; PR_SET_DUMPABLE=0 otherwise refuses one."""
    monkeypatch.setenv(hardening.ESCAPE_HATCH, "1")
    libc = FakeLibc()
    with caplog.at_level(logging.INFO):
        report = harden(libc=libc)

    assert report == Hardening(ptrace_refusal_asked=False)
    assert libc.prctl_calls == [] and libc.mlockall_calls == []
    assert any(hardening.ESCAPE_HATCH in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# the real setrlimit, which is safe to run here
# ---------------------------------------------------------------------------


@posix_only
def test_core_dumps_are_disabled_on_both_limits() -> None:
    """One-way by design: this pytest process keeps a 0 core limit afterwards.

    That costs nothing and is the property being tested -- an unprivileged
    process cannot raise a hard limit back, so nothing inside SafePaste can
    re-enable dumps after startup.
    """
    import resource

    assert hardening._disable_core_dumps() is True
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


# ---------------------------------------------------------------------------
# the report, and the wiring
# ---------------------------------------------------------------------------


def test_the_report_says_which_way_round_it_went() -> None:
    good = Hardening(core_dumps_off=True, undumpable=True, memory_locked=True).describe()
    assert "POSSIBLE" not in good

    bad = Hardening(ptrace_refusal_asked=True).describe()
    assert bad.count("POSSIBLE") == 2 and "core dumps ON" in bad

    # Not asking is a choice, not a failure, and must not read like one. This
    # is what the shipped default produces.
    default = Hardening(
        core_dumps_off=True, memory_locked=True, ptrace_refusal_asked=False
    ).describe()
    assert "POSSIBLE" not in default and "refuse_ptrace is off" in default


@pytest.fixture
def _restore_package_logger():
    """Undo what `cli._configure_logging` does to the shared logger.

    It clears the `safepaste` logger's handlers, installs its own and sets
    propagate=False -- correct for a command-line process, and global state for
    everyone after it. Leaving it in place made tests/test_privacy.py capture no
    records at all, and that test asserts its capture is not vacuous.
    """
    lg = logging.getLogger("safepaste")
    handlers, level, propagate = lg.handlers[:], lg.level, lg.propagate
    yield
    lg.handlers[:] = handlers
    lg.setLevel(level)
    lg.propagate = propagate


def test_the_cli_hardens_itself(monkeypatch, capsys, _restore_package_logger) -> None:
    from safepaste import cli

    calls: list[dict] = []
    monkeypatch.setattr(
        cli.hardening, "harden", lambda **kw: calls.append(kw) or Hardening()
    )
    cli.main(["rules", "--stats"])
    capsys.readouterr()

    assert calls == [{"lock_memory": False}], "the CLI must not lock its address space"


@pytest.mark.parametrize("module", ["app.py", "daemon.py", "shell.py"])
def test_every_long_lived_entry_point_hardens(module: str) -> None:
    """Read as text rather than imported: app.py and daemon.py need GTK, which
    the macOS and Windows runners deliberately do not install."""
    source = (pathlib.Path(__file__).parent.parent / "safepaste" / module).read_text()
    body = source.split("def main(")[-1]
    assert "hardening.harden(" in body, f"{module} starts without hardening"
    assert "refuse_ptrace=cfg.refuse_ptrace" in body, (
        f"{module} must honour the config switch, not decide for the user"
    )


# ---------------------------------------------------------------------------
# the config switch
# ---------------------------------------------------------------------------


def test_the_default_config_keeps_the_portal_working() -> None:
    from safepaste import config as config_mod

    assert config_mod.Config().validated().refuse_ptrace is False


def test_the_switch_survives_a_save_and_load(tmp_path) -> None:
    from safepaste import config as config_mod

    path = tmp_path / "config.toml"
    config_mod.save(config_mod.Config(refuse_ptrace=True).validated(), path)
    assert "[hardening]" in path.read_text()
    assert config_mod.load(path).refuse_ptrace is True
