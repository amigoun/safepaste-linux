"""Keep a retained secret out of the places it can outlive the process.

*Restore original* holds a pre-redaction clipboard value in memory for the
retention window. Three ordinary events -- none of them a bug in SafePaste --
copy that memory somewhere a later reader can reach:

  1. **swap.** The kernel writes idle pages to a file on disk. Measured on the
     machine this was written on: 16 GB of swap, 15.6 GB of it in use. Not
     theoretical.
  2. **core dumps.** A crash writes the whole address space to a file, and on
     Ubuntu that file goes to apport. The shipped unit sets a soft limit of 0,
     but the *hard* limit is unlimited -- one setrlimit call away from a dump
     with the retained value in it.
  3. **ptrace.** A process running as you attaches and reads the memory. Yama's
     `ptrace_scope=1` refuses an unrelated process; it does not refuse one you
     started yourself, which is the realistic case.

`harden()` refuses the first two at startup, before the first clipboard read.
It never raises: a daemon that cannot lock its memory should still guard the
clipboard, loudly degraded rather than absent.

**The third one is opt-in, and this is why.** `PR_SET_DUMPABLE=0` makes
`/proc/self/root` unreadable, and that is exactly what xdg-desktop-portal opens
to find out who is calling it. Measured against a live GNOME 46 session:

    GDBus.Error:org.freedesktop.DBus.Error.AccessDenied:
    Portal operation not allowed: Unable to open /proc/3784547/root

So an undumpable daemon loses *About SafePaste* -- the item 0.5.2 exists to fix
-- and auto-paste, both of which go through the portal. On Ubuntu the trade is a
poor one: Yama's `ptrace_scope=1` already refuses an attach from anything that is
not an ancestor, so the marginal gain is small and the loss is two visible
features. `refuse_ptrace = true` in `[hardening]` turns it on for anyone whose
kernel has no Yama and who does not want the portal, and the command-line tool
takes it unconditionally because it never speaks to a portal at all.
`mlockall` was measured against the same session and is clean.

**Why the whole process rather than only the retention buffer.** CPython offers
no stable private address for the bytes of a `str`. Every slice, encode and
concat allocates a fresh copy on the ordinary heap, and the same value exists at
the same moment in the reader's buffer and in the X11 property we serve it from.
Locking one object would leave every copy of it swappable -- a comfortable lie
rather than a mitigation. `mlockall(MCL_CURRENT | MCL_FUTURE)` covers all of
them, including the ones a future refactor invents.

**What this does not do.** Hibernation writes RAM to disk whatever is locked.
Root reads any process it likes. Pages that reached swap *before* this ran stay
there until they are touched again. And the value still passes through the
compositor's clipboard bridge, which is another process entirely. This narrows
the window; it does not close the subject.

Set `SAFEPASTE_NO_HARDENING=1` to skip all of it -- for attaching a debugger to
SafePaste itself, which `PR_SET_DUMPABLE=0` otherwise refuses.
"""

from __future__ import annotations

import errno
import logging
import os
import sys
from dataclasses import dataclass

log = logging.getLogger(__name__)

# From <sys/mman.h> and <linux/prctl.h>. ctypes has no header to read, and these
# values are the same across every Linux ABI SafePaste runs on.
MCL_CURRENT = 1
MCL_FUTURE = 2
MCL_ONFAULT = 4  # Linux 4.4+; lock pages as they fault instead of pre-faulting
PR_SET_DUMPABLE = 4

ESCAPE_HATCH = "SAFEPASTE_NO_HARDENING"


@dataclass(frozen=True)
class Hardening:
    """What actually took effect. One log line, and what the tests assert on."""

    core_dumps_off: bool = False
    undumpable: bool = False
    memory_locked: bool = False
    # Distinguishes "asked for and failed" from "deliberately not asked for":
    # only the first is a problem, and only the first should shout.
    ptrace_refusal_asked: bool = True

    def describe(self) -> str:
        # Capitals on the bad side deliberately: a degraded daemon should be
        # readable at a glance in a journal full of ordinary lines.
        if not self.ptrace_refusal_asked:
            ptrace = "allowed (refuse_ptrace is off, so portals keep working)"
        elif self.undumpable:
            ptrace = "refused"
        else:
            ptrace = "POSSIBLE"
        return (
            "memory hardening: swap "
            + ("refused" if self.memory_locked else "POSSIBLE")
            + ", core dumps "
            + ("off" if self.core_dumps_off else "ON")
            + ", same-user ptrace "
            + ptrace
        )


class _Libc:
    """Every ctypes reference lives here, so the logic above stays testable.

    Same shape as the Windows clipboard wrapper: one class that owns the foreign
    calls, injected as an argument everywhere else.
    """

    def __init__(self) -> None:
        import ctypes  # noqa: PLC0415 - deferred so this module imports anywhere
        import ctypes.util

        self._ctypes = ctypes
        self._lib = ctypes.CDLL(
            ctypes.util.find_library("c") or "libc.so.6", use_errno=True
        )
        # prctl is variadic; five ints is what the two options used here take.
        self._lib.prctl.argtypes = [ctypes.c_int] * 5
        self._lib.prctl.restype = ctypes.c_int
        self._lib.mlockall.argtypes = [ctypes.c_int]
        self._lib.mlockall.restype = ctypes.c_int

    def prctl(self, option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
        return int(self._lib.prctl(option, arg2, arg3, arg4, arg5))

    def mlockall(self, flags: int) -> int:
        return int(self._lib.mlockall(flags))

    def errno(self) -> int:
        return int(self._ctypes.get_errno())


def harden(
    *,
    lock_memory: bool = True,
    refuse_ptrace: bool = True,
    libc: object | None = None,
) -> Hardening:
    """Apply what this platform allows, and say plainly what took effect.

    `lock_memory=False` for short-lived processes: the CLI holds a secret for
    milliseconds and locking its whole address space buys little, while a core
    dump of it would still be a file full of secret.

    `refuse_ptrace=False` for anything that talks to a portal -- see the module
    docstring. The daemon takes it from the config and defaults it off; the CLI
    leaves it on because it has no portal to lose.
    """
    if os.environ.get(ESCAPE_HATCH):
        log.info("%s is set: memory hardening skipped entirely", ESCAPE_HATCH)
        return Hardening(ptrace_refusal_asked=False)

    core_dumps_off = _disable_core_dumps()

    if not sys.platform.startswith("linux"):
        # macOS: mlockall needs root and `brew services` runs SafePaste as you;
        # prctl does not exist there at all. Windows: neither, and no resource
        # module either. The core-dump limit above is the portable half.
        log.debug("memory locking and PR_SET_DUMPABLE are Linux-only; skipped")
        return Hardening(
            core_dumps_off=core_dumps_off, ptrace_refusal_asked=refuse_ptrace
        )

    if libc is None:
        try:
            libc = _Libc()
        except (OSError, AttributeError) as exc:  # pragma: no cover - no libc
            log.warning("cannot reach libc (%s); memory hardening skipped", exc)
            return Hardening(
                core_dumps_off=core_dumps_off, ptrace_refusal_asked=refuse_ptrace
            )

    report = Hardening(
        core_dumps_off=core_dumps_off,
        undumpable=_refuse_ptrace_and_dumps(libc) if refuse_ptrace else False,
        memory_locked=_lock_memory(libc) if lock_memory else False,
        ptrace_refusal_asked=refuse_ptrace,
    )
    log.info("%s", report.describe())
    return report


def _disable_core_dumps() -> bool:
    """Soft *and* hard to zero, so nothing in-process can raise it back.

    Lowering a hard limit is one-way for an unprivileged process, which is the
    point: the unit's soft 0 is a default, not a guarantee.
    """
    try:
        import resource  # noqa: PLC0415 - absent on Windows
    except ImportError:
        return False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as exc:
        log.warning(
            "could not disable core dumps (%s); a crash could write the "
            "retained value to disk",
            exc,
        )
        return False
    return True


def _refuse_ptrace_and_dumps(libc) -> bool:
    """PR_SET_DUMPABLE=0 -- no core dump, and no ptrace from the same user."""
    try:
        rc = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (AttributeError, OSError) as exc:  # pragma: no cover - exotic libc
        log.warning("prctl is unavailable (%s); this process stays ptrace-able", exc)
        return False
    if rc != 0:
        log.warning(
            "prctl(PR_SET_DUMPABLE, 0) failed (%s); this process stays ptrace-able",
            os.strerror(libc.errno()),
        )
        return False
    return True


def _lock_memory(libc) -> bool:
    """mlockall, after lifting our own soft ceiling as far as it will go."""
    _raise_memlock_soft_limit()

    flags = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT
    try:
        rc = libc.mlockall(flags)
    except (AttributeError, OSError) as exc:  # pragma: no cover - exotic libc
        log.warning("mlockall is unavailable (%s); memory can reach swap", exc)
        return False

    if rc != 0 and libc.errno() == errno.EINVAL:
        # MCL_ONFAULT needs Linux 4.4. Without it every future mapping is faulted
        # in and locked at once: heavier, still correct.
        rc = libc.mlockall(MCL_CURRENT | MCL_FUTURE)

    if rc != 0:
        err = libc.errno()
        if err == errno.ENOMEM:
            log.warning(
                "cannot lock memory against swap: RLIMIT_MEMLOCK is %s and this "
                "process is already larger. Raise it -- LimitMEMLOCK= in the "
                "systemd unit, or ulimit -l -- or the retained value can be "
                "written to disk",
                _memlock_ceiling(),
            )
        else:
            log.warning(
                "mlockall failed (%s); the retained value can reach swap",
                os.strerror(err),
            )
        return False
    return True


def _raise_memlock_soft_limit() -> None:
    """Take the soft ceiling up to the hard one. Never fatal.

    Costs nothing when they already match, and is the difference between working
    and not on a box whose hard limit is generous but whose soft limit is 8 MiB.
    """
    try:
        import resource  # noqa: PLC0415 - absent on Windows

        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        if soft != hard:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
    except (ImportError, OSError, ValueError) as exc:
        log.debug("leaving RLIMIT_MEMLOCK alone (%s)", exc)


def _memlock_ceiling() -> str:
    """The current ceiling, for the one warning that has to be actionable."""
    try:
        import resource  # noqa: PLC0415 - absent on Windows
    except ImportError:  # pragma: no cover - Windows never reaches this path
        return "unknown"
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except (OSError, ValueError):  # pragma: no cover - defensive
        return "unknown"
    return "unlimited" if soft == resource.RLIM_INFINITY else f"{soft} bytes"
