#!/usr/bin/env python3
"""End-to-end check against the real desktop clipboard.

Unit tests cannot cover the part that actually breaks: whether a change made by
another process is noticed, whether the replacement is visible to other
applications, and whether the daemon avoids reacting to its own writes. This
drives a real daemon against the real clipboard and asserts the observable
behaviour.

It saves your clipboard first and puts it back afterwards, and prints only
lengths and digests — never clipboard contents.

    .venv/bin/python scripts/verify-live.py
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = REPO / ".venv" / "bin" / "python"

# Realistic shape, invented value. Note the upstream ruleset deliberately
# allowlists documentation placeholders (anything ending in EXAMPLE), so a doc
# key would be correctly ignored and prove nothing.
SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = (
    "Release checklist for tomorrow, please review.\n"
    f"GITHUB_TOKEN={SECRET}\n"
    "Everything else in this note should survive untouched.\n"
)

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"\n         {detail}" if detail else ""), flush=True)


def wl_read() -> str:
    # Always bounded. With no clipboard-management protocol on Mutter,
    # wl-clipboard waits for keyboard focus, which a lock screen never grants —
    # an unbounded call here hangs forever rather than failing.
    try:
        out = subprocess.run(
            ["wl-paste", "-n"], capture_output=True, check=False, timeout=6
        ).stdout
    except subprocess.TimeoutExpired:
        return ""
    return out.decode("utf-8", "replace")


def wl_write(text: str) -> None:
    # wl-copy forks into the background and holds its inherited stdout/stderr for
    # as long as it owns the selection. If those are our pipe, the pipe never
    # reaches EOF and anything reading our output hangs. Detach both.
    try:
        subprocess.run(
            ["wl-copy"],
            input=text.encode(),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            timeout=6,
        )
    except subprocess.TimeoutExpired:
        pass


def dbus(method: str, *args: str) -> str:
    cmd = [
        "gdbus", "call", "--session",
        "--dest", "dev.safepaste.Daemon",
        "--object-path", "/dev/safepaste/Daemon",
        "--method", f"dev.safepaste.Daemon.{method}",
        *args,
    ]
    proc = subprocess.run(cmd, capture_output=True, check=False, timeout=10)
    return (proc.stdout or proc.stderr).decode("utf-8", "replace").strip()


def main() -> int:
    for var in ("WAYLAND_DISPLAY", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
        if not os.environ.get(var):
            print(f"missing {var}; run this from inside your desktop session")
            return 2

    # Refuse to run locked, rather than appearing to hang. wl-clipboard blocks
    # in poll() indefinitely while the lock screen holds keyboard focus.
    probe = subprocess.run(
        ["gdbus", "call", "--session", "--dest", "org.gnome.ScreenSaver",
         "--object-path", "/org/gnome/ScreenSaver",
         "--method", "org.gnome.ScreenSaver.GetActive"],
        capture_output=True, check=False, timeout=10)
    if b"true" in probe.stdout.lower():
        print(
            "Your session is locked. wl-clipboard cannot transfer the selection "
            "while\nthe lock screen holds keyboard focus, so this check would hang.\n"
            "Unlock the screen and run it again."
        )
        return 2

    original = wl_read()
    print(f"== saved your clipboard ({len(original)} bytes) ==\n", flush=True)

    tmp = pathlib.Path(tempfile.mkdtemp())
    logfile = tmp / "daemon.log"
    # Isolated config so the run cannot disturb real settings.
    cfg = tmp / "config.toml"
    cfg.write_text(
        '[protection]\nmode = "redact"\nrestore_timeout_secs = 120\n'
        '[input]\nauto_paste = false\n'
    )

    proc = subprocess.Popen(
        [str(PY), "-m", "safepaste.daemon", "-v", "--config", str(cfg)],
        stdout=logfile.open("w"),
        stderr=subprocess.STDOUT,
        cwd=REPO,
    )
    try:
        time.sleep(2.5)  # let the monitor attach and the bus name be taken
        if proc.poll() is not None:
            print(logfile.read_text())
            print("daemon exited early")
            return 1
        check("daemon started and stayed up", True, f"pid {proc.pid}")

        probe = subprocess.run(
            ["gdbus", "call", "--session", "--dest", "dev.safepaste.Daemon",
             "--object-path", "/dev/safepaste/Daemon",
             "--method", "org.freedesktop.DBus.Properties.Get",
             "dev.safepaste.Daemon", "Version"],
            capture_output=True, check=False, timeout=10)
        answer = (probe.stdout or probe.stderr).decode("utf-8", "replace").strip()
        check("D-Bus interface reachable", probe.returncode == 0, answer)

        # --- the main event: a secret arrives from another process -----------
        wl_write(PAYLOAD)
        time.sleep(2.5)
        after = wl_read()
        check(
            "secret removed from the clipboard",
            SECRET not in after,
            f"clipboard now {len(after)} bytes",
        )
        check(
            "placeholder substituted",
            "[REDACTED]" in after,
            repr(after.split("\n")[1][:60]) if "\n" in after else repr(after[:60]),
        )
        check(
            "surrounding text preserved",
            "Release checklist for tomorrow" in after
            and "should survive untouched" in after,
        )

        # --- it must not react to its own write ------------------------------
        log = logfile.read_text()
        detections = log.count("secret(s) on the clipboard")
        check(
            "no redaction loop (exactly one detection)",
            detections == 1,
            f"{detections} detection(s) logged",
        )

        # --- restore, and confirm the restore is not re-redacted -------------
        out = dbus("RestoreOriginal")
        time.sleep(2.0)
        restored = wl_read()
        check("RestoreOriginal returned true", "true" in out.lower(), out)
        check(
            "original value came back intact",
            restored == PAYLOAD,
            f"{len(restored)} bytes vs {len(PAYLOAD)} expected",
        )
        log = logfile.read_text()
        check(
            "restored original was not immediately re-redacted",
            log.count("secret(s) on the clipboard") == 1,
            f"{log.count('secret(s) on the clipboard')} detection(s) after restore",
        )

        # --- privacy invariant on the real log --------------------------------
        check(
            "secret never written to the daemon log",
            SECRET not in log,
            f"log is {len(log)} bytes",
        )

        # --- clean text must not trigger anything -----------------------------
        wl_write("just an ordinary sentence with nothing sensitive in it")
        time.sleep(1.5)
        log2 = logfile.read_text()
        check(
            "benign clipboard produces no detection",
            log2.count("secret(s) on the clipboard") == 1,
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        wl_write(original)
        time.sleep(0.4)
        print(f"\n== clipboard restored: {'yes' if wl_read() == original else 'CHECK MANUALLY'} ==")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("failed:", ", ".join(failed))
        print(f"\ndaemon log at {logfile}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
