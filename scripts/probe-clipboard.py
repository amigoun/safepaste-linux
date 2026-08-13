#!/usr/bin/env python3
"""Diagnostic: can we observe clipboard changes on this desktop, and how?

SafePaste's whole monitoring design rests on one question that varies by
compositor: does XFIXES deliver a SetSelectionOwnerNotify on the X11 CLIPBOARD
selection when a *Wayland-native* client takes the selection?

On GNOME/Mutter there is no wlr-data-control protocol, so `wl-paste --watch`
does not work, and an unfocused Wayland client reads an empty clipboard. The
XWayland selection bridge is the only remaining vantage point.

This probe answers it without needing a human to copy anything: `wl-copy` is
itself a Wayland-native client, so driving it is a faithful test of the
Wayland-source case. `xclip -i` provides the X11-source control.

Run it and paste the output into a bug report. It restores your clipboard when
it finishes, and never writes clipboard contents to disk.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import time

try:
    from Xlib import display as xdisplay
    from Xlib.ext import xfixes
except ImportError:
    sys.exit("python-xlib missing: sudo apt install python3-xlib")

SETTLE = 0.6  # seconds to wait for the compositor's selection bridge to catch up


def sh(cmd: list[str], stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    ).stdout


def wl_read() -> bytes:
    return sh(["wl-paste", "-n"])


def x_read() -> bytes:
    return sh(["xclip", "-o", "-selection", "clipboard"])


def wl_write(data: bytes) -> None:
    # wl-copy daemonises to serve the selection; it exits when it loses ownership.
    subprocess.run(["wl-copy"], input=data, stderr=subprocess.DEVNULL)


def x_write(data: bytes) -> None:
    subprocess.run(
        ["xclip", "-i", "-selection", "clipboard"], input=data, stderr=subprocess.DEVNULL
    )


class Watcher:
    """XFIXES watcher on the X11 CLIPBOARD selection.

    Two python-xlib 0.33 traps are encoded here, both of which fail silently:

    1. select_selection_input is bound onto the *Display*, not the Window, unlike
       most Xlib wrappers.
    2. extension_add_subevent registers a dynamically-generated *copy* of the
       event class, so `isinstance(ev, xfixes.SetSelectionOwnerNotify)` is always
       False and quietly drops every event. Match the (type, sub_code) tuple that
       display.extension_event exposes instead.
    """

    def __init__(self) -> None:
        self.d = xdisplay.Display()
        if not self.d.has_extension("XFIXES"):
            sys.exit("XFIXES extension unavailable on this X server")
        self.version = self.d.xfixes_query_version()
        self.clipboard = self.d.get_atom("CLIPBOARD")
        self.d.xfixes_select_selection_input(
            self.d.screen().root,
            self.clipboard,
            xfixes.XFixesSetSelectionOwnerNotifyMask,
        )
        self.d.flush()
        # (type, sub_code) pair, e.g. (86, 0) — see class docstring trap #2.
        self.owner_notify = self.d.extension_event.SetSelectionOwnerNotify

    def _is_owner_notify(self, ev: object) -> bool:
        return (getattr(ev, "type", None), getattr(ev, "sub_code", None)) == tuple(
            self.owner_notify
        )

    def drain(self, timeout: float = 0.0) -> int:
        """Count SetSelectionOwnerNotify events, waiting up to `timeout`.

        The forced next_event() below is load-bearing: python-xlib's
        pending_events() reports only events already decoded into its queue, it
        does not poll the socket. Looping on pending_events() alone therefore
        spins until the deadline and reports nothing, even while events are
        sitting on the wire. select() tells us data is ready; next_event() is
        what actually reads it.
        """
        seen = 0
        deadline = time.monotonic() + timeout
        while True:
            while self.d.pending_events():
                if self._is_owner_notify(self.d.next_event()):
                    seen += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return seen
            if not select.select([self.d.fileno()], [], [], remaining)[0]:
                return seen
            if self._is_owner_notify(self.d.next_event()):
                seen += 1

    def owner(self) -> int:
        own = self.d.get_selection_owner(self.clipboard)
        return getattr(own, "id", 0)


def main() -> int:
    print("== environment ==")
    for k in ("XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY", "DISPLAY"):
        print(f"  {k}={os.environ.get(k, '<unset>')}")

    w = Watcher()
    print(f"  XFIXES version={w.version.major_version}.{w.version.minor_version}")

    original = wl_read()
    print(f"\n== saved your clipboard ({len(original)} bytes, restored at exit) ==")

    results: list[tuple[str, bool, str]] = []
    try:
        w.drain()  # clear anything queued from before we started

        # --- Case 1: Wayland-native source (this is the load-bearing case) ---
        probe = b"safepaste-probe-wayland-source"
        owner_before = w.owner()
        wl_write(probe)
        events = w.drain(SETTLE)
        owner_after = w.owner()
        mirrored = x_read() == probe
        results.append(
            (
                "XFIXES event on Wayland-native copy (wl-copy)",
                events > 0,
                f"{events} event(s); owner {owner_before:#x} -> {owner_after:#x}",
            )
        )
        results.append(
            (
                "Wayland write visible to X11 reader (xclip -o)",
                mirrored,
                "byte-identical" if mirrored else "MISMATCH",
            )
        )

        # --- Case 2: X11 source (control) ---
        probe2 = b"safepaste-probe-x11-source"
        x_write(probe2)
        events2 = w.drain(SETTLE)
        mirrored2 = wl_read() == probe2
        results.append(
            ("XFIXES event on X11 copy (xclip -i)", events2 > 0, f"{events2} event(s)")
        )
        results.append(
            (
                "X11 write visible to Wayland reader (wl-paste)",
                mirrored2,
                "byte-identical" if mirrored2 else "MISMATCH",
            )
        )

        # --- Case 3: repeated Wayland writes each generate an event ---
        counts = []
        for i in range(3):
            wl_write(f"safepaste-probe-repeat-{i}".encode())
            counts.append(w.drain(SETTLE))
        results.append(
            (
                "each subsequent Wayland copy fires exactly once",
                all(c == 1 for c in counts),
                f"per-copy event counts: {counts}",
            )
        )

        # --- Case 4: owner-polling fallback viability ---
        wl_write(b"safepaste-probe-owner-a")
        w.drain(SETTLE)
        owner_a = w.owner()
        wl_write(b"safepaste-probe-owner-b")
        w.drain(SETTLE)
        owner_b = w.owner()
        w.drain()
        results.append(
            (
                "fallback: selection-owner id is readable",
                owner_a != 0 and owner_b != 0,
                f"owner {owner_a:#x} then {owner_b:#x}"
                + (" (stable id -> must hash content)" if owner_a == owner_b else ""),
            )
        )
    finally:
        if original:
            wl_write(original)
        else:
            subprocess.run(["wl-copy", "--clear"], stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        restored = wl_read() == original
        print(f"== clipboard restored: {'yes' if restored else 'NO - check manually'} ==")

    print("\n== results ==")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {detail}")

    critical = results[0][1] and results[1][1] and results[5][1]
    print("\n== verdict ==")
    if results[0][1]:
        print("  XFIXES sees Wayland-native copies -> event-driven monitor is viable.")
    else:
        print("  XFIXES does NOT see Wayland-native copies -> use the polling fallback")
        print("  (compare selection-owner id + content hash).")
    return 0 if critical else 1


if __name__ == "__main__":
    sys.exit(main())
