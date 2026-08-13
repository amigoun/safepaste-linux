#!/usr/bin/env python3
"""End-to-end check of the Windows backend against the real Win32 clipboard.

The counterpart to scripts/verify-darwin.py and scripts/verify-live.py. The unit
tests drive a *fake* clipboard, so they say nothing about whether the ctypes calls
are right — and the thing most likely to be wrong here is timing behaviour around
the clipboard's global exclusive lock, which no amount of reading the documentation
settles.

    python -m pip install regex
    python scripts/verify-windows.py

Saves and restores the clipboard; prints lengths and digests only, never contents.
Exits non-zero on failure so CI can rely on it, and 77 if it is not on Windows —
so it cannot silently verify nothing.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"release notes\nGITHUB_TOKEN={SECRET}\nthis line must survive\n"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"\n         {detail}" if detail else ""), flush=True)
    return ok


def main() -> int:
    if sys.platform != "win32":
        print(f"this check only means anything on Windows (running on {sys.platform})")
        return 77

    from safepaste import config as config_mod
    from safepaste.backend import ClipboardEvent
    from safepaste.backend.windows import (
        CF_LOCALE,
        CF_UNICODETEXT,
        WindowsBackend,
        WindowsClipboardReader,
        WindowsClipboardWriter,
        WindowsInjector,
        has_rich_formats,
        _real_clipboard,
    )
    from safepaste.guard import Guard

    api = _real_clipboard()
    reader = WindowsClipboardReader(api)
    writer = WindowsClipboardWriter(api)
    backend = WindowsBackend(api=api)

    original = reader.read_text()
    print(f"== saved the clipboard ({len(original.text) if original else 0} chars) ==\n")

    try:
        first = api.sequence_number()
        check("sequence number is readable", isinstance(first, int), f"seq={first}")

        probe = "safepaste-windows-probe"
        check("write succeeds", writer.write(probe) is True)
        back = reader.read_text()
        check(
            "read-back is byte-identical",
            back is not None and back.text == probe,
            f"{len(back.text) if back else 0} chars",
        )
        check(
            "sequence number moved after our write",
            api.sequence_number() > first,
            f"{first} -> {api.sequence_number()}",
        )
        check(
            "the event carries the contract type",
            isinstance(back, ClipboardEvent) and bool(back.digest),
            f"flavour={back.flavour if back else '-'}",
        )

        # Unicode must survive the GlobalAlloc/memmove round trip: the size
        # calculation is in wide chars, and getting it wrong truncates.
        unicode_probe = "naïve — 日本語 — 🔐 tail"
        writer.write(unicode_probe)
        got = reader.read_text()
        check(
            "non-ASCII survives the wide-char round trip",
            got is not None and got.text == unicode_probe,
            f"{len(unicode_probe)} chars in, {len(got.text) if got else 0} out",
        )

        # CF_LOCALE is synthesised by Windows next to any text; counting it as
        # rich would make every plain copy claim it had formatting.
        writer.write("plain text only")
        fresh = reader.read_text()
        formats = [int(f) for f in (fresh.flavours if fresh else ())]
        check(
            "plain text is not misreported as rich",
            fresh is not None and fresh.has_rich_flavours is False,
            f"formats offered: {formats} (CF_UNICODETEXT={CF_UNICODETEXT}, CF_LOCALE={CF_LOCALE})",
        )
        check(
            "format classification agrees with the live clipboard",
            has_rich_formats(formats) is False,
        )

        # --- monitoring ----------------------------------------------------
        seen: list[ClipboardEvent] = []
        monitor = backend.clipboard_monitor(seen.append)
        check("monitor starts", monitor.start() is True)
        monitor.poll_once()
        check("an unchanged clipboard is silent", seen == [])

        writer.write(PAYLOAD)  # stand in for another application copying
        monitor.poll_once()
        check(
            "an external change is detected exactly once",
            len(seen) == 1 and seen[0].text == PAYLOAD,
            f"{len(seen)} event(s)",
        )

        monitor.note_own_write("our own value")
        writer.write("our own value")
        before = len(seen)
        monitor.poll_once()
        check(
            "our own write is not reported back",
            len(seen) == before,
            "otherwise a redaction is rescanned and an undo is re-redacted",
        )

        # --- the whole pipeline --------------------------------------------
        tmp = pathlib.Path(tempfile.mkdtemp())
        config_mod.CONFIG_FILE = tmp / "config.toml"
        config_mod.CONFIG_DIR = tmp
        config_mod.RULES_DIR = tmp / "rules"
        guard = Guard(
            config_mod.Config(mode="redact", restore_timeout_secs=120).validated(),
            backend=backend,
        )
        check("guard starts", guard.start() is True)

        writer.write(PAYLOAD)
        guard.monitor.poll_once()
        after = reader.read_text()
        after_text = after.text if after else ""
        check("the secret is gone from the clipboard", SECRET not in after_text)
        check("a placeholder replaced it", "[REDACTED]" in after_text)
        check(
            "the surrounding text survived",
            "release notes" in after_text and "this line must survive" in after_text,
        )
        guard.monitor.poll_once()
        still = reader.read_text()
        check("no redaction loop", still is not None and SECRET not in still.text)
        check("restore returns the original", guard.restore_original() is True)
        restored = reader.read_text()
        check(
            "the original came back intact",
            restored is not None and restored.text == PAYLOAD,
        )
        guard.stop()

        # --- injection ------------------------------------------------------
        # SendInput needs no permission, so this should genuinely succeed. It types
        # into whatever has focus, which on a CI runner is nothing.
        outcome: list[bool] = []
        WindowsInjector().paste(outcome.append)
        check("SendInput reports a result without raising", len(outcome) == 1,
              f"delivered={outcome[0] if outcome else '-'}")
    finally:
        if original is not None:
            writer.write(original.text)
        else:
            writer.clear()
        restored = reader.read_text()
        same = (original is None and restored is None) or (
            original is not None and restored is not None and restored.text == original.text
        )
        print(f"\n== clipboard restored: {'yes' if same else 'CHECK MANUALLY'} ==")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
