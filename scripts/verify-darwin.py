#!/usr/bin/env python3
"""End-to-end check of the macOS backend against a real NSPasteboard.

The counterpart to scripts/verify-live.py, which does the same job on Linux. The
whole point is that the unit tests drive a *fake* pasteboard, so they say nothing
about whether the PyObjC calls are right. This does.

Run on a Mac, or on a `macos-latest` CI runner:

    python3 -m pip install pyobjc-framework-Cocoa pyobjc-framework-Quartz regex
    python3 scripts/verify-darwin.py

It saves and restores the pasteboard, and prints lengths and digests only, never
clipboard contents. Exits non-zero if any check fails, so CI can rely on it.
"""

from __future__ import annotations

import logging
import pathlib
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Realistic shape, invented value. Not a documentation placeholder: the upstream
# rule set deliberately allowlists those, so a doc key would be correctly ignored
# and prove nothing.
SECRET = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
PAYLOAD = f"release notes\nGITHUB_TOKEN={SECRET}\nthis line must survive\n"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"\n         {detail}" if detail else ""), flush=True)
    return ok


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="  %(levelname)s %(name)s: %(message)s")

    if sys.platform != "darwin":
        print(f"this check only means anything on macOS (running on {sys.platform})")
        return 77  # distinct from a failure: nothing was verified

    try:
        from AppKit import NSPasteboard  # noqa: F401
    except ImportError as exc:
        print(f"PyObjC missing ({exc});")
        print("  python3 -m pip install pyobjc-framework-Cocoa pyobjc-framework-Quartz")
        return 2

    from safepaste import config as config_mod
    from safepaste.backend import ClipboardEvent
    from safepaste.backend.darwin import (
        UTI_HTML,
        UTI_STRING,
        DarwinBackend,
        DarwinClipboardReader,
        DarwinClipboardWriter,
        DarwinInjector,
        has_rich_representations,
    )
    from safepaste.guard import Guard

    backend = DarwinBackend()
    board = backend._pb()
    reader = DarwinClipboardReader(board)
    writer = DarwinClipboardWriter(board)

    original = reader.read_text()
    print(f"== saved the pasteboard ({len(original.text) if original else 0} chars) ==\n")

    try:
        # --- the primitives ------------------------------------------------
        first = int(board.changeCount())
        check("changeCount is readable", isinstance(first, int), f"count={first}")

        probe = "safepaste-darwin-probe"
        check("write succeeds", writer.write(probe) is True)
        back = reader.read_text()
        check(
            "read-back is byte-identical",
            back is not None and back.text == probe,
            f"{len(back.text) if back else 0} chars",
        )
        check(
            "changeCount moved after our write",
            int(board.changeCount()) > first,
            f"{first} -> {board.changeCount()}",
        )
        check(
            "the event carries the contract type",
            isinstance(back, ClipboardEvent) and back.digest,
            f"flavour={back.flavour if back else '-'}",
        )

        # --- the capability Linux lacks -------------------------------------
        ok = writer.write_flavours(
            {UTI_STRING: "plain here", UTI_HTML: "<b>rich here</b>"}
        )
        plain = board.stringForType_(UTI_STRING)
        html = board.stringForType_(UTI_HTML)
        check(
            "multi-representation write keeps both flavours",
            bool(ok) and plain == "plain here" and html == "<b>rich here</b>",
            "this is what wl-copy cannot do on Linux",
        )
        rich = reader.read_text()
        check(
            "rich content is reported as rich",
            rich is not None and rich.has_rich_flavours is True,
            f"{len(rich.flavours) if rich else 0} representations offered",
        )
        check(
            "UTI classification agrees with the live pasteboard",
            has_rich_representations(list(board.types() or [])) is True,
        )

        # --- monitoring ------------------------------------------------------
        seen: list[ClipboardEvent] = []
        monitor = backend.clipboard_monitor(seen.append)
        check("monitor starts", monitor.start() is True)

        monitor.poll_once()
        check("an unchanged pasteboard is silent", seen == [])

        # Something else copies (simulated by writing without telling the monitor).
        writer.write(PAYLOAD)
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

        # --- the whole pipeline ---------------------------------------------
        tmp = pathlib.Path(tempfile.mkdtemp())
        config_mod.CONFIG_FILE = tmp / "config.toml"
        config_mod.CONFIG_DIR = tmp
        config_mod.RULES_DIR = tmp / "rules"
        guard = Guard(
            config_mod.Config(mode="redact", restore_timeout_secs=120).validated(),
            backend=backend,
        )
        check("guard starts", guard.start() is True)

        writer.write(PAYLOAD)  # an application copies a secret
        guard.monitor.poll_once()

        after = board.stringForType_(UTI_STRING) or ""
        check("the secret is gone from the pasteboard", SECRET not in after)
        check("a placeholder replaced it", "[REDACTED]" in after)
        check(
            "the surrounding text survived",
            "release notes" in after and "this line must survive" in after,
        )
        check(
            "no redaction loop",
            (guard.monitor.poll_once() or True) and SECRET not in (board.stringForType_(UTI_STRING) or ""),
        )
        check("restore returns the original", guard.restore_original() is True)
        check(
            "the original came back intact",
            board.stringForType_(UTI_STRING) == PAYLOAD,
        )
        guard.stop()

        # --- injection is permission-gated, and must decline politely --------
        injector = DarwinInjector()
        trusted = injector.ready
        outcome: list[bool] = []
        injector.paste(outcome.append)
        check(
            "injector reports a result without raising",
            outcome == [trusted],
            f"Accessibility granted: {trusted} (False is expected on a CI runner)",
        )
    finally:
        if original is not None:
            writer.write(original.text)
        else:
            writer.clear()
        restored = reader.read_text()
        same = (original is None and restored is None) or (
            original is not None and restored is not None and restored.text == original.text
        )
        print(f"\n== pasteboard restored: {'yes' if same else 'CHECK MANUALLY'} ==")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
