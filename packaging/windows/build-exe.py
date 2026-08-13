#!/usr/bin/env python3
"""Build standalone Windows executables with PyInstaller.

Two of them, because they want opposite console behaviour:

    safepaste.exe          console. A CLI whose output is the point.
    safepaste-daemon.exe   windowed. A background service; a console window
                           appearing at login would be a bug.

The interesting risk is not the build, it is the *data*. The detector is useless
without safepaste/detector/data/*.toml, and a bundle that omits them still starts,
still exits zero, and silently finds nothing — the worst possible failure for a tool
whose job is catching secrets. So the build asserts the files are collected, and CI
additionally runs the built exe and checks the rule count.

Deliberately unsigned. A signing certificate costs a few hundred a year and Scoop
installs portable archives without one, so the trade is not worth it yet. Windows
SmartScreen may warn on first run; the README says so plainly rather than pretending
otherwise.

    python packaging/windows/build-exe.py [--onedir]
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
DIST = REPO / "dist" / "windows"
WORK = REPO / "build" / "pyinstaller"

# Every file the detector needs at runtime. Named explicitly rather than globbed so
# a missing one fails the build instead of shipping a scanner with no rules.
DATA_FILES = (
    "gitleaks.toml",
    "safepaste-extra.toml",
    "gitleaks.provenance.json",
)

# PyInstaller cannot see these: they are reached through deferred imports inside
# accessor methods, which is deliberate elsewhere but invisible to static analysis.
HIDDEN_IMPORTS = (
    "safepaste.backend.windows",
    "safepaste.backend.win32_loop",
    "safepaste.cli",
    "safepaste.daemon",
    "safepaste.service",
    "safepaste.shell",
    "regex",
)


def version() -> str:
    text = (REPO / "safepaste" / "__init__.py").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split('"')[1]
    raise SystemExit("could not read __version__")


def check_data_present() -> None:
    data_dir = REPO / "safepaste" / "detector" / "data"
    missing = [name for name in DATA_FILES if not (data_dir / name).is_file()]
    if missing:
        raise SystemExit(
            f"rule data missing: {', '.join(missing)}. "
            "Run scripts/fetch-rules.py before building."
        )


def build(name: str, entry: str, *, windowed: bool, onedir: bool) -> pathlib.Path:
    # Two things about --add-data, both of which fail by producing a bundle with no
    # rules rather than by complaining:
    #
    # 1. The separator is os.pathsep: ';' on Windows, ':' elsewhere.
    # 2. A *relative* source path is resolved against the --specpath directory, not
    #    the working directory. Since the spec lives under build/, a relative
    #    "safepaste/detector/data" is looked for at build/pyinstaller/safepaste/...
    #    and is not there. Absolute source, relative destination.
    sep = ";" if sys.platform == "win32" else ":"
    source = REPO / "safepaste" / "detector" / "data"
    data_spec = f"{source}{sep}safepaste/detector/data"

    argv = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", name,
        "--distpath", str(DIST),
        "--workpath", str(WORK),
        "--specpath", str(WORK),
        "--onedir" if onedir else "--onefile",
        "--windowed" if windowed else "--console",
        "--add-data", data_spec,
    ]
    for module in HIDDEN_IMPORTS:
        argv += ["--hidden-import", module]
    argv.append(str(REPO / entry))

    print(f"\n=== building {name} ===", flush=True)
    subprocess.run(argv, check=True, cwd=REPO)
    suffix = ".exe" if sys.platform == "win32" else ""
    built = DIST / (name + suffix) if not onedir else DIST / name / (name + suffix)
    if not built.exists():
        raise SystemExit(f"expected {built} but it was not produced")
    return built


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--onedir",
        action="store_true",
        help="a directory rather than a single file: starts faster, and is what "
        "Scoop prefers since it extracts an archive anyway",
    )
    args = ap.parse_args()

    check_data_present()
    if DIST.exists():
        shutil.rmtree(DIST)

    # Tiny launcher scripts, so PyInstaller has a real entry point to analyse
    # rather than a -m module reference, which it handles poorly.
    WORK.mkdir(parents=True, exist_ok=True)
    entries = {
        "safepaste": ("packaging/windows/_entry_cli.py", False),
        "safepaste-daemon": ("packaging/windows/_entry_service.py", True),
    }
    built = []
    for name, (entry, windowed) in entries.items():
        built.append(build(name, entry, windowed=windowed, onedir=args.onedir))

    print(f"\n=== built SafePaste {version()} ===")
    for path in built:
        size = path.stat().st_size / (1024 * 1024)
        print(f"  {path.relative_to(REPO)}  ({size:.1f} MiB)")
    print("\nUnsigned: SmartScreen may warn on first run. See README.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
