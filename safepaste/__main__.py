"""Enables `python -m safepaste ...`.

A package needs this file for `-m` to work at all. It deliberately does
nothing but hand off to cli.main, so there is exactly one place argv parsing
happens regardless of how the CLI is invoked.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
