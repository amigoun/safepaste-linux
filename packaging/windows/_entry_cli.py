"""PyInstaller entry point for the CLI.

A real script rather than a `-m safepaste.cli` reference: PyInstaller analyses an
actual file far more reliably than a module invocation.
"""

import sys

from safepaste.cli import main

if __name__ == "__main__":
    sys.exit(main())
