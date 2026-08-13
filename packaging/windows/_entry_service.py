"""PyInstaller entry point for the background service.

Dispatches by platform through safepaste.service, exactly as the packaged
safepaste-daemon shim does on Linux, so one entry point behaves correctly wherever
it is built.
"""

import sys

from safepaste.service import main

if __name__ == "__main__":
    sys.exit(main())
