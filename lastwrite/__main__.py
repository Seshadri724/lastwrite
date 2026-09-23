"""Enable `python -m lastwrite` and serve as the PyInstaller entry point."""

import sys

from lastwrite.cli import main

if __name__ == "__main__":
    sys.exit(main())
