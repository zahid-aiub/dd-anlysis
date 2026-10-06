"""Entry point: python analyze.py --config config/config.yaml (see trace_analyzer.cli)."""

import sys

from trace_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
