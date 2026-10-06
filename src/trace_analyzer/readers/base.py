"""Contract every reader implements."""

from pathlib import Path
from typing import Protocol

from trace_analyzer.model import Source, SourceData


class Reader(Protocol):
    source: Source

    def read(self, path: Path) -> SourceData:
        """Parse one file. Event times stay in the source's native time base (see SourceData.time_base)."""
        ...
