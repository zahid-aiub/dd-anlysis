"""Readers for PCAPNG, BLF, CANoe PDF report, CANoe text log and test descriptions."""

from trace_analyzer.model import EventKind, Source, SourceData

from .base import Reader
from .blf import BlfReader
from .canoe_log import CanoeLogReader
from .pcapng import PcapngReader
from .pdf_report import PdfReportReader
from .test_spec import TestSpecReader

NETWORK_KINDS = (EventKind.RASTA, EventKind.SCI_TELEGRAM, EventKind.NETWORK)

__all__ = ["BlfReader", "CanoeLogReader", "PcapngReader", "PdfReportReader", "Reader", "TestSpecReader", "load_sources"]


def load_sources(cfg: dict) -> dict[Source, SourceData]:
    """Read every data file configured in `cfg["data"]` that exists.

    `sources.blf_ethernet: false` drops the BLF's Ethernet frames and keeps only its CANoe objects (variables,
    panel, test structure), e.g. when the PCAPNG was edited and the BLF frames no longer describe the same run.
    """
    nodes = cfg["nodes"]
    baseline = cfg["protocol"]["sci_tds_baseline"]
    port = cfg["protocol"].get("rasta_udp_port")
    readers: dict[str, Reader] = {
        "pcapng": PcapngReader(nodes, baseline, port),
        "blf": BlfReader(nodes, baseline, port),
        "report_pdf": PdfReportReader(),
        "canoe_log": CanoeLogReader(),
        "test_descriptions": TestSpecReader(),
    }
    sources = {}
    for key, reader in readers.items():
        path = cfg["data"].get(key)
        if path is not None and path.exists():
            sources[reader.source] = reader.read(path)
    if not cfg.get("sources", {}).get("blf_ethernet", True) and Source.BLF in sources:
        blf = sources[Source.BLF]
        blf.events = [e for e in blf.events if e.kind not in NETWORK_KINDS]
        blf.metadata["ethernet_dropped"] = True
    return sources
