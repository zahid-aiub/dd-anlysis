"""Merging two captures of the same link: identical frames, frames recorded differently, frames in one only."""

from dataclasses import replace
from pathlib import Path

from builders import rasta

from trace_analyzer.correlate.timeline import merge_network
from trace_analyzer.model import Direction, EvidenceRef, RastaType, Source, SourceData, TimeBase, TimeReference


def capture(source: Source, events) -> SourceData:
    return SourceData(source, Path(f"x.{source.value}"), TimeBase(TimeReference.MEASUREMENT), list(events))


def frame(t: float, seq: int, raw: bytes, source: Source, locator: str, typ=RastaType.HEARTBEAT):
    e = rasta(t, typ, Direction.RX, seq)
    return replace(e, raw=raw, ref=EvidenceRef(source, f"x.{source.value}", locator))


def test_frames_recorded_differently_are_paired():
    pcap = [frame(1.0, 1, b"\x01" * 40, Source.PCAPNG, "frame 1"),
            frame(1.3, 2, b"\x02" * 82, Source.PCAPNG, "frame 2", RastaType.DATA),
            frame(1.6, 3, b"\x03" * 40, Source.PCAPNG, "frame 3"),
            frame(1.9, 4, b"\x04" * 40, Source.PCAPNG, "frame 4")]
    blf = [frame(1.0002, 1, b"\x01" * 40, Source.BLF, "object 1"),
           frame(1.3002, 2, b"\x02" * 81, Source.BLF, "object 2", RastaType.DATA),       # one byte shorter
           frame(1.6002, 3, b"\x03" * 39 + b"\xff", Source.BLF, "object 3"),            # last byte changed
           frame(5.0, 9, b"\x09" * 40, Source.BLF, "object 4")]                          # only in the BLF
    merged, stats = merge_network(capture(Source.PCAPNG, pcap), capture(Source.BLF, blf), tolerance=0.005)

    assert stats.matched_frames == 1
    assert [(d.primary.locator, d.secondary.locator, d.primary_length, d.secondary_length, d.first_difference)
            for d in stats.differing] == [("frame 2", "object 2", 82, 81, 81), ("frame 3", "object 3", 40, 40, 39)]
    assert stats.only_in_primary == ("frame 4",) and stats.only_in_secondary == ("object 4",)
    by_locator = {e.ref.locator: e for e in merged}
    assert by_locator["frame 2"].fields["differs_from"] == "x.blf object 2"
    assert "object 2" not in by_locator and "object 4" in by_locator
