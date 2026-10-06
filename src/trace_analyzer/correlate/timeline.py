"""Merge all aligned sources into one timeline.

PCAPNG and BLF Ethernet objects capture the same frames. PCAPNG is the primary network source (its frame
numbers are what engineers see in Wireshark); matched BLF frames are dropped and referenced in
`fields["duplicate_ref"]`, frames that only the BLF has are kept.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from trace_analyzer.model import (
    Alignment,
    ConsistencyCheck,
    EventKind,
    FrameDifference,
    MergeStats,
    Source,
    SourceData,
    TestCaseResult,
    TestSpec,
    TraceEvent,
)

from .timebase import (
    align,
    apply,
    cross_check,
    frame_events,
    match_frames,
    measurement_start_utc,
    pair_differing,
    utc_offset,
)

NETWORK_KINDS = (EventKind.RASTA, EventKind.SCI_TELEGRAM, EventKind.NETWORK)
METADATA_KEYS = ("configuration", "user", "computer", "application_version", "tester", "canoe_version")


@dataclass(slots=True)
class Timeline:
    events: list[TraceEvent]                          # master time (CANoe measurement time), sorted
    test_cases: dict[Source, list[TestCaseResult]]   # per source, aligned
    specs: list[TestSpec]
    alignments: dict[Source, Alignment]
    checks: list[ConsistencyCheck]
    merge: MergeStats | None
    measurement_start: datetime | None = None         # aware, test bench local time
    metadata: dict[str, Any] = field(default_factory=dict)

    def absolute(self, t: float) -> datetime | None:
        """Wall-clock time of a master-timeline instant."""
        return self.measurement_start + timedelta(seconds=t) if self.measurement_start else None


def _frame_locator(event: TraceEvent) -> str:
    return event.ref.locator.split(" telegram", 1)[0]


def _first_difference(a: bytes, b: bytes) -> int:
    return next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))


def merge_network(primary: SourceData, secondary: SourceData | None,
                  tolerance: float = 0.005) -> tuple[list[TraceEvent], MergeStats]:
    """Merge two captures of the same link; frames recorded differently are paired within `tolerance` s."""
    primary_events = [e for e in primary.events if e.kind in NETWORK_KINDS]
    if secondary is None:
        return primary_events, MergeStats(primary.source, None)

    secondary_events = [e for e in secondary.events if e.kind in NETWORK_KINDS]
    pairs = match_frames(primary_events, secondary_events)
    duplicate_of = {a.ref.locator: b.ref for a, b in pairs}
    matched_secondary = {b.ref.locator for _, b in pairs}

    # leftovers that are the same frame with different bytes: keep the primary frame, record the difference
    differing = pair_differing([e for e in primary_events if e.ref.locator not in duplicate_of],
                               [e for e in secondary_events if e.ref.locator not in matched_secondary], tolerance)
    differs_from = {a.ref.locator: b.ref for a, b in differing}
    matched_secondary |= {b.ref.locator for _, b in differing}

    merged = []
    for e in primary_events:
        frame = _frame_locator(e)
        if (dup := duplicate_of.get(frame)) is not None:
            suffix = e.ref.locator[len(frame):]          # " telegram 2" for SCI telegrams
            e = replace(e, fields={**e.fields, "duplicate_ref": f"{dup.file} {dup.locator}{suffix}"})
        elif (other := differs_from.get(frame)) is not None:
            e = replace(e, fields={**e.fields, "differs_from": f"{other.file} {other.locator}"})
        merged.append(e)
    only_secondary = [e for e in secondary_events if _frame_locator(e) not in matched_secondary]
    merged += only_secondary

    paired_primary = duplicate_of.keys() | differs_from.keys()
    stats = MergeStats(
        primary.source, secondary.source, len(pairs),
        only_in_primary=tuple(e.ref.locator for e in frame_events(primary_events) if e.ref.locator not in paired_primary),
        only_in_secondary=tuple(e.ref.locator for e in frame_events(only_secondary)),
        differing=tuple(FrameDifference(a.time, a.ref, b.ref, len(a.raw), len(b.raw), _first_difference(a.raw, b.raw),
                                        a.name) for a, b in differing),
    )
    return merged, stats


def build_timeline(sources: dict[Source, SourceData], cfg: dict | None = None) -> Timeline:
    cfg = cfg or {}
    alignments = align(sources, cfg.get("alignment"))
    aligned = {source: apply(data, alignments[source]) for source, data in sources.items()}

    events: list[TraceEvent] = []
    merge = None
    primary = Source.PCAPNG if Source.PCAPNG in aligned else Source.BLF if Source.BLF in aligned else None
    if primary is not None:
        secondary = aligned.get(Source.BLF) if primary is Source.PCAPNG else None
        if secondary is not None and not any(e.kind in NETWORK_KINDS for e in secondary.events):
            secondary = None   # BLF without Ethernet frames (sources.blf_ethernet: false)
        tolerance = cfg.get("alignment", {}).get("max_spread_ms", 5.0) / 1000
        network, merge = merge_network(aligned[primary], secondary, tolerance)
        events += network
    for data in aligned.values():
        events += [e for e in data.events if e.kind not in NETWORK_KINDS]
    events.sort(key=lambda e: e.time)

    start_utc = measurement_start_utc(sources, alignments)
    local = sources[Source.BLF].metadata.get("measurement_start_local") if Source.BLF in sources else None
    tz = utc_offset(local, start_utc)
    if tz is None and Source.PDF_REPORT in sources and (begin := sources[Source.PDF_REPORT].metadata.get("test_begin")):
        tz = begin.tzinfo
    start = start_utc.astimezone(tz) if start_utc and tz else start_utc

    metadata = {}
    for data in sources.values():
        for key in METADATA_KEYS:
            if data.metadata.get(key) and key not in metadata:
                metadata[key] = data.metadata[key]

    return Timeline(
        events=events,
        test_cases={s: d.test_cases for s, d in aligned.items() if d.test_cases},
        specs=aligned[Source.TEST_SPEC].specs if Source.TEST_SPEC in aligned else [],
        alignments=alignments,
        checks=cross_check(aligned),
        merge=merge,
        measurement_start=start,
        metadata=metadata,
    )
