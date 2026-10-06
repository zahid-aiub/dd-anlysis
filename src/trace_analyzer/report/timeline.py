"""Timeline chart of one test case as a self-contained SVG (inline in HTML, a file next to the Markdown).

Swimlanes on the CANoe measurement time axis: findings, test steps, manual panel actions, telegrams in each
direction, the RaSTA connection, and the GFM-A state as a step line. Cause and symptom are vertical rules
across all lanes. Every mark has a native tooltip (<title>); the report's event table is the table view.
"""

import math
from dataclasses import dataclass
from xml.sax.saxutils import escape

from trace_analyzer.model import (
    AnalysisContext,
    Diagnosis,
    Direction,
    EventKind,
    Finding,
    Severity,
    TestCaseResult,
    Verdict,
)
from trace_analyzer.rules.common import gfma_status, status_at

WIDTH, GUTTER, RIGHT, TOP, AXIS = 960, 168, 24, 40, 34
LANE = 28
STATE_ROW = 18
STATE_NAMES = {0: "ungültig", 1: "frei", 2: "belegt", 3: "gestört", 4: "w. Zugfahrt", 5: "w. Quittung"}
SHORT = {"KOMMANDO_AZGH": "AZGH", "KOMMANDO_AZG": "AZG", "KOMMANDO_ACHSZAEHLFUELLSTAND_AKTUALISIERUNG": "AFA",
         "KOMMANDO_ZDP_AKTIVIERUNG": "ZDP"}

# Light values on the root, dark values for the OS setting and for an explicit dark theme.
STYLE = """
svg.tl { --surface:#fcfcfb; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7;
  --s1:#2a78d6; --s2:#eb6834; --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
@media (prefers-color-scheme: dark) { :root:where(:not([data-theme="light"])) svg.tl {
  --surface:#1a1a19; --ink:#ffffff; --ink-2:#c3c2b7; --grid:#2c2c2a; --axis:#383835; --s1:#3987e5; --s2:#d95926; } }
:root[data-theme="dark"] svg.tl { --surface:#1a1a19; --ink:#ffffff; --ink-2:#c3c2b7; --grid:#2c2c2a; --axis:#383835;
  --s1:#3987e5; --s2:#d95926; }
svg.tl .bg { fill: var(--surface); }
svg.tl .grid { stroke: var(--grid); stroke-width: 1; }
svg.tl .axis { stroke: var(--axis); stroke-width: 1; }
svg.tl .lane-label { fill: var(--ink-2); font-size: 12px; }
svg.tl .tick, svg.tl .level { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
svg.tl .label { fill: var(--ink); font-size: 11px; }
svg.tl .label-2 { fill: var(--ink-2); font-size: 10px; }
svg.tl .state { fill: none; stroke: var(--s1); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
svg.tl .wash { fill: var(--s1); opacity: 0.12; }
svg.tl .session { fill: var(--s1); opacity: 0.22; }
svg.tl .dot { stroke: var(--surface); stroke-width: 2; }
svg.tl .s1 { fill: var(--s1); } svg.tl .s2 { fill: var(--s2); }
svg.tl .good { fill: var(--good); } svg.tl .fail { fill: var(--critical); } svg.tl .none { fill: var(--muted); }
svg.tl .warning { fill: var(--warning); } svg.tl .serious { fill: var(--serious); }
svg.tl .critical { fill: var(--critical); } svg.tl .info { fill: var(--muted); }
svg.tl .rule-cause { stroke: var(--critical); stroke-width: 1.5; }
svg.tl .rule-symptom { stroke: var(--serious); stroke-width: 1.5; }
svg.tl .hit { fill: transparent; }
"""


@dataclass(frozen=True, slots=True)
class _Lane:
    key: str
    label: str
    top: float
    height: float

    @property
    def mid(self) -> float:
        return self.top + self.height / 2


def nice_step(span: float, target: int = 8) -> float:
    raw = span / max(target, 1)
    magnitude = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    return next(m * magnitude for m in (1, 2, 5, 10) if m * magnitude >= raw)


def _fmt(t: float, step: float) -> str:
    decimals = max(0, -math.floor(math.log10(step))) if step < 1 else 0
    return f"{t:.{decimals}f}"


def _title(text: str) -> str:
    return f"<title>{escape(text)}</title>"


def _dot(x: float, y: float, cls: str, tip: str, r: float = 4) -> str:
    return (f'<g>{_title(tip)}<circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="9"/>'
            f'<circle class="dot {cls}" cx="{x:.1f}" cy="{y:.1f}" r="{r}"/></g>')


def _severity_class(f: Finding) -> str:
    return {Severity.ERROR: "critical", Severity.WARNING: "warning"}.get(f.severity, "info")


def timeline_svg(ctx: AnalysisContext, tc: TestCaseResult, diagnosis: Diagnosis, findings: list[Finding]) -> str:
    start, end = tc.start, max(tc.end, tc.start + 1e-3)
    events = ctx.window(start, end + 1e-9)
    telegrams = [e for e in events if e.kind is EventKind.SCI_TELEGRAM]
    operator = [e for e in events if e.kind is EventKind.OPERATOR_ACTION]
    statuses = gfma_status(ctx)
    in_window = [s for s in statuses if start <= s.time <= end]
    first = status_at(statuses, start)
    sessions = [s for s in ctx.sessions if s.start < end and s.end >= start]

    levels = sorted({1, 2, 3} | {s.fields["belegung"] for s in in_window} | ({first.fields["belegung"]} if first else set()))
    lanes, y = [], TOP
    for key, label, height, present in (
            ("findings", "Findings", LANE, True),
            ("steps", "Test steps (report)", LANE, bool(tc.steps)),
            ("operator", "Manual panel actions", LANE, bool(operator)),
            ("tx", "ZE → AZ telegrams", LANE, True),
            ("rx", "AZ → ZE telegrams", LANE, True),
            ("rasta", "RaSTA connection", LANE, True),
            ("state", "GFM-A state", STATE_ROW * len(levels) + 8, True)):
        if present:
            lanes.append(_Lane(key, label, y, height))
            y += height
    lane = {l.key: l for l in lanes}
    plot_bottom = y
    height = plot_bottom + AXIS
    plot_w = WIDTH - GUTTER - RIGHT

    def x(t: float) -> float:
        return GUTTER + (min(max(t, start), end) - start) / (end - start) * plot_w

    out = [f'<svg class="tl" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="100%" '
           f'role="img" aria-label="{escape(f"Timeline of {tc.name}")}"><style>{STYLE}</style>',
           f'<rect class="bg" x="0" y="0" width="{WIDTH}" height="{height}"/>']

    # grid and axis
    step = nice_step(end - start)
    t = math.ceil(start / step) * step
    while t <= end + 1e-9:
        out.append(f'<line class="grid" x1="{x(t):.1f}" y1="{TOP}" x2="{x(t):.1f}" y2="{plot_bottom}"/>')
        out.append(f'<text class="tick" x="{x(t):.1f}" y="{plot_bottom + 15}" text-anchor="middle">{_fmt(t, step)}</text>')
        t += step
    out.append(f'<line class="axis" x1="{GUTTER}" y1="{plot_bottom}" x2="{WIDTH - RIGHT}" y2="{plot_bottom}"/>')
    out.append(f'<text class="tick" x="{WIDTH - RIGHT}" y="{plot_bottom + 30}" text-anchor="end">'
               f'CANoe measurement time (s)</text>')
    for l in lanes:
        out.append(f'<line class="grid" x1="{GUTTER}" y1="{l.top + l.height:.1f}" x2="{WIDTH - RIGHT}" '
                   f'y2="{l.top + l.height:.1f}"/>')
        label_y = l.mid + 4 if l.key != "state" else l.top + 16
        out.append(f'<text class="lane-label" x="12" y="{label_y:.1f}">{escape(l.label)}</text>')

    # GFM-A state: resettable windows as a wash, Belegungszustand as a step line
    s_lane = lane["state"]

    def level_y(belegung: int) -> float:
        return s_lane.top + 4 + STATE_ROW * (len(levels) - 1 - levels.index(belegung)) + STATE_ROW / 2

    for b in levels:
        out.append(f'<text class="level" x="{GUTTER - 8}" y="{level_y(b) + 4:.1f}" text-anchor="end">'
                   f'{escape(STATE_NAMES.get(b, str(b)))}</text>')
    points = ([(start, first)] if first else []) + [(s.time, s) for s in in_window]
    if points:
        path, wash = [], []
        for i, (t0, s) in enumerate(points):
            t1 = points[i + 1][0] if i + 1 < len(points) else end
            yy = level_y(s.fields["belegung"])
            if i == 0:
                path.append(f"M{x(t0):.1f},{yy:.1f}")
            else:
                path.append(f"V{yy:.1f}")
            path.append(f"H{x(t1):.1f}")
            if s.fields["grundstellbar"] == 1 and x(t1) > x(t0):
                wash.append((x(t0), x(t1)))
        for a, b in wash:
            out.append(f'<g>{_title("Grundstellbar (reset possible)")}<rect class="wash" x="{a:.1f}" '
                       f'y="{s_lane.top + 2}" width="{b - a:.1f}" height="{s_lane.height - 4}"/></g>')
            if b - a > 70:
                out.append(f'<text class="label-2" x="{a + 4:.1f}" y="{s_lane.top + s_lane.height - 6:.1f}">'
                           f'resettable</text>')
        out.append(f'<path class="state" d="{"".join(path)}"/>')
        for t0, s in points[1:]:
            st = s.fields
            tip = (f"{t0:.3f} s  GFM-A {s.sender or ''}: {STATE_NAMES.get(st['belegung'], st['belegung'])}, "
                   f"Grundstellbarkeit {st['grundstellbar']}, Achszählfüllstand 0x{st['achszaehlfuellstand']:04X}"
                   f"  ({s.ref})")
            out.append(_dot(x(t0), level_y(st["belegung"]), "s1", tip, r=3.5))

    # RaSTA sessions
    r_lane = lane["rasta"]
    for s in sessions:
        a, b = x(s.start), x(s.end)
        tip = (f"RaSTA session {s.index}: {s.start:.3f} – {s.end:.3f} s"
               f"{', reason ' + str(s.disconnect_reason) if s.disconnect_reason is not None else ''}")
        out.append(f'<g>{_title(tip)}<rect class="session" x="{a:.1f}" y="{r_lane.mid - 6:.1f}" '
                   f'width="{max(b - a, 2):.1f}" height="12" rx="4"/></g>')
        if b - a > 80:
            out.append(f'<text class="label-2" x="{a + 6:.1f}" y="{r_lane.mid + 4:.1f}">session {s.index}</text>')

    # telegrams
    for key, direction in (("tx", Direction.TX), ("rx", Direction.RX)):
        l, last_label = lane[key], -1e9
        for e in [t for t in telegrams if t.direction is direction]:
            tip = f"{e.time:.3f} s  {e.name} ({e.length} bytes)  {e.ref}"
            out.append(_dot(x(e.time), l.mid, "s1", tip))
            short = SHORT.get(e.name)
            if short and x(e.time) - last_label > 44:
                out.append(f'<text class="label-2" x="{x(e.time) + 7:.1f}" y="{l.mid - 6:.1f}">{short}</text>')
                last_label = x(e.time)

    # manual panel actions
    if "operator" in lane:
        l = lane["operator"]
        for e in operator:
            what = e.fields.get("command") or f"{e.name} = {e.fields.get('value')}"
            out.append(_dot(x(e.time), l.mid, "s2", f"{e.time:.3f} s  manual panel action: {what}  ({e.ref})"))

    # test steps: muted ticks, pass / fail markers; the first failure labeled
    if "steps" in lane:
        l, labeled = lane["steps"], False
        for s in tc.steps:
            if s.verdict is Verdict.FAIL:
                cls = "fail"
            elif s.verdict is Verdict.PASS:
                cls = "good"
            else:
                continue
            tip = f"{s.time:.3f} s  {s.section} {s.step}: {s.title}  [{s.verdict.value}]"
            out.append(_dot(x(s.time), l.mid, cls, tip))
            if cls == "fail" and not labeled:
                anchor = "end" if x(s.time) > WIDTH - RIGHT - 60 else "start"
                dx = -8 if anchor == "end" else 8
                out.append(f'<text class="label" x="{x(s.time) + dx:.1f}" y="{l.mid + 4:.1f}" '
                           f'text-anchor="{anchor}">✕ step failed</text>')
                labeled = True
        for s in tc.steps:
            if s.verdict not in (Verdict.FAIL, Verdict.PASS) and not s.title.startswith("Resumed on value"):
                out.append(f'<g>{_title(f"{s.time:.3f} s  {s.section} {s.step}: {s.title}")}'
                           f'<rect class="hit" x="{x(s.time) - 4:.1f}" y="{l.mid - 9:.1f}" width="8" height="18"/>'
                           f'<rect class="none" x="{x(s.time) - 0.5:.1f}" y="{l.mid - 5:.1f}" width="1" height="10"/></g>')

    # findings lane, cause and symptom rules with direct labels above the plot
    f_lane = lane["findings"]
    for f in findings:
        if f.time is None:
            continue
        role = ("cause" if f is diagnosis.cause else "symptom" if f is diagnosis.symptom else "contributing")
        tip = f"{f.time:.3f} s  [{role}, {f.severity.value}] {f.category.value}: {f.summary}"
        out.append(_dot(x(f.time), f_lane.mid, _severity_class(f), tip, r=5 if role != "contributing" else 4))
    marks = []
    for role, f in (("cause", diagnosis.cause), ("symptom", diagnosis.symptom)):
        if f is not None and f.time is not None and not (role == "symptom" and f is diagnosis.cause):
            marks.append((role, f))
    rows = []
    for role, f in sorted(marks, key=lambda m: m[1].time):
        xx = x(f.time)
        row = 0 if not rows or xx - rows[-1] > 150 else 1
        rows.append(xx)
        label = f"{'cause' if role == 'cause' else 'symptom'} · {f.category.value} · {f.time:.3f} s"
        if f is diagnosis.cause and f is diagnosis.symptom:
            label = f"cause = symptom · {f.category.value} · {f.time:.3f} s"
        out.append(f'<line class="rule-{role}" x1="{xx:.1f}" y1="{TOP - 4 - 14 * row}" x2="{xx:.1f}" y2="{plot_bottom}"/>')
        anchor = "end" if xx > WIDTH - RIGHT - 220 else "start"
        dx = -5 if anchor == "end" else 5
        out.append(f'<text class="label" x="{xx + dx:.1f}" y="{TOP - 8 - 14 * row}" text-anchor="{anchor}">'
                   f'{escape(label)}</text>')
    out.append("</svg>")
    return "".join(out)


LEGEND = (("s1", "telegram / GFM-A report"), ("s2", "manual panel action"), ("good", "step passed"),
          ("fail", "step failed / error finding"), ("warning", "warning finding"))


def legend_svg() -> str:
    """One-row legend; the lanes name what each mark is, the legend names the colors."""
    items, xx = [], 12
    for cls, text in LEGEND:
        items.append(f'<circle class="dot {cls}" cx="{xx + 4}" cy="12" r="4"/>'
                     f'<text class="label-2" x="{xx + 13}" y="16">{escape(text)}</text>')
        xx += 22 + 6.2 * len(text)
    items.append(f'<rect class="wash" x="{xx}" y="6" width="16" height="12"/>'
                 f'<text class="label-2" x="{xx + 21}" y="16">resettable</text>')
    xx += 90
    items.append(f'<line class="rule-cause" x1="{xx}" y1="4" x2="{xx}" y2="20"/>'
                 f'<text class="label-2" x="{xx + 6}" y="16">cause</text>'
                 f'<line class="rule-symptom" x1="{xx + 52}" y1="4" x2="{xx + 52}" y2="20"/>'
                 f'<text class="label-2" x="{xx + 58}" y="16">symptom</text>')
    return (f'<svg class="tl" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} 24" width="100%" '
            f'role="img" aria-label="Legend"><style>{STYLE}</style><rect class="bg" x="0" y="0" width="{WIDTH}" '
            f'height="24"/>{"".join(items)}</svg>')
