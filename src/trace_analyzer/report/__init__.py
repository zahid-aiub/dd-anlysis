"""Markdown and HTML reports: per test case the result, detected failure, root cause, evidence and a timeline."""

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from trace_analyzer.pipeline import AnalysisResult

from .build import CaseReport, RunReport, area, build_report, confidence_label
from .timeline import legend_svg, timeline_svg

__all__ = ["CaseReport", "RunReport", "build_report", "render", "write_reports"]

FORMATS = ("md", "html")


def _environment(result: AnalysisResult, html: bool) -> Environment:
    env = Environment(loader=PackageLoader("trace_analyzer.report", "templates"),
                      autoescape=select_autoescape(enabled_extensions=("html.j2",)) if html else False,
                      trim_blocks=False, lstrip_blocks=False, keep_trailing_newline=True)

    def clock(t: float | None) -> str:
        absolute = result.timeline.absolute(t) if t is not None else None
        return absolute.strftime("%H:%M:%S.%f")[:-3] if absolute else ""

    env.filters.update(
        t=lambda t: "–" if t is None else f"{t:.3f} s",
        clock=clock,
        cell=lambda s: str(s).replace("|", "\\|").replace("\n", " "),
        confidence=lambda c: f"{confidence_label(c)} ({c:.2f})",
        area=area,
    )
    return env


def render(result: AnalysisResult, report: RunReport, fmt: str) -> str:
    for case in report.cases:
        if not case.timeline_svg:
            own = [f for f in result.findings if f.test_case == case.name]
            case.timeline_svg = timeline_svg(result.context, case.test_case, case.diagnosis, own)
    template = _environment(result, fmt == "html").get_template(f"report.{fmt}.j2")
    return template.render(report=report, legend=legend_svg())


def write_reports(result: AnalysisResult, out_dir: Path, formats: tuple[str, ...] = FORMATS,
                  test_ids: list[str] | None = None, name: str = "report") -> list[Path]:
    """Write report.md (with one timeline SVG per test case) and/or report.html to `out_dir`."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(result, test_ids)
    written = []
    for fmt in formats:
        if fmt not in FORMATS:
            raise ValueError(f"unknown report format {fmt!r}; use one of {FORMATS}")
        path = out_dir / f"{name}.{fmt}"
        path.write_text(render(result, report, fmt), encoding="utf-8")
        written.append(path)
        if fmt == "md":
            for case in report.cases:
                svg = out_dir / case.timeline_file
                svg.write_text(case.timeline_svg + "\n", encoding="utf-8")
                written.append(svg)
            legend = out_dir / "timeline_legend.svg"
            legend.write_text(legend_svg() + "\n", encoding="utf-8")
            written.append(legend)
    return written
