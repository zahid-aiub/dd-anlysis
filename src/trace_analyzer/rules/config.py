"""Rules on configuration and data quality: spec vs. baseline, versions, time alignment between sources."""

from trace_analyzer.model import AnalysisContext, FailureCategory, Finding, Severity, TestCaseResult
from trace_analyzer.readers.decode import bl5_layout

from .base import BaseRule
from .common import FIELD_RANGES, finding, spec_target_state, target_state

C = FailureCategory


def _layout_keys(message_type: int) -> dict[str, str]:
    """Spec byte key ('44', '45..46') → BL5 field name."""
    return {(str(offset) if size == 1 else f"{offset}..{offset + size - 1}"): name
            for name, offset, size in bl5_layout(message_type)}


class ConfigurationRule(BaseRule):
    """Test_Description values the configured baseline cannot produce; precondition and version differences.

    Expected bytes beyond the BL5 telegram length are a length failure (`LengthRule`), not a mismatch here.
    """

    name = "configuration"
    categories = (C.CONFIGURATION_MISMATCH,)

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return tc.test_id in ctx.specs

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        baseline = ctx.config.get("protocol", {}).get("sci_tds_baseline", 5)
        findings = []
        for tc in ctx.test_cases:
            spec = ctx.specs.get(tc.test_id)
            if spec is None:
                continue
            for step in spec.steps:
                if step.message_type is None or step.expect_absent or not step.expected_bytes:
                    continue
                fields = _layout_keys(step.message_type)
                invalid = [f"BTP[{k}] = {v} is not a valid BL{baseline} {fields[k]}"
                           for k, v in step.expected_bytes.items()
                           if k in fields and fields[k] in FIELD_RANGES and v.lower().startswith("0x")
                           and int(v, 16) not in FIELD_RANGES[fields[k]]]
                if invalid:
                    findings.append(finding(
                        ctx, C.CONFIGURATION_MISMATCH, Severity.WARNING,
                        f"Test_Description step {step.number} does not match SCI-TDS BL{baseline}: {invalid[0]}",
                        None, [spec.ref] if spec.ref else [], 0.8, test_case=tc.name, spec_step=step.number,
                        problems=invalid))
            spec_target, report_target = spec_target_state(spec), target_state(tc)
            if spec_target and report_target and spec_target != report_target:
                findings.append(finding(
                    ctx, C.CONFIGURATION_MISMATCH, Severity.WARNING,
                    f"Test_Description precondition {spec_target[0]}/{spec_target[1]} (\"{spec.precondition}\"), "
                    f"the report prepares {report_target[0]}/{report_target[1]}",
                    None, [r for r in (spec.ref, tc.ref) if r], 0.8, test_case=tc.name,
                    spec_target=list(spec_target), report_target=list(report_target)))
            if spec.version and tc.version and spec.version != tc.version:
                findings.append(finding(
                    ctx, C.CONFIGURATION_MISMATCH, Severity.WARNING,
                    f"Test case version {tc.version} in the report, {spec.version} in the Test_Description",
                    None, [r for r in (tc.ref, spec.ref) if r], 0.6, test_case=tc.name,
                    report_version=tc.version, spec_version=spec.version))
        return findings


class TimeAlignmentRule(BaseRule):
    """Sources that could only be aligned roughly, disagree after alignment, or miss frames the other has."""

    name = "time_alignment"
    categories = (C.TIME_ALIGNMENT,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        limit = ctx.config.get("alignment", {}).get("max_spread_ms", 5.0) / 1000
        findings = []
        for a in ctx.alignments.values():
            if a.method in ("measurement_start", "first_frame"):
                findings.append(finding(ctx, C.TIME_ALIGNMENT, Severity.WARNING,
                                        f"{a.source.value} aligned via {a.method}: {a.note}", None, (), 0.7,
                                        source=a.source.value, method=a.method))
            elif a.spread > limit:
                findings.append(finding(ctx, C.TIME_ALIGNMENT, Severity.WARNING,
                                        f"{a.source.value} offset varies by {a.spread * 1000:.1f} ms ({a.method})",
                                        None, (), 0.8, source=a.source.value, spread_s=a.spread,
                                        drift_ppm=a.drift_ppm))
        for c in ctx.checks:
            if c.max_difference > limit or c.unmatched:
                findings.append(finding(
                    ctx, C.TIME_ALIGNMENT, Severity.WARNING,
                    f"{c.name}: {c.sources[0].value} and {c.sources[1].value} differ by up to "
                    f"{c.max_difference * 1000:.1f} ms, {c.unmatched} unmatched", None, (), 0.8,
                    check=c.name, max_difference_s=c.max_difference, unmatched=c.unmatched))
        if ctx.merge and (ctx.merge.only_in_primary or ctx.merge.only_in_secondary):
            m = ctx.merge
            findings.append(finding(
                ctx, C.TIME_ALIGNMENT, Severity.WARNING,
                f"{len(m.only_in_primary)} frames only in {m.primary.value}, "
                f"{len(m.only_in_secondary)} only in {m.secondary.value if m.secondary else '-'}", None, (), 0.9,
                only_in_primary=list(m.only_in_primary[:20]), only_in_secondary=list(m.only_in_secondary[:20])))
        return findings
