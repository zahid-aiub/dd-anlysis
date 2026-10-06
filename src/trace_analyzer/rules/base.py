"""Contract every root-cause rule implements."""

from typing import Protocol

from trace_analyzer.model import AnalysisContext, FailureCategory, Finding, TestCaseResult


class Rule(Protocol):
    name: str
    categories: tuple[FailureCategory, ...]   # categories this rule can report (and rule out)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        """Return findings; a category without findings in a test case counts as ruled out there."""
        ...

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        """Whether the rule could check this test case at all (e.g. spec available, step executed)."""
        ...


class BaseRule:
    """Convenience base: applies to every test case unless overridden."""

    name = ""
    categories: tuple[FailureCategory, ...] = ()

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return True

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        raise NotImplementedError


class NetworkRule(BaseRule):
    """Rule on captured traffic: only checks test cases during which a RaSTA connection existed."""

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return any(s.start < tc.end and s.end >= tc.start for s in ctx.sessions)
