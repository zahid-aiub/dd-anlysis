"""Run the rules and turn their findings into one diagnosis per test case."""

from collections.abc import Sequence

from trace_analyzer.model import (
    AnalysisContext,
    Diagnosis,
    FailureCategory,
    Finding,
    Severity,
    TestCaseResult,
    Verdict,
)

from .base import Rule
from .config import ConfigurationRule, TimeAlignmentRule
from .connection import ConnectionRule, SequenceRule
from .protocol import (
    CommandRejectedRule,
    LengthRule,
    OrderRule,
    PayloadRule,
    ProtocolResponseRule,
    SpecExpectationRule,
)
from .state import AbortRule, CascadeRule, DeviceStateRule, ManualInterventionRule, PreconditionRule, TestStepRule

C = FailureCategory

DEFAULT_RULES: tuple[Rule, ...] = (
    ProtocolResponseRule(), SpecExpectationRule(), OrderRule(), PayloadRule(), LengthRule(), CommandRejectedRule(),
    ConnectionRule(), SequenceRule(), DeviceStateRule(), PreconditionRule(), TestStepRule(), CascadeRule(),
    AbortRule(), ManualInterventionRule(), ConfigurationRule(), TimeAlignmentRule(),
)

SYMPTOMS = (C.TEST_ABORTED, C.PRECONDITION_NOT_REACHED, C.TEST_STEP_FAILED)
STEP_EXPLANATIONS = (C.TIMEOUT, C.MISSING_MESSAGE, C.UNEXPECTED_RESPONSE, C.INVALID_PAYLOAD)
# Tie-break for causes at the same time: infrastructure before device state before protocol content.
PRECEDENCE = (
    C.CASCADE_FAILURE, C.CONNECTION_INTERRUPTION, C.SEQUENCE_ERROR, C.DEVICE_DISTURBED, C.CONFIGURATION_MISMATCH,
    C.COMMAND_REJECTED, C.INCORRECT_LENGTH, C.INVALID_PAYLOAD, C.WRONG_ORDER, C.MISSING_MESSAGE, C.TIMEOUT,
    C.UNEXPECTED_RESPONSE,
)
# Observations, not failure explanations: never listed as ruled out
NOT_RULED_OUT = (*SYMPTOMS, C.MANUAL_INTERVENTION, C.TIME_ALIGNMENT)


def run_rules(ctx: AnalysisContext, rules: Sequence[Rule] = DEFAULT_RULES) -> list[Finding]:
    findings = [f for rule in rules for f in rule.evaluate(ctx)]
    return sorted(findings, key=lambda f: (f.time is None, f.time or 0.0))


def _symptom(tc: TestCaseResult, own: list[Finding]) -> Finding | None:
    candidates = [f for f in own if f.category in SYMPTOMS]
    if not candidates:
        errors = [f for f in own if f.severity is Severity.ERROR]
        return min(errors, key=lambda f: f.time if f.time is not None else tc.start) if errors else None
    symptom = min(candidates, key=lambda f: f.time if f.time is not None else tc.end)
    if symptom.category is C.TEST_STEP_FAILED:
        # a protocol rule that explains the same spec step is the more precise symptom
        step = symptom.details.get("spec_step")
        precise = [f for f in own if f.category in STEP_EXPLANATIONS and f.details.get("spec_step") == step]
        if precise:
            return precise[0]
    return symptom


def _cause(tc: TestCaseResult, own: list[Finding], symptom: Finding | None) -> Finding | None:
    horizon = symptom.time if symptom is not None and symptom.time is not None else tc.end
    # a test that failed in its preparation never ran its spec steps: findings about those steps are failures
    # of their own (contributing), not the cause of the preparation failure
    preparation = symptom is not None and symptom.category is C.PRECONDITION_NOT_REACHED
    candidates = [f for f in own
                  if f.severity is Severity.ERROR and f.category not in SYMPTOMS and f is not symptom
                  and (f.time is None or f.time <= horizon)
                  and not (preparation and f.details.get("spec_step") is not None)]
    if candidates:
        def key(f: Finding):
            rank = PRECEDENCE.index(f.category) if f.category in PRECEDENCE else len(PRECEDENCE)
            return (f.time if f.time is not None else tc.start, rank)
        return min(candidates, key=key)
    if symptom is not None and symptom.category not in (C.PRECONDITION_NOT_REACHED, C.TEST_STEP_FAILED):
        return symptom   # the symptom explains itself, e.g. a stopped test unit or a missing telegram
    return None


def diagnose(ctx: AnalysisContext, findings: Sequence[Finding],
             rules: Sequence[Rule] = DEFAULT_RULES) -> list[Diagnosis]:
    diagnoses = []
    for tc in ctx.test_cases:
        own = [f for f in findings if f.test_case == tc.name]
        checked = {c for rule in rules if rule.applies_to(tc, ctx) for c in rule.categories}
        found = {f.category for f in own}
        ruled_out = [c for c in C if c in checked and c not in found and c not in NOT_RULED_OUT]
        if tc.verdict is Verdict.PASS and not any(f.severity is Severity.ERROR for f in own):
            diagnoses.append(Diagnosis(tc, contributing=own, ruled_out=ruled_out))
            continue
        # failed, inconclusive, or passed by the report although the analysis found an error
        symptom = _symptom(tc, own)
        cause = _cause(tc, own, symptom)
        contributing = [f for f in own if f is not symptom and f is not cause]
        diagnoses.append(Diagnosis(tc, symptom, cause, contributing, ruled_out))
    return diagnoses
