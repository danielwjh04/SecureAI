"""Tests for the self-contained demo driver."""

from pathlib import Path

import pytest

from secureSG.demo.driver import _BenignJudge, main, run_demo
from secureSG.schemas.assessment import AssessmentTask


async def test_demo_runs_expected_verdicts(tmp_path: Path) -> None:
    outcomes = await run_demo(tmp_path / "demo.db", emit=lambda _msg: None)
    assert all(outcome.matched_expectation for outcome in outcomes)
    rule_ids = [outcome.rule_id for outcome in outcomes]
    assert "injection.signature" in rule_ids
    assert "taint.high_to_external" in rule_ids
    assert "trajectory.sensitive_to_external" in rule_ids
    assert sum(1 for outcome in outcomes if not outcome.blocked) == 1


def test_demo_main_prints_intact_chain(capsys: pytest.CaptureFixture[str]) -> None:
    main()
    output = capsys.readouterr().out
    assert "audit chain: INTACT" in output
    assert "injection.signature" in output
    assert "trajectory.sensitive_to_external" in output


async def test_benign_judge_reports_safe_and_empty() -> None:
    judge = _BenignJudge()
    assessment = await judge.assess("anything", AssessmentTask.INJECTION_SCAN)
    assert assessment.p_unsafe == 0.0
    assert await judge.generate("prompt") == ""
