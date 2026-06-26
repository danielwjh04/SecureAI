"""Tests for GuardFormer: the local llama-cpp provider's inference and generation."""

from typing import Any

import pytest

from secureSG.exceptions import InferenceError
from secureSG.models.guardformer import QwenGuardProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


class FakeCompletionModel:
    """Stand-in for llama_cpp.Llama returning a scripted top_logprobs dict."""

    def __init__(self, top_logprobs: dict[str, float]) -> None:
        self._top = top_logprobs
        self.prompts: list[str] = []

    def create_completion(
        self,
        prompt: str,
        *,
        max_tokens: int,
        temperature: float,
        logprobs: int | None = None,
        grammar: object | None = None,
    ) -> dict[str, Any]:
        self.prompts.append(prompt)
        return {"choices": [{"logprobs": {"top_logprobs": [self._top]}}]}


async def test_assess_returns_probability_via_fake_model() -> None:
    fake = FakeCompletionModel({"0": -3.0, "1": -0.05})
    provider = QwenGuardProvider(
        fake, max_output_tokens=1, logprobs_top_k=5, author_max_tokens=512
    )
    result = await provider.assess("some scraped text", AssessmentTask.INJECTION_SCAN)
    assert isinstance(result, SemanticAssessment)
    assert result.task is AssessmentTask.INJECTION_SCAN
    assert result.p_unsafe > 0.9
    assert fake.prompts and "some scraped text" in fake.prompts[0]


async def test_assess_propagates_degenerate_inference_error() -> None:
    fake = FakeCompletionModel({"weird": -0.1})
    provider = QwenGuardProvider(
        fake, max_output_tokens=1, logprobs_top_k=5, author_max_tokens=512
    )
    with pytest.raises(InferenceError):
        await provider.assess("x", AssessmentTask.CALL_RISK)


class FakeTextModel:
    """Stand-in for llama_cpp.Llama returning scripted completion text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.grammars: list[object | None] = []

    def create_completion(
        self,
        prompt: str,
        *,
        max_tokens: int,
        temperature: float,
        logprobs: int | None = None,
        grammar: object | None = None,
    ) -> dict[str, Any]:
        self.grammars.append(grammar)
        return {"choices": [{"text": self.text}]}


async def test_generate_returns_completion_text() -> None:
    fake = FakeTextModel('{"denylist": ["execute_shell"]}')
    provider = QwenGuardProvider(
        fake, max_output_tokens=1, logprobs_top_k=5, author_max_tokens=256
    )
    out = await provider.generate("author a policy from intent", grammar=None)
    assert out == '{"denylist": ["execute_shell"]}'
    assert fake.grammars == [None]
