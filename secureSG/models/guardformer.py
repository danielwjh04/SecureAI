"""GuardFormer: Qwen3 GGUF inference (llama-cpp) that yields P(unsafe).

The model answers a guard prompt with a single digit (``1`` = unsafe, ``0`` =
safe). Rather than parse generated text, we read the per-token logprobs of those
two tokens and 2-way softmax them into a calibrated probability. The prompt
construction and the logprob->probability math live in
:mod:`secureSG.models.guard_classifier` (shared with the Ollama provider); only
the native llama-cpp completion call lives here. Thresholds and verdict mapping
live in the Screener and settings, never here.
"""

import asyncio
from typing import Any, Protocol

from secureSG.models.guard_classifier import (
    build_guard_prompt,
    p_unsafe_from_logprobs,
)
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


class _CompletionModel(Protocol):
    """The minimal slice of the llama_cpp.Llama API the provider depends on."""

    def create_completion(
        self,
        prompt: str,
        *,
        max_tokens: int,
        temperature: float,
        logprobs: int | None = ...,
        grammar: object | None = ...,
    ) -> Any: ...


class QwenGuardProvider(ModelProvider):
    """GuardFormer over a local Qwen3 GGUF via llama-cpp-python."""

    def __init__(
        self,
        llm: _CompletionModel,
        *,
        max_output_tokens: int,
        logprobs_top_k: int,
        author_max_tokens: int,
    ) -> None:
        self._llm = llm
        self._max_output_tokens = max_output_tokens
        self._logprobs_top_k = logprobs_top_k
        self._author_max_tokens = author_max_tokens
        self._lock = asyncio.Lock()

    async def assess(
        self, content: str, task: AssessmentTask
    ) -> SemanticAssessment:
        """Return P(unsafe) for ``content`` under ``task``.

        Inference is serialized (llama.cpp is not concurrency-safe on one
        context) and runs off the event loop in a worker thread.

        Time complexity: O(prompt + generated tokens). Space complexity: O(1).
        """
        prompt = build_guard_prompt(content, task)
        async with self._lock:
            top_logprobs = await asyncio.to_thread(self._infer_top_logprobs, prompt)
        return SemanticAssessment(
            task=task, p_unsafe=p_unsafe_from_logprobs(top_logprobs)
        )

    def _infer_top_logprobs(self, prompt: str) -> dict[str, float]:
        completion = self._llm.create_completion(
            prompt=prompt,
            max_tokens=self._max_output_tokens,
            temperature=0.0,
            logprobs=self._logprobs_top_k,
        )
        per_token: list[dict[str, float]] = completion["choices"][0]["logprobs"][
            "top_logprobs"
        ]
        return per_token[0] if per_token else {}

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        """Generate text for ``prompt``, optionally constrained by a GBNF grammar.

        Serialized and run off the event loop, like ``assess``.
        Time complexity: O(prompt + generated tokens). Space complexity: O(1).
        """
        async with self._lock:
            return await asyncio.to_thread(self._complete_text, prompt, grammar)

    def _complete_text(self, prompt: str, grammar: str | None) -> str:
        completion = self._llm.create_completion(
            prompt=prompt,
            max_tokens=self._author_max_tokens,
            temperature=0.0,
            grammar=self._compile_grammar(grammar),
        )
        text: str = completion["choices"][0]["text"]
        return text

    @staticmethod
    def _compile_grammar(grammar: str | None) -> object | None:  # pragma: no cover
        # reason: LlamaGrammar.from_string needs the native llama_cpp wheel; the
        # grammar path runs only under the @pytest.mark.model authoring test.
        if grammar is None:
            return None
        from llama_cpp import LlamaGrammar

        compiled: object = LlamaGrammar.from_string(grammar)
        return compiled
