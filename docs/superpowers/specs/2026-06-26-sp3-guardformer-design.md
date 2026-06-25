# SP3 — GuardFormer Semantic Layer — Design Spec

**Status:** Approved (2026-06-26). Supersedes the roadmap stub for SP3 in the build plan.
**Depends on:** SP1 (audit spine), SP2 (deterministic guard core).
**Delivers:** the `ModelProvider` interface, a real Qwen3-0.6B Q4_K_M provider, a defense-in-depth `Screener`, two audited entry points wired into the SP2 `Enforcer`, signature-as-data policy, a weights fetch script, and full tests.

---

## 1. Decisions locked (from brainstorming)

| Question | Decision |
|---|---|
| What does GuardFormer score, and where does it hook in? | **Both** — one `ModelProvider`, two entry points: untrusted-content scanning (result path) **and** uncertain-call adjudication (call path). |
| Detection model | **Defense-in-depth** — deterministic injection-signature matcher (Aho-Corasick, reuses SP2 engine) as the reliable first layer, **plus** Qwen3-0.6B as the semantic generalization layer behind it. |
| Weights sourcing | **Auto-download script** via `huggingface-hub` into a git-ignored weights dir; `SECURESG_MODEL_PATH` points at it. CI and all non-gated tests use a deterministic stub provider and never touch the file. |
| Output contract (from CLAUDE.md §6) | The model emits a **probability**; ALLOW / HUMAN_APPROVAL_REQUIRED / BLOCK **thresholds live in `settings.py`**. Not a generative JSON judge. |

---

## 2. Core safety invariant — the model can only tighten

Severity order: **ALLOW < HUMAN_APPROVAL_REQUIRED < BLOCK**.

The semantic verdict is always `max(deterministic_baseline, model_verdict)` by severity. **The model may raise caution; it may never lower it.** A fail-closed tool stays fail-closed even if the model likes the call. This structurally prevents the canonical failure *"the model said it was fine, so we allowed the exfiltration."* The model's only power is to escalate.

Consequences:
- Deterministic `BLOCK` (schema / denylist / taint→external) short-circuits **before** any inference (CLAUDE.md §6: taint HIGH→external is an automatic BLOCK before the semantic check).
- The model is consulted on **flagged calls only** (latency + the tighten-only rule make it pointless elsewhere): `screener present AND baseline.verdict != BLOCK AND (baseline.rule_id == "default.fail_mode" OR baseline.verdict == HUMAN_APPROVAL_REQUIRED)`.

---

## 3. Module layout

```
secureSG/
  models/
    provider.py      # ModelProvider ABC (async assess) — the swap seam
    guardformer.py   # QwenGuardProvider: llama-cpp inference; pure prompt+probability helpers
    loader.py        # load_guard_provider(settings) — one-time GGUF load, fail-loud
  guard/
    matching.py      # AhoCorasick (extracted from taint.py; shared multi-pattern matcher)
    screening.py     # Screener: signatures + provider; thresholds; tighten-only composition
    taint.py         # (modified) import AhoCorasick from matching.py
    enforcer.py      # (modified) +screen_result(); semantic call-adjudication in evaluate();
                     #   +injection_signatures / content_scan_sources in policy IR
  schemas/
    assessment.py    # AssessmentTask enum, SemanticAssessment model
  policies/
    injection_signatures.yaml   # injection_signatures: [...]  + content_scan_sources: [...]
scripts/
  fetch_model.py     # huggingface-hub download → git-ignored weights dir
```

No file exceeds the §1 size limits; each unit is independently testable with a stub.

---

## 4. Data contracts (`schemas/assessment.py`)

```python
class AssessmentTask(StrEnum):
    INJECTION_SCAN = "INJECTION_SCAN"   # untrusted content → P(injection)
    CALL_RISK      = "CALL_RISK"        # serialized tool call → P(malicious)

class SemanticAssessment(BaseModel):   # frozen
    task: AssessmentTask
    p_unsafe: float                    # 0.0–1.0, validated in range
```

`p_unsafe` carries a `Field(ge=0.0, le=1.0)` bound; out-of-range is a programming error and raises.

---

## 5. The `ModelProvider` seam (`models/provider.py`)

```python
class ModelProvider(ABC):
    @abstractmethod
    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment: ...
```

- Implementations own their own prompt formatting (model-specific), so swapping Qwen3 → a hosted guard model later re-implements exactly this contract. Thresholds and verdict mapping stay out of the provider (they live in the `Screener` + `settings.py`).
- `tests/` ships a `StubProvider(scripted: dict[..., float])` returning deterministic `p_unsafe`. It lives in tests only — never in `secureSG/` (it is a test double, not a production stub).

---

## 6. Qwen3 runtime (`models/guardformer.py`, `models/loader.py`)

### Probability, not generation
The guard prompt ends where the model must answer with a single class label. We read **logprobs** rather than parse generated text:

1. `Llama.create_completion(prompt, max_tokens=settings.model_max_output_tokens, temperature=0.0, logprobs=settings.model_logprobs_top_k)`.
2. From `choices[0]["logprobs"]["top_logprobs"][0]` (dict `{token: logprob}`), aggregate (log-sum-exp) the logprobs of tokens belonging to the UNSAFE class vs the SAFE class.
3. 2-way softmax of the two aggregates → `p_unsafe ∈ [0,1]` — a real probability per §6.
4. If neither class token appears in the top-K (degenerate output), raise `InferenceError` → the caller fails closed.

`_build_guard_prompt(content, task)`, the class-token aggregation, and the 2-way softmax are **pure functions** unit-tested with synthetic `top_logprobs` — no weights needed. Only the thin `create_completion` call is gated behind real weights (`# pragma: no cover` with a documented reason).

> Library-syntax note: the `logprobs`/`top_logprobs` shape is per the documented llama-cpp-python completion API. The exact field access is re-confirmed against installed-version docs during implementation; no method signature is invented.

### Loader
`load_guard_provider(settings) -> QwenGuardProvider` constructs `Llama(model_path=..., n_ctx=model_context_size, n_threads=model_threads, logits_all=False)` **once** at startup (CLAUDE.md §6: never reload per request). Missing/unset `model_path`, a non-existent file, or a llama-cpp import failure raises `ModelLoadError` — loud, never a silent degrade.

### Concurrency
llama.cpp is not concurrency-safe on one context. The provider serializes inference with an `asyncio.Lock` around a single `asyncio.to_thread(...)` call: no blocking in the event loop (CLAUDE.md §5), no interleaved-state corruption. For a 0.6B CPU model, serialized inference is correct and sufficient.

---

## 7. The `Screener` (`guard/screening.py`)

Owns: the signature `AhoCorasick` (built from `policy.injection_signatures`), the `ModelProvider`, and the thresholds.

Pure helpers (unit-tested):
- `map_probability_to_verdict(p) -> Verdict` — `p ≥ block → BLOCK`, `p ≥ review → HUMAN_APPROVAL_REQUIRED`, else `ALLOW`.
- `escalate(baseline, model_verdict) -> Verdict` — severity-max (the §2 invariant).
- `serialize_call(call) -> str` — canonical `tool(args)` text fed to `CALL_RISK`.

Async entry points (return `PolicyVerdict`, no audit — mirrors SP2's pure `_decide`):
- `async screen_content(content) -> PolicyVerdict`
  1. Signature scan → match ⇒ `BLOCK`, `rule_id=injection.signature`, reason names the matched pattern. *(Reliable, explainable, O(n).)*
  2. Clean ⇒ `provider.assess(content, INJECTION_SCAN)` → `map_probability_to_verdict` → `rule_id ∈ {injection.semantic, injection.semantic.review, injection.clean}` (reason carries `p_unsafe`).
- `async assess_call(call, baseline) -> PolicyVerdict`
  - `provider.assess(serialize_call(call), CALL_RISK)` → model verdict → `escalate(baseline.verdict, model_verdict)`. If escalated above baseline ⇒ `rule_id=semantic.call_risk`; otherwise the baseline verdict/rule stands. An `InferenceError` ⇒ the tool's fail-mode (fail-closed), surfaced to the caller for audit.

---

## 8. Policy IR additions (`guard/enforcer.py`)

`PolicySchema` / `CompiledPolicy` gain two fields, loaded and merged by the existing `load_policy` (concatenated across `*.yaml`):
- `injection_signatures: list[str]` → `frozenset[str]` — known jailbreak/injection substrings (data, never code).
- `content_scan_sources: list[str]` → `frozenset[str]` — tools whose **results** are untrusted external content to scan (e.g. `scrape_page`). Distinct from `taint_sources` (sensitive **outputs** like `read_secret`).

`policies/injection_signatures.yaml` carries the initial signature set and `content_scan_sources: [scrape_page]`.

---

## 9. Enforcer integration (`guard/enforcer.py`)

Constructor becomes `Enforcer(policy, audit_logger, screener: Screener | None = None)`. **`screener=None` reproduces SP2 behavior exactly** — every SP2 test stays green; deterministic-only is an explicit, logged construction choice, not an accidental degrade.

- **Call path** — `evaluate()` computes the deterministic baseline via the existing sync `_decide`, then, when the §2 flag condition holds and a screener is present, `await screener.assess_call(call, baseline)`; the **final** verdict (escalated or baseline) is what gets appended to the chain. Idempotency and the audit append are unchanged.
- **Content path** — new `async screen_result(result, transaction_id) -> PolicyVerdict`: if `result.tool_name` is not a `content_scan_source` → `ALLOW`, `rule_id=content.untracked` (no inference). Otherwise `await screener.screen_content(...)`, then append the verdict to the audit chain (same idempotent path as `evaluate`). The existing sync `observe_result` (taint ingest) is unchanged and orthogonal.

---

## 10. Settings additions (`config/settings.py`)

Add to `Settings` (env `SECURESG_*`), with `model_config = SettingsConfigDict(..., protected_namespaces=())` to silence pydantic v2's `model_`-prefix warning and keep the intuitive `MODEL_PATH` mapping:

| Field | Default | Purpose |
|---|---|---|
| `model_path: Path \| None` | `None` | GGUF weights path (`SECURESG_MODEL_PATH`). |
| `model_context_size: int` | `2048` | llama `n_ctx`. |
| `model_threads: int` | `4` | llama `n_threads`. |
| `model_max_output_tokens: int` | `1` | only one label token is needed. |
| `model_logprobs_top_k: int` | `20` | top-K logprobs to read. |
| `semantic_block_threshold: float` | `0.80` | `p_unsafe ≥` ⇒ BLOCK. |
| `semantic_review_threshold: float` | `0.50` | `p_unsafe ≥` ⇒ HUMAN_APPROVAL_REQUIRED. |

A model validator enforces `0.0 < review < block ≤ 1.0` (fail-loud on misconfiguration). The guard **prompt template** and class-label tokens are documented constants in `guardformer.py` (model artifacts, not tunable config).

---

## 11. Exceptions (`exceptions.py`)

```python
class ModelError(SecureSGError): ...
class ModelLoadError(ModelError): ...     # weights missing / import failure at startup
class InferenceError(ModelError): ...     # degenerate/failed inference at runtime → fail closed
```

Only these three are added (each is actually raised; no speculative taxonomy).

---

## 12. Fail-closed semantics

- No silent degradation anywhere. Startup model failure ⇒ `ModelLoadError`. Runtime inference failure ⇒ the tool's fail-mode, audited.
- Deterministic BLOCKs never reach the model.
- The tighten-only invariant means the model can never weaken a fail-closed default.

---

## 13. Testing strategy

- **`StubProvider`** in `tests/` drives every unit/integration test deterministically; no weights, no native lib.
- Unit coverage: signature matcher (known patterns, overlaps, clean); `map_probability_to_verdict` band edges; `escalate` severity-max (model cannot downgrade a fail-closed tool); `serialize_call`; guardformer pure helpers (prompt build, class aggregation, softmax, degenerate→`InferenceError`); settings threshold validator; new exceptions; policy loads `injection_signatures` + `content_scan_sources`.
- Integration: `screen_result` blocks a signatured page and a high-`p_unsafe` page, audits each, and the chain still verifies `CHAIN_OK`; `evaluate` escalates a no-rule call when the stub returns high `p_unsafe`; `evaluate` cannot downgrade a denylisted/taint BLOCK; idempotent replay.
- **One** real-model test, `@pytest.mark.model`, skipped unless weights present **and** llama-cpp importable: a known injection scores high, benign low. Keeps the 85% gate off the 400 MB file.
- Gates: `pytest --cov=secureSG --cov-fail-under=85`, `ruff check`, `mypy --strict`. The only `# pragma: no cover` is the native `create_completion` call, with a documented reason.

---

## 14. Scope boundary (explicit deferrals)

- **Proxy wiring** of `screen_result` into the live inbound stream is **SP5** (the proxy/interceptor). SP3 delivers and tests the method; nothing calls it in a running server yet.
- **REDACT-tier PII stripping before inference** (CLAUDE.md §6) is **deferred**: no policy *tier* system exists yet (current policy has denylist / external_comms / taint_sources / tool_rules — no REDACT). Building a redaction hook now would be dead code. It lands when the tier system does (SP4-adjacent).
- No new dashboard, no warden, no trajectory work.

---

## 15. Build order (TDD, dependency-ordered)

1. **Deps** — `requirements.txt += llama-cpp-python, huggingface-hub` (documented reason in the commit).
2. **Exceptions** — add `ModelError`/`ModelLoadError`/`InferenceError` (RED→GREEN).
3. **Settings** — model + semantic fields, `protected_namespaces=()`, threshold validator (RED→GREEN).
4. **schemas/assessment.py** — `AssessmentTask`, `SemanticAssessment` (RED→GREEN).
5. **guard/matching.py** — extract `AhoCorasick` from `taint.py`; repoint `taint.py`; re-run SP2 taint tests (stay GREEN).
6. **models/provider.py** — `ModelProvider` ABC (exercised via `StubProvider`).
7. **models/guardformer.py** — pure helpers first (TDD with synthetic logprobs), then the gated `create_completion` glue.
8. **models/loader.py** — `load_guard_provider`, fail-loud (missing path → `ModelLoadError`; real load gated).
9. **Policy IR** — `injection_signatures` + `content_scan_sources` in schema/compiled/merge; `policies/injection_signatures.yaml` (RED→GREEN).
10. **guard/screening.py** — `Screener` + pure helpers (RED→GREEN with `StubProvider`).
11. **Enforcer** — `screener=None` ctor, call-adjudication in `evaluate`, `screen_result` (RED→GREEN; SP2 tests stay GREEN).
12. **scripts/fetch_model.py** — huggingface-hub download (thin; arg-construction smoke test).
13. **Verify** — full suite, coverage ≥ 85%, ruff, `mypy --strict`. Commit SP3 in logical commits.

---

## 16. Success criteria

- All SP1+SP2 tests stay green; new tests cover every new public function.
- `screen_result` blocks both a signatured and a high-`p_unsafe` page and the audit chain verifies.
- `evaluate` escalates an uncertain call on high `p_unsafe` and **cannot** weaken any deterministic BLOCK.
- Coverage ≥ 85%, ruff clean, `mypy --strict` clean.
- `scripts/fetch_model.py` downloads the GGUF; the gated real-model test passes locally with weights present.
