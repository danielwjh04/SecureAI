"""Entrypoint: build the proxy from settings and serve it, degrading gracefully.

The heavy ML providers (the guard model, the embedding model) are loaded if
their weights and wheels are present; otherwise the proxy runs in
deterministic-only mode — no semantic screening, no intent drift — rather than
refusing to start. The deterministic policy, field-level taint tracking, the
trajectory rule, and the audit chain are always active.
"""

import logging

import uvicorn
from fastapi import FastAPI

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError, SecureSGError
from secureSG.guard.backend import HttpMcpBackend, McpBackend
from secureSG.guard.enforcer import Enforcer
from secureSG.guard.policy import CompiledPolicy, load_policy
from secureSG.guard.proxy import create_app
from secureSG.guard.screening import Screener
from secureSG.models.loader import load_guard_provider
from secureSG.warden.embeddings import EmbeddingCache, load_embedding_provider

_LOGGER = logging.getLogger("secureSG.main")


def _build_backend(settings: Settings) -> McpBackend:
    """Build the HTTP MCP backend, failing loudly if no URL is configured."""
    if settings.mcp_backend_url is None:
        raise SecureSGError(
            "SECURESG_MCP_BACKEND_URL must be set to forward calls to the MCP server"
        )
    return HttpMcpBackend(
        settings.mcp_backend_url, timeout=settings.mcp_backend_timeout
    )


def _build_screener(settings: Settings, policy: CompiledPolicy) -> Screener | None:
    """Build the semantic screener, or None if the guard model cannot load."""
    try:
        provider = load_guard_provider(settings)
    except ModelLoadError as exc:
        _LOGGER.warning(
            "guard model unavailable (%s); running deterministic-only screening",
            exc.__class__.__name__,
        )
        return None
    return Screener(
        injection_signatures=policy.injection_signatures,
        provider=provider,
        block_threshold=settings.semantic_block_threshold,
        review_threshold=settings.semantic_review_threshold,
    )


def _build_embedding_cache(settings: Settings) -> EmbeddingCache | None:
    """Build the embedding cache, or None if the embedding model cannot load."""
    try:
        provider = load_embedding_provider(settings)
    except ModelLoadError as exc:
        _LOGGER.warning(
            "embedding model unavailable (%s); intent drift detection disabled",
            exc.__class__.__name__,
        )
        return None
    return EmbeddingCache(provider)


def build_app(settings: Settings) -> FastAPI:
    """Construct the proxy app, degrading to deterministic-only without models.

    Time complexity: O(policy size) plus a one-time model load.
    Space complexity: O(model size).
    """
    backend = _build_backend(settings)
    policy = load_policy(settings.policy_dir)
    audit_logger = AuditLogger(
        db_path=settings.db_path,
        genesis_hash=derive_genesis_hash(settings.genesis_seed),
        journal_mode=settings.sqlite_journal_mode,
    )
    enforcer = Enforcer(
        policy=policy,
        audit_logger=audit_logger,
        screener=_build_screener(settings, policy),
    )
    return create_app(
        settings=settings,
        enforcer=enforcer,
        audit_logger=audit_logger,
        policy=policy,
        mcp_backend=backend,
        embedding_cache=_build_embedding_cache(settings),
    )


def main() -> None:
    """Build the proxy from environment settings and serve it with uvicorn."""
    settings = Settings()
    app = build_app(settings)
    uvicorn.run(app, host=settings.proxy_host, port=settings.proxy_port)


if __name__ == "__main__":  # pragma: no cover
    main()
