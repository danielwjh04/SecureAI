"""Tests for pattern-based PII / secret redaction."""

import pytest

from secureSG.dashboard.redaction import redact_pii


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("contact a.user@example.com now", "contact [REDACTED] now"),
        ("key sk-abcdefghijklmnop1234 here", "key [REDACTED] here"),
        ("id AKIAIOSFODNN7EXAMPLE end", "id [REDACTED] end"),
        (
            "hash 0123456789abcdef0123456789abcdef done",
            "hash [REDACTED] done",
        ),
        ("the quick brown fox jumps", "the quick brown fox jumps"),
    ],
)
def test_redact_pii(text: str, expected: str) -> None:
    assert redact_pii(text) == expected
