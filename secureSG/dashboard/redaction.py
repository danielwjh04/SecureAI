"""Pattern-based PII / secret redaction for dashboard display.

This complements taint-based masking (which only knows the values the guard has
actually seen this session). Here we mask common sensitive *shapes* in free text
— emails and key-like tokens — so the dashboard never echoes a credential that a
scraped page happened to contain.

Detecting a sensitive shape in free text is a pattern-recognition task with no
"proper parser" to defer to, so compiled regular expressions are the right tool
(CLAUDE.md's no-regex rule targets parsing structured grammars, not free-text
detection). The patterns are deliberately specific to keep false positives low,
and each is linear (no nested quantifiers) so there is no catastrophic
backtracking.
"""

import re
from typing import Final

_MASK: Final[str] = "[REDACTED]"

_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email address
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\b[A-Za-z]{2,5}-[A-Za-z0-9]{16,}\b"),  # prefixed key, e.g. sk-...
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex token / hash
)


def redact_pii(text: str) -> str:
    """Mask emails and key-like tokens in ``text``.

    Time complexity: O(patterns * len(text)). Space complexity: O(len(text)).
    """
    redacted = text
    for pattern in _PATTERNS:
        redacted = pattern.sub(_MASK, redacted)
    return redacted
