"""Shared utilities used across Vigil modules.

Centralizes common functions to avoid duplication and circular imports:
- Text processing (message extraction, fingerprinting, formatting stripping)
- GitHub API helpers (headers)
- Severity emoji mapping
"""

import hashlib
import re

from .models import Severity

# ---------- GitHub API ----------

def github_headers(token: str) -> dict[str, str]:
    """Build standard GitHub API headers with Bearer auth."""
    return {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }


# ---------- Severity ----------

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.critical: "\U0001f534",
    Severity.high: "\U0001f7e0",
    Severity.medium: "\U0001f7e1",
    Severity.low: "\U0001f535",
}


def severity_emoji(sev: Severity) -> str:
    """Return the emoji for a severity level."""
    return SEVERITY_EMOJI.get(sev, "")


# ---------- Text processing ----------

# Patterns to strip formatting for dedup / fingerprint comparison
STRIP_PATTERNS = [
    re.compile(r"[\U0001f534\U0001f7e0\U0001f7e1\U0001f535]"),  # severity emoji
    re.compile(r"\*\*\[(?:CRITICAL|HIGH|MEDIUM|LOW)\]\*\*"),  # severity tags
    re.compile(r"\[[\w\s]+\]"),  # category tags
    re.compile(r"\*\*[\w\s]+\*\*"),  # bold persona names
    re.compile(r"`VGL-[0-9a-f]{6}`"),  # session IDs
    re.compile(r"\*\*Suggestion:\*\*.*", re.DOTALL),  # suggestion blocks
    re.compile(r"\*Originally for.*?\*\n*"),  # relocation notes
]


def extract_message_content(body: str) -> str:
    """Strip formatting to get core message text for dedup comparison.

    Removes severity emoji, tags, session IDs, suggestions, and relocation
    notes, then collapses whitespace and lowercases.
    """
    text = body
    for pattern in STRIP_PATTERNS:
        text = pattern.sub("", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def content_fingerprint(text: str) -> str:
    """Generate a short hash fingerprint of normalized text for fast pre-filtering.

    Returns the first 12 hex characters of the MD5 hash.
    """
    return hashlib.md5(text.encode()).hexdigest()[:12]
