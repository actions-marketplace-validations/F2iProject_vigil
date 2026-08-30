"""Shared utilities used across Vigil modules.

Centralizes common functions to avoid duplication and circular imports:
- Text processing (message extraction, fingerprinting, formatting stripping)
- GitHub API helpers (headers)
- Severity emoji mapping
- Not-reviewed labelling for specialists that never ran
"""

import hashlib
import re

from .models import (
    SKIP_NO_EXTERNAL_CONTEXT,
    SKIP_NO_FILES_IN_SCOPE,
    SKIP_REVIEWER_UNAVAILABLE,
    Severity,
)

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


# ---------- Specialists that never ran (F2iLLC/vigil#66) ----------

# One marker and one phrasing for a specialist that made no model call, so
# every surface that reports one says the same thing. Deliberately NOT a
# check-mark and deliberately never the word APPROVE: the whole defect is
# that these rendered indistinguishably from a specialist that read the diff
# and found nothing.
NOT_REVIEWED_ICON = "\u23ed\ufe0f"  # skip marker (never a check-mark)
NOT_REVIEWED_LABEL = "NOT REVIEWED"

NOT_REVIEWED_REASON_TEXT: dict[str, str] = {
    SKIP_NO_FILES_IN_SCOPE: "no files in scope",
    SKIP_REVIEWER_UNAVAILABLE: "reviewer unavailable",
    SKIP_NO_EXTERNAL_CONTEXT: "no governing spec supplied",
}


def not_reviewed_reason_text(skip_reason: str = "") -> str:
    """Return the bare reason phrase for a skip, or "" if it is unrecognized.

    Split out from ``not_reviewed_label`` so a surface that already has its
    own label column — the CLI's live specialist line — can put the reason
    where it belongs without re-deriving it from a different map. One map,
    one vocabulary, every surface in lockstep.
    """
    return NOT_REVIEWED_REASON_TEXT.get(skip_reason, "")


def not_reviewed_label(skip_reason: str = "") -> str:
    """Render a PersonaVerdict.skip_reason as display text.

    An unrecognized or missing reason degrades to the bare label rather than
    guessing. That is still honest — "NOT REVIEWED" alone already says the
    only thing a reader must not get wrong — and it means a future skip
    reason cannot accidentally render as a completed review.
    """
    detail = not_reviewed_reason_text(skip_reason)
    return f"{NOT_REVIEWED_LABEL} — {detail}" if detail else NOT_REVIEWED_LABEL


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


# ---------- XSS Prevention & Markdown Sanitization ----------

def sanitize_markdown(text: str) -> str:
    """Sanitize markdown to prevent XSS and markdown injection attacks.

    Removes or escapes dangerous content while preserving legitimate markdown:
    - Strips HTML tags (especially <script>, <img onerror>, etc.)
    - Escapes markdown special chars that could break formatting when embedded
    - Preserves legitimate markdown like code blocks, bold, italic
    - Efficient, uses only stdlib re module

    Args:
        text: The markdown text to sanitize

    Returns:
        Sanitized text safe to embed in markdown comments
    """
    if not text:
        return ""

    # Strip dangerous HTML tags AND their content (script, style, iframe, etc.)
    text = re.sub(
        r"<\s*(script|style|iframe|object|embed|applet|form)\b[^>]*>.*?</\s*\1\s*>",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Strip remaining HTML tags (keep content, remove tag markers)
    text = re.sub(r"<[^>]+>", "", text)

    # Escape markdown link syntax: [text](url) -> prevent link injection
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\\[\1\\](\2)", text)

    # Normalize line breaks to prevent confusion
    text = re.sub(r"\r\n", "\n", text)
    text = re.sub(r"\r", "\n", text)

    return text


def validate_specialist_name(name: str, max_length: int = 50) -> str:
    """Validate and sanitize a specialist name for safe embedding in comments.

    Allows alphanumeric characters, spaces, hyphens, underscores.
    Truncates to max_length to prevent excessive comment size.

    Args:
        name: The specialist name to validate
        max_length: Maximum allowed length (default 50)

    Returns:
        Validated, sanitized name
    """
    if not name:
        return "Unknown"

    # Strip dangerous HTML tags AND their content (e.g., "Security<script>alert(1)</script>" -> "Security")
    name = re.sub(
        r"<\s*(script|style|iframe|object|embed)\b[^>]*>.*?</\s*\1\s*>",
        "",
        name,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # Strip any remaining HTML tags (keep content between non-dangerous tags)
    name = re.sub(r"<[^>]*>", " ", name)

    # Keep only safe characters: alphanumeric, space, hyphen, underscore
    safe_name = re.sub(r"[^a-zA-Z0-9\s\-_]", "", name)

    # Collapse multiple spaces
    safe_name = re.sub(r"\s+", " ", safe_name).strip()

    # Truncate to max length
    if len(safe_name) > max_length:
        safe_name = safe_name[:max_length].rstrip()

    # Ensure non-empty
    return safe_name or "Unknown"


def validate_session_id(session_id: str) -> str:
    """Validate and sanitize a session ID for safe embedding in comments.

    Session IDs should match the pattern VGL-[0-9a-f]{6}.
    Invalid IDs are rejected.

    Args:
        session_id: The session ID to validate

    Returns:
        Valid session ID, or empty string if invalid
    """
    if not session_id:
        return ""

    # Match pattern: VGL-[0-9a-f]{6}
    if re.match(r"^VGL-[0-9a-f]{6}$", session_id):
        return session_id

    # Invalid — return empty
    return ""


def embed_json_metadata(metadata: dict) -> str:
    """Embed finding metadata as HTML comment for robust comment parsing.

    Creates an HTML comment block with JSON metadata that can be reliably
    extracted regardless of markdown formatting changes.

    Format: <!-- vigil-meta: {...} -->

    Args:
        metadata: Dict with keys like severity, category, message, suggestion, fingerprint

    Returns:
        HTML comment string
    """
    import json

    try:
        json_str = json.dumps(metadata, separators=(",", ":"))
        return f"<!-- vigil-meta: {json_str} -->"
    except (TypeError, ValueError) as e:
        # If serialization fails, return empty comment
        import logging

        logging.warning("Failed to serialize metadata to JSON: %s", e)
        return ""
