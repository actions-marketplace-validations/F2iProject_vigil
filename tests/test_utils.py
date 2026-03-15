"""Tests for utils.py: centralized shared utilities."""

from vigil.models import Severity
from vigil.utils import (
    content_fingerprint,
    extract_message_content,
    github_headers,
    severity_emoji,
    SEVERITY_EMOJI,
    STRIP_PATTERNS,
)


class TestGithubHeaders:

    def test_returns_bearer_auth(self):
        headers = github_headers("my-token")
        assert headers["Authorization"] == "Bearer my-token"

    def test_returns_accept_header(self):
        headers = github_headers("token")
        assert "application/vnd.github" in headers["Accept"]


class TestSeverityEmoji:

    def test_critical(self):
        assert severity_emoji(Severity.critical) == "\U0001f534"

    def test_high(self):
        assert severity_emoji(Severity.high) == "\U0001f7e0"

    def test_medium(self):
        assert severity_emoji(Severity.medium) == "\U0001f7e1"

    def test_low(self):
        assert severity_emoji(Severity.low) == "\U0001f535"

    def test_severity_emoji_dict(self):
        assert len(SEVERITY_EMOJI) == 4


class TestExtractMessageContent:

    def test_strips_all_formatting(self):
        body = "\U0001f534 **[CRITICAL]** [SQL Injection] **Security** `VGL-abc123`\n\nDangerous query"
        result = extract_message_content(body)
        assert "dangerous query" in result
        assert "\U0001f534" not in result
        assert "VGL-" not in result

    def test_strips_suggestion(self):
        body = "Main issue\n\n**Suggestion:** Fix it"
        result = extract_message_content(body)
        assert "main issue" in result
        assert "fix it" not in result

    def test_empty_string(self):
        assert extract_message_content("") == ""

    def test_lowercases(self):
        result = extract_message_content("UPPERCASE TEXT")
        assert result == "uppercase text"


class TestContentFingerprint:

    def test_deterministic(self):
        assert content_fingerprint("hello") == content_fingerprint("hello")

    def test_different_input(self):
        assert content_fingerprint("a") != content_fingerprint("b")

    def test_returns_12_chars(self):
        fp = content_fingerprint("test")
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)


class TestStripPatterns:

    def test_patterns_are_compiled(self):
        import re
        for p in STRIP_PATTERNS:
            assert isinstance(p, re.Pattern)
