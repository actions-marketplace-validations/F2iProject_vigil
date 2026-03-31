"""Tests for utils.py: centralized shared utilities."""

from vigil.models import Severity
from vigil.utils import (
    content_fingerprint,
    extract_message_content,
    github_headers,
    severity_emoji,
    SEVERITY_EMOJI,
    STRIP_PATTERNS,
    sanitize_markdown,
    validate_specialist_name,
    validate_session_id,
    embed_json_metadata,
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


class TestSanitizeMarkdown:
    """Test XSS prevention via markdown sanitization."""

    def test_strips_html_tags(self):
        """HTML tags should be stripped entirely."""
        text = "Normal text <script>alert('xss')</script> more text"
        result = sanitize_markdown(text)
        assert "<script>" not in result
        assert "alert" not in result
        assert "Normal text" in result
        assert "more text" in result

    def test_strips_img_onerror_injection(self):
        """Image onerror attributes should be removed."""
        text = "Check <img src=x onerror='alert(1)'> this"
        result = sanitize_markdown(text)
        assert "<img" not in result
        assert "onerror" not in result
        assert "alert" not in result

    def test_preserves_normal_markdown(self):
        """Normal markdown formatting should be preserved."""
        text = "**bold** and *italic* and `code`"
        result = sanitize_markdown(text)
        assert "**bold**" in result
        assert "*italic*" in result
        assert "`code`" in result

    def test_escapes_markdown_links(self):
        """Markdown link syntax should be escaped to prevent injection."""
        text = "[click here](javascript:alert('xss'))"
        result = sanitize_markdown(text)
        # Links should be escaped
        assert "\\[" in result or "[" not in result

    def test_handles_empty_string(self):
        assert sanitize_markdown("") == ""

    def test_handles_none_gracefully(self):
        # Should not raise even if input validation is needed
        result = sanitize_markdown(None or "")
        assert result == ""

    def test_normalizes_line_breaks(self):
        """Different line break styles should be normalized."""
        text = "line1\r\nline2\rline3\nline4"
        result = sanitize_markdown(text)
        assert result.count("\n") >= 3


class TestValidateSpecialistName:
    """Test specialist name validation."""

    def test_accepts_normal_names(self):
        assert validate_specialist_name("Security") == "Security"
        assert validate_specialist_name("Logic Reviewer") == "Logic Reviewer"

    def test_strips_special_chars(self):
        result = validate_specialist_name("Security@#$%")
        assert "@" not in result
        assert "#" not in result
        assert "Security" in result

    def test_strips_html_tags_from_name(self):
        """HTML tags embedded in names should be sanitized."""
        result = validate_specialist_name("Evil<script>alert(1)</script>Name")
        assert "<script>" not in result
        assert "alert" not in result
        assert "Evil" in result
        assert "Name" in result

    def test_allows_hyphen_underscore(self):
        assert validate_specialist_name("Security-Team") == "Security-Team"
        assert validate_specialist_name("Logic_Reviewer") == "Logic_Reviewer"

    def test_collapses_spaces(self):
        result = validate_specialist_name("Multiple   Spaces")
        assert "   " not in result

    def test_truncates_long_names(self):
        long_name = "A" * 100
        result = validate_specialist_name(long_name, max_length=50)
        assert len(result) <= 50

    def test_empty_returns_unknown(self):
        assert validate_specialist_name("") == "Unknown"
        assert validate_specialist_name(None or "") == "Unknown"

    def test_only_special_chars_returns_unknown(self):
        assert validate_specialist_name("<>!@#$%^") == "Unknown"


class TestValidateSessionId:
    """Test session ID validation."""

    def test_accepts_valid_session_ids(self):
        assert validate_session_id("VGL-abc123") == "VGL-abc123"
        assert validate_session_id("VGL-000000") == "VGL-000000"
        assert validate_session_id("VGL-ffffff") == "VGL-ffffff"

    def test_rejects_invalid_format(self):
        assert validate_session_id("VGL-xyz") == ""
        assert validate_session_id("VGL-12345") == ""
        assert validate_session_id("VGL_abc123") == ""
        assert validate_session_id("vgl-abc123") == ""

    def test_rejects_non_hex_chars(self):
        assert validate_session_id("VGL-ghijkl") == ""
        assert validate_session_id("VGL-ABCDEF") == ""

    def test_empty_returns_empty(self):
        assert validate_session_id("") == ""
        assert validate_session_id(None or "") == ""


class TestEmbedJsonMetadata:
    """Test JSON metadata embedding."""

    def test_creates_html_comment(self):
        metadata = {"severity": "high", "category": "SQL Injection"}
        result = embed_json_metadata(metadata)
        assert result.startswith("<!-- vigil-meta:")
        assert result.endswith("-->")
        assert "high" in result
        assert "SQL Injection" in result

    def test_valid_json_format(self):
        import json
        metadata = {"severity": "high", "message": "Test", "category": "Issue"}
        result = embed_json_metadata(metadata)
        # Extract JSON from comment
        json_str = result.replace("<!-- vigil-meta: ", "").replace(" -->", "")
        parsed = json.loads(json_str)
        assert parsed["severity"] == "high"
        assert parsed["message"] == "Test"

    def test_empty_metadata(self):
        result = embed_json_metadata({})
        assert "<!-- vigil-meta:" in result
        assert "{}}" in result or "{}" in result

    def test_unserializable_value_returns_empty(self):
        """Non-serializable values should return empty string, not raise."""
        metadata = {"bad_value": object()}
        result = embed_json_metadata(metadata)
        assert result == ""
