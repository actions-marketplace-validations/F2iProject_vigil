"""Tests for comment_manager: deduplication, content extraction, batch resolution."""

import pytest

from vigil.comment_manager import (
    _content_fingerprint,
    _extract_message_content,
    deduplicate_comments,
    is_duplicate_finding,
    resolve_threads_batch,
    VIGIL_SESSION_PATTERN,
)


# ---------- _extract_message_content ----------

class TestExtractMessageContent:

    def test_strips_severity_emoji(self):
        body = "\U0001f534 **[CRITICAL]** [SQL Injection] **Security** `VGL-abc123`\n\nDangerous query"
        result = _extract_message_content(body)
        assert "dangerous query" in result
        assert "\U0001f534" not in result

    def test_strips_severity_tags(self):
        body = "**[HIGH]** some finding"
        result = _extract_message_content(body)
        assert "HIGH" not in result.upper() or "high" not in result
        assert "some finding" in result

    def test_strips_session_ids(self):
        body = "Finding text `VGL-abc123` more text"
        result = _extract_message_content(body)
        assert "VGL-abc123" not in result
        assert "finding text" in result
        assert "more text" in result

    def test_strips_suggestions(self):
        body = "Main issue here\n\n**Suggestion:** Use parameterized queries instead"
        result = _extract_message_content(body)
        assert "main issue here" in result
        assert "parameterized" not in result

    def test_strips_relocation_notes(self):
        body = "*Originally for `other.py:42` (nearest diff location)*\n\nActual finding"
        result = _extract_message_content(body)
        assert "actual finding" in result
        assert "originally" not in result.lower()

    def test_collapses_whitespace(self):
        body = "  lots   of   spaces  \n\n  and  newlines  "
        result = _extract_message_content(body)
        assert "  " not in result
        assert result == "lots of spaces and newlines"

    def test_empty_body(self):
        assert _extract_message_content("") == ""

    def test_preserves_core_message(self):
        body = "\U0001f7e1 **[MEDIUM]** [Race Condition] **Logic** `VGL-def456`\n\nThe shared counter is accessed without a lock, which can cause data races under concurrent access.\n\n**Suggestion:** Use a mutex or atomic operations."
        result = _extract_message_content(body)
        assert "shared counter" in result
        assert "data races" in result
        assert "mutex" not in result  # suggestion stripped


# ---------- _content_fingerprint ----------

class TestContentFingerprint:

    def test_same_text_same_fingerprint(self):
        assert _content_fingerprint("hello world") == _content_fingerprint("hello world")

    def test_different_text_different_fingerprint(self):
        assert _content_fingerprint("hello") != _content_fingerprint("goodbye")

    def test_returns_string(self):
        fp = _content_fingerprint("test")
        assert isinstance(fp, str)
        assert len(fp) == 12


# ---------- is_duplicate_finding ----------

class TestIsDuplicateFinding:

    def test_exact_duplicate(self):
        new = {"path": "src/app.py", "line": 10, "body": "Some finding message"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Some finding message"}]
        assert is_duplicate_finding(new, existing) is True

    def test_same_file_nearby_line(self):
        new = {"path": "src/app.py", "line": 12, "body": "Some finding message"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Some finding message"}]
        assert is_duplicate_finding(new, existing) is True  # within 3 lines

    def test_same_file_far_line_not_duplicate(self):
        new = {"path": "src/app.py", "line": 50, "body": "Some finding message"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Some finding message"}]
        assert is_duplicate_finding(new, existing) is False  # >3 lines apart

    def test_different_file_not_duplicate(self):
        new = {"path": "src/other.py", "line": 10, "body": "Some finding message"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Some finding message"}]
        assert is_duplicate_finding(new, existing) is False

    def test_similar_but_below_threshold(self):
        new = {"path": "src/app.py", "line": 10, "body": "Completely different message about auth"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Message about database indexing performance"}]
        assert is_duplicate_finding(new, existing) is False

    def test_minor_wording_change_is_duplicate(self):
        new = {"path": "src/app.py", "line": 10, "body": "The input is not validated before use in the query"}
        existing = [{"path": "src/app.py", "line": 10, "body": "Input is not validated before being used in the query"}]
        assert is_duplicate_finding(new, existing) is True

    def test_empty_body_not_duplicate(self):
        new = {"path": "src/app.py", "line": 10, "body": ""}
        existing = [{"path": "src/app.py", "line": 10, "body": "Some finding"}]
        assert is_duplicate_finding(new, existing) is False

    def test_empty_existing_not_duplicate(self):
        new = {"path": "src/app.py", "line": 10, "body": "Some finding"}
        existing = [{"path": "src/app.py", "line": 10, "body": ""}]
        assert is_duplicate_finding(new, existing) is False

    def test_no_existing_comments(self):
        new = {"path": "src/app.py", "line": 10, "body": "Finding"}
        assert is_duplicate_finding(new, []) is False

    def test_uses_original_line_fallback(self):
        new = {"path": "src/app.py", "line": 10, "body": "Same finding"}
        existing = [{"path": "src/app.py", "original_line": 10, "body": "Same finding"}]
        assert is_duplicate_finding(new, existing) is True

    def test_custom_threshold(self):
        new = {"path": "src/app.py", "line": 10, "body": "abc def ghi"}
        existing = [{"path": "src/app.py", "line": 10, "body": "abc def xyz"}]
        # With very low threshold, should match
        assert is_duplicate_finding(new, existing, similarity_threshold=0.3) is True
        # With very high threshold, should not match
        assert is_duplicate_finding(new, existing, similarity_threshold=0.99) is False

    def test_with_formatting_stripped(self):
        """Two comments with different formatting but same core message."""
        new = {
            "path": "src/app.py",
            "line": 10,
            "body": "\U0001f534 **[CRITICAL]** [SQL Injection] **Security** `VGL-aaa111`\n\nUnsafe query construction",
        }
        existing = [{
            "path": "src/app.py",
            "line": 10,
            "body": "\U0001f7e0 **[HIGH]** [SQL Injection] **Security** `VGL-bbb222`\n\nUnsafe query construction",
        }]
        assert is_duplicate_finding(new, existing) is True


# ---------- deduplicate_comments ----------

class TestDeduplicateComments:

    def test_removes_duplicates(self):
        new_comments = [
            {"path": "a.py", "line": 1, "body": "Finding A"},
            {"path": "b.py", "line": 5, "body": "Finding B"},
        ]
        existing = [
            {"path": "a.py", "line": 1, "body": "Finding A"},
        ]
        result = deduplicate_comments(new_comments, existing)
        assert len(result) == 1
        assert result[0]["body"] == "Finding B"

    def test_no_duplicates_returns_all(self):
        new_comments = [
            {"path": "a.py", "line": 1, "body": "New finding"},
            {"path": "b.py", "line": 5, "body": "Another new finding"},
        ]
        existing = [
            {"path": "c.py", "line": 10, "body": "Old finding"},
        ]
        result = deduplicate_comments(new_comments, existing)
        assert len(result) == 2

    def test_empty_existing_returns_all(self):
        new_comments = [{"path": "a.py", "line": 1, "body": "Finding"}]
        result = deduplicate_comments(new_comments, [])
        assert len(result) == 1

    def test_empty_new_returns_empty(self):
        result = deduplicate_comments([], [{"path": "a.py", "line": 1, "body": "Old"}])
        assert result == []

    def test_all_duplicates_returns_empty(self):
        comments = [
            {"path": "a.py", "line": 1, "body": "Same finding"},
            {"path": "b.py", "line": 5, "body": "Another same"},
        ]
        existing = [
            {"path": "a.py", "line": 1, "body": "Same finding"},
            {"path": "b.py", "line": 5, "body": "Another same"},
        ]
        result = deduplicate_comments(comments, existing)
        assert len(result) == 0

    def test_path_indexed_performance(self):
        """Many existing comments in different files shouldn't slow down dedup."""
        existing = [
            {"path": f"file_{i}.py", "line": 1, "body": f"Finding {i}"}
            for i in range(100)
        ]
        new = [{"path": "file_50.py", "line": 1, "body": "Finding 50"}]
        result = deduplicate_comments(new, existing)
        assert len(result) == 0  # duplicate of file_50


# ---------- VIGIL_SESSION_PATTERN ----------

class TestVigilSessionPattern:

    def test_matches_valid_session_id(self):
        assert VIGIL_SESSION_PATTERN.search("text `VGL-abc123` more") is not None

    def test_no_match_without_prefix(self):
        assert VIGIL_SESSION_PATTERN.search("abc123") is None

    def test_no_match_wrong_length(self):
        assert VIGIL_SESSION_PATTERN.search("VGL-ab") is None
        assert VIGIL_SESSION_PATTERN.search("VGL-abcdefg") is not None  # matches first 6

    def test_extracts_session_id(self):
        match = VIGIL_SESSION_PATTERN.search("blah VGL-f0f0f0 blah")
        assert match is not None
        assert match.group(0) == "VGL-f0f0f0"


# ---------- resolve_threads_batch (unit-level, no network) ----------

class TestResolveThreadsBatch:

    def test_empty_list_returns_empty(self):
        # No network call should happen
        result = resolve_threads_batch([], "fake-token")
        assert result == []
