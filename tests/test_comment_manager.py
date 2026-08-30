"""Tests for comment_manager: deduplication, content extraction, batch resolution."""

import pytest

from vigil.comment_manager import (
    _content_fingerprint,
    _extract_issue_refs,
    _extract_message_content,
    _is_resolution_reply,
    _issue_covers_finding,
    _parse_finding_from_comment,
    build_conversation_context,
    deduplicate_comments,
    is_duplicate_finding,
    resolve_addressed_threads,
    resolve_threads_batch,
    resolve_vigil_threads_on_approval,
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


# ---------- resolve_addressed_threads ----------

class TestResolveAddressedThreads:

    def test_resolves_exact_changed_line(self, monkeypatch):
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads",
            lambda *args: [{
                "id": "thread-1",
                "isResolved": False,
                "path": "src/app.py",
                "line": 42,
                "body": "Finding `VGL-abc123`",
                "comments": [{"body": "Finding `VGL-abc123`", "author": {"login": "vigil"}}],
            }],
        )
        resolved_ids = []
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: resolved_ids.extend(ids) or ids,
        )

        count = resolve_addressed_threads("F2iLLC", "demo", 1, "token", {"src/app.py": {42}})

        assert count == 1
        assert resolved_ids == ["thread-1"]

    def test_resolves_same_file_when_thread_has_reply(self, monkeypatch):
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads",
            lambda *args: [{
                "id": "thread-1",
                "isResolved": False,
                "path": "tests/test_app.py",
                "line": 1,
                "body": "Add regression coverage `VGL-def456`",
                "comments": [
                    {"body": "Add regression coverage `VGL-def456`", "author": {"login": "vigil"}},
                    {"body": "Added malformed-reference tests in the same file.", "author": {"login": "codex"}},
                ],
            }],
        )
        resolved_ids = []
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: resolved_ids.extend(ids) or ids,
        )

        count = resolve_addressed_threads("F2iLLC", "demo", 1, "token", {"tests/test_app.py": {88, 89}})

        assert count == 1
        assert resolved_ids == ["thread-1"]

    def test_same_file_change_without_reply_does_not_resolve_nearby_thread(self, monkeypatch):
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads",
            lambda *args: [{
                "id": "thread-1",
                "isResolved": False,
                "path": "src/app.py",
                "line": 10,
                "body": "Finding `VGL-abc123`",
                "comments": [{"body": "Finding `VGL-abc123`", "author": {"login": "vigil"}}],
            }],
        )
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: ids,
        )

        count = resolve_addressed_threads("F2iLLC", "demo", 1, "token", {"src/app.py": {99}})

        assert count == 0

    def test_reply_without_same_file_change_does_not_resolve_thread(self, monkeypatch):
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads",
            lambda *args: [{
                "id": "thread-1",
                "isResolved": False,
                "path": "src/app.py",
                "line": 10,
                "body": "Finding `VGL-abc123`",
                "comments": [
                    {"body": "Finding `VGL-abc123`", "author": {"login": "vigil"}},
                    {"body": "Handled elsewhere.", "author": {"login": "codex"}},
                ],
            }],
        )
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: ids,
        )

        count = resolve_addressed_threads("F2iLLC", "demo", 1, "token", {"src/other.py": {10}})

        assert count == 0


# ---------- resolve_vigil_threads_on_approval (issue #61) ----------

def _thread(tid: str, body: str, *, path: str = "src/app.py",
            line: int = 10, resolved: bool = False) -> dict:
    """A review thread in the shape fetch_review_threads returns."""
    return {
        "id": tid,
        "isResolved": resolved,
        "path": path,
        "line": line,
        "body": body,
        "comments": [{"body": body, "path": path, "line": line,
                      "author": {"login": "vigil"}}],
    }


class TestResolveVigilThreadsOnApproval:
    """Decision-driven resolution: the diff is not consulted at all.

    The scope under test is every open Vigil thread on the PR, not the current
    session's. session_id is per-specialist-run (models.py), so the stranded
    threads this clears necessarily carry other session IDs.
    """

    def _wire(self, monkeypatch, threads: list[dict]) -> list[str]:
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads", lambda *args: threads,
        )
        resolved_ids: list[str] = []
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: resolved_ids.extend(ids) or ids,
        )
        return resolved_ids

    def test_resolves_a_thread_from_an_earlier_session(self, monkeypatch):
        """The reported shape: the open thread is not from this run."""
        resolved_ids = self._wire(monkeypatch, [
            _thread("thread-1", "Finding `VGL-abc123`", path="foo.py"),
        ])

        count = resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token")

        assert count == 1
        assert resolved_ids == ["thread-1"]

    def test_resolves_threads_across_several_sessions(self, monkeypatch):
        resolved_ids = self._wire(monkeypatch, [
            _thread("thread-1", "Finding `VGL-abc123`", path="foo.py"),
            _thread("thread-2", "Finding `VGL-def456`", path="bar.py"),
        ])

        count = resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token")

        assert count == 2
        assert resolved_ids == ["thread-1", "thread-2"]

    def test_never_resolves_a_human_thread(self, monkeypatch):
        """The VGL marker is the only thing separating ours from theirs."""
        resolved_ids = self._wire(monkeypatch, [
            _thread("human-1", "This naming is confusing to me.", path="foo.py"),
        ])

        count = resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token")

        assert count == 0
        assert resolved_ids == []

    def test_resolves_ours_and_leaves_theirs_alone_in_the_same_pr(self, monkeypatch):
        resolved_ids = self._wire(monkeypatch, [
            _thread("human-1", "Please rename this.", path="foo.py"),
            _thread("thread-1", "Finding `VGL-abc123`", path="foo.py"),
        ])

        count = resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token")

        assert count == 1
        assert resolved_ids == ["thread-1"]

    def test_skips_already_resolved_threads(self, monkeypatch):
        resolved_ids = self._wire(monkeypatch, [
            _thread("thread-1", "Finding `VGL-abc123`", resolved=True),
        ])

        assert resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token") == 0
        assert resolved_ids == []

    def test_no_threads_makes_no_mutation_call(self, monkeypatch):
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads", lambda *args: [],
        )

        def fail(*args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("resolve_threads_batch must not be called")

        monkeypatch.setattr("vigil.comment_manager.resolve_threads_batch", fail)

        assert resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token") == 0

    def test_counts_only_what_github_confirmed_resolved(self, monkeypatch):
        """resolve_threads_batch drops IDs GitHub did not confirm; so does the count."""
        monkeypatch.setattr(
            "vigil.comment_manager.fetch_review_threads",
            lambda *args: [
                _thread("thread-1", "Finding `VGL-abc123`"),
                _thread("thread-2", "Finding `VGL-def456`"),
            ],
        )
        monkeypatch.setattr(
            "vigil.comment_manager.resolve_threads_batch",
            lambda ids, token: ids[:1],
        )

        assert resolve_vigil_threads_on_approval("F2iLLC", "demo", 1, "token") == 1


# ---------- _is_resolution_reply ----------

class TestIsResolutionReply:

    def test_resolved_keyword(self):
        assert _is_resolution_reply("resolved") is True

    def test_fixed_keyword(self):
        assert _is_resolution_reply("fixed") is True

    def test_addressed_keyword(self):
        assert _is_resolution_reply("addressed") is True

    def test_done_keyword(self):
        assert _is_resolution_reply("done") is True

    def test_case_insensitive(self):
        assert _is_resolution_reply("RESOLVED") is True
        assert _is_resolution_reply("Fixed") is True

    def test_with_surrounding_text(self):
        assert _is_resolution_reply("This has been resolved.") is True

    def test_issue_link_short(self):
        assert _is_resolution_reply("#45") is True

    def test_issue_link_full_url(self):
        assert _is_resolution_reply("https://github.com/org/repo/issues/123") is True

    def test_combined_keyword_and_link(self):
        assert _is_resolution_reply("Fixed in #45") is True

    def test_empty_string(self):
        assert _is_resolution_reply("") is False

    def test_unrelated_text(self):
        assert _is_resolution_reply("LGTM") is False

    def test_partial_keyword_rejected(self):
        assert _is_resolution_reply("unresolvable") is False

    def test_whitespace_only(self):
        assert _is_resolution_reply("   ") is False

    def test_resolved_with_issue_link(self):
        assert _is_resolution_reply("Resolved via https://github.com/o/r/issues/10") is True

    def test_overruled_reply(self):
        assert _is_resolution_reply("Overruled by maintainer; acceptable risk.") is True

    def test_follow_up_reply(self):
        assert _is_resolution_reply("Tracked for a follow-up PR.") is True

    def test_just_number_not_resolution(self):
        assert _is_resolution_reply("42") is False


# ---------- _extract_issue_refs ----------

class TestExtractIssueRefs:

    def test_full_url(self):
        refs = _extract_issue_refs("See https://github.com/org/repo/issues/123")
        assert len(refs) == 1
        assert refs[0] == ("org", "repo", 123)

    def test_full_pull_url(self):
        refs = _extract_issue_refs("Follow-up PR: https://github.com/org/repo/pull/456")
        assert len(refs) == 1
        assert refs[0] == ("org", "repo", 456)

    def test_short_ref(self):
        refs = _extract_issue_refs("Fixed in #45")
        assert len(refs) == 1
        assert refs[0] == ("", "", 45)

    def test_multiple_refs(self):
        refs = _extract_issue_refs("Fixed #1 and #2")
        assert len(refs) == 2

    def test_mixed_full_and_short(self):
        refs = _extract_issue_refs("See https://github.com/org/repo/issues/1 and #2")
        assert len(refs) == 2
        # Full URL
        assert ("org", "repo", 1) in refs
        # Short ref
        assert ("", "", 2) in refs

    def test_no_refs(self):
        refs = _extract_issue_refs("Just a comment with no links")
        assert refs == []


# ---------- _issue_covers_finding ----------

class TestIssueCoversFinding:

    def test_relevant_issue(self):
        issue = {"title": "Fix SQL injection in login handler", "body": "The query is not parameterized"}
        finding = "SQL injection vulnerability in the login query construction"
        assert _issue_covers_finding(issue, finding) is True

    def test_irrelevant_issue(self):
        issue = {"title": "Update README formatting", "body": "Fix some typos in docs"}
        finding = "SQL injection vulnerability in the login query construction"
        assert _issue_covers_finding(issue, finding) is False

    def test_empty_issue_body(self):
        issue = {"title": "Fix security vulnerabilities", "body": None}
        finding = "Security vulnerability in authentication"
        assert _issue_covers_finding(issue, finding) is True

    def test_partial_overlap(self):
        issue = {"title": "Database connection pooling", "body": "Improve connection handling and reduce leaks"}
        finding = "Database connection is never closed, causing resource leaks"
        assert _issue_covers_finding(issue, finding) is True

    def test_completely_unrelated(self):
        issue = {"title": "Add dark mode toggle", "body": "Users want dark mode support"}
        finding = "Buffer overflow in the parser when handling malformed input"
        assert _issue_covers_finding(issue, finding) is False

    def test_empty_finding(self):
        issue = {"title": "Fix bug", "body": "Fix it"}
        finding = ""
        assert _issue_covers_finding(issue, finding) is True  # benefit of doubt


# ---------- build_conversation_context ----------

class TestBuildConversationContext:

    def test_empty_inputs_returns_empty_string(self):
        assert build_conversation_context([], []) == ""
        assert build_conversation_context([], None) == ""

    def test_includes_comment_author_and_body(self):
        comments = [{
            "created_at": "2026-07-15T10:00:00Z",
            "user": {"login": "codex-bot"},
            "body": "Your team has set up Codex to review pull requests in this repo.",
        }]
        result = build_conversation_context(comments)
        assert "codex-bot" in result
        assert "Codex to review pull requests" in result

    def test_skips_blank_body_comments(self):
        comments = [
            {"created_at": "2026-07-15T10:00:00Z", "user": {"login": "a"}, "body": "   "},
            {"created_at": "2026-07-15T10:01:00Z", "user": {"login": "b"}, "body": "real comment"},
        ]
        result = build_conversation_context(comments)
        assert "real comment" in result
        assert "**a**" not in result

    def test_includes_review_body_with_state(self):
        reviews = [{
            "submitted_at": "2026-07-15T11:00:00Z",
            "user": {"login": "reviewer1"},
            "state": "APPROVED",
            "body": "LGTM overall",
        }]
        result = build_conversation_context([], reviews)
        assert "reviewer1" in result
        assert "review:approved" in result
        assert "LGTM overall" in result

    def test_excludes_prior_vigil_reviews_from_re_review_context(self):
        reviews = [{
            "submitted_at": "2026-07-15T11:00:00Z",
            "user": {"login": "vigil-reviewer"},
            "state": "CHANGES_REQUESTED",
            "body": (
                "Old finding claims bodyChunks still buffers the response.\n\n"
                "Reviewed by [Vigil]"
            ),
        }]

        assert build_conversation_context([], reviews) == ""

    def test_keeps_human_review_alongside_excluded_vigil_review(self):
        reviews = [
            {
                "submitted_at": "2026-07-15T11:00:00Z",
                "user": {"login": "vigil-reviewer"},
                "state": "CHANGES_REQUESTED",
                "body": "Superseded bot finding\n\nReviewed by [Vigil]",
            },
            {
                "submitted_at": "2026-07-15T12:00:00Z",
                "user": {"login": "maintainer"},
                "state": "COMMENTED",
                "body": "The current implementation still needs a timeout test.",
            },
        ]

        result = build_conversation_context([], reviews)

        assert "Superseded bot finding" not in result
        assert "maintainer" in result
        assert "timeout test" in result

    def test_excludes_vigils_own_issue_comment_from_the_context(self):
        """F2iLLC/vigil#74: the same exclusion, on the loop that lacked it.

        When every PR Review API attempt fails, post_review falls back to
        posting the whole review body — findings text included — as an *issue*
        comment, and issue comments arrive through the comments loop, not the
        reviews loop. So Vigil read its own prior CRITICAL findings back in as
        "PR Conversation" evidence and could re-assert a defect a later commit
        had already removed.
        """
        comments = [{
            "created_at": "2026-07-15T11:00:00Z",
            "user": {"login": "vigil-reviewer"},
            "body": (
                "## ❌ Vigil Review: **REQUEST_CHANGES**\n\n"
                "Cannot find namespace JSX in AdminUserList.tsx\n\n"
                "*Reviewed by [Vigil](https://github.com/F2iProject/vigil)*"
            ),
        }]

        assert build_conversation_context(comments) == ""

    def test_keeps_human_comments_alongside_an_excluded_vigil_comment(self):
        comments = [
            {
                "created_at": "2026-07-15T11:00:00Z",
                "user": {"login": "vigil-reviewer"},
                "body": "Stale JSX finding\n\nReviewed by [Vigil]",
            },
            {
                "created_at": "2026-07-15T12:00:00Z",
                "user": {"login": "maintainer"},
                "body": "CI typecheck passes on this head; that finding is wrong.",
            },
        ]

        result = build_conversation_context(comments)

        assert "Stale JSX finding" not in result
        assert "maintainer" in result
        assert "CI typecheck passes" in result

    def test_skips_reviews_without_body(self):
        reviews = [{
            "submitted_at": "2026-07-15T11:00:00Z",
            "user": {"login": "reviewer1"},
            "state": "APPROVED",
            "body": "",
        }]
        assert build_conversation_context([], reviews) == ""

    def test_chronological_ordering(self):
        comments = [
            {"created_at": "2026-07-15T12:00:00Z", "user": {"login": "later"}, "body": "second"},
            {"created_at": "2026-07-15T10:00:00Z", "user": {"login": "earlier"}, "body": "first"},
        ]
        result = build_conversation_context(comments)
        assert result.index("first") < result.index("second")

    def test_truncates_long_item(self):
        comments = [{
            "created_at": "2026-07-15T10:00:00Z",
            "user": {"login": "verbose"},
            "body": "x" * 2000,
        }]
        result = build_conversation_context(comments, max_item_chars=100)
        assert "truncated" in result
        assert len(result) < 2000

    def test_drops_oldest_items_when_over_budget(self):
        comments = [
            {"created_at": f"2026-07-15T{h:02d}:00:00Z", "user": {"login": f"u{h}"}, "body": "x" * 200}
            for h in range(10)
        ]
        result = build_conversation_context(comments, max_total_chars=500, max_item_chars=200)
        # Most recent author should survive, oldest should be dropped
        assert "u9" in result
        assert "u0" not in result
        assert "omitted for length" in result


# ---------- _parse_finding_from_comment ----------

class TestParseFindingFromComment:

    def test_parses_standard_comment(self):
        body = "\U0001f534 **[CRITICAL]** [SQL Injection] **Security** `VGL-abc123`\n\nUnsafe query construction"
        finding = _parse_finding_from_comment(body, "src/app.py", 10)
        assert finding is not None
        assert finding.file == "src/app.py"
        assert finding.line == 10
        assert finding.severity.value == "critical"
        assert finding.category == "SQL Injection"

    def test_parses_medium_severity(self):
        body = "\U0001f7e1 **[MEDIUM]** [Race Condition] **Logic** `VGL-def456`\n\nShared counter issue"
        finding = _parse_finding_from_comment(body, "src/db.py", 42)
        assert finding is not None
        assert finding.severity.value == "medium"
        assert finding.category == "Race Condition"

    def test_returns_none_for_non_vigil_comment(self):
        body = "LGTM, looks good!"
        finding = _parse_finding_from_comment(body, "src/app.py", 10)
        assert finding is None

    def test_handles_none_path(self):
        body = "\U0001f7e0 **[HIGH]** [Auth] **Security**\n\nMissing auth check"
        finding = _parse_finding_from_comment(body, None, None)
        assert finding is not None
        assert finding.file == "unknown"
        assert finding.line is None

    def test_handles_empty_body(self):
        finding = _parse_finding_from_comment("", "app.py", 1)
        assert finding is None
