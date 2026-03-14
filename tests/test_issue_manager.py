"""Tests for issue_manager: issue creation, dedup, label management."""

import pytest
from unittest.mock import patch, MagicMock

from vigil.issue_manager import (
    _build_issue_body,
    _build_issue_title,
    _VIGIL_ISSUE_MARKER,
    _VIGIL_LABEL,
    create_issue,
    create_issues_for_observations,
    ensure_vigil_label,
    find_existing_issue,
)
from vigil.models import Finding, PersonaVerdict, ReviewResult, Severity


# ---------- Fixtures ----------

def _make_finding(
    file="src/app.py",
    line=10,
    sev=Severity.medium,
    category="race_condition",
    message="Shared counter accessed without a lock",
    suggestion="Use a mutex",
):
    return Finding(
        file=file, line=line, severity=sev, category=category,
        message=message, suggestion=suggestion,
    )


def _make_result(observations=None, verdicts=None, observation_sources=None):
    """Build a minimal ReviewResult with observations."""
    obs = observations or []
    sources = observation_sources or []
    v = verdicts or [
        PersonaVerdict(
            persona="Security", decision="APPROVE",
            checks={}, findings=[], observations=obs,
        )
    ]
    return ReviewResult(
        decision="APPROVE",
        summary="All good",
        commit_sha="abc1234",
        pr_url="https://github.com/o/r/pull/1",
        model="test-model",
        specialist_verdicts=v,
        lead_findings=[],
        observations=obs,
        observation_sources=sources,
    )


# ---------- _build_issue_title ----------

class TestBuildIssueTitle:

    def test_basic_title(self):
        f = _make_finding()
        title = _build_issue_title(f, "Security")
        assert "[Vigil/Security]" in title
        assert "race_condition" in title

    def test_truncates_long_message(self):
        f = _make_finding(message="A" * 100)
        title = _build_issue_title(f, "Logic")
        assert len(title) < 120  # reasonable length
        assert "..." in title

    def test_short_message_not_truncated(self):
        f = _make_finding(message="Short msg")
        title = _build_issue_title(f, "Logic")
        assert "..." not in title
        assert "Short msg" in title


# ---------- _build_issue_body ----------

class TestBuildIssueBody:

    def test_contains_marker(self):
        f = _make_finding()
        body = _build_issue_body(f, "Security")
        assert _VIGIL_ISSUE_MARKER in body

    def test_contains_severity(self):
        f = _make_finding(sev=Severity.critical)
        body = _build_issue_body(f, "Security")
        assert "CRITICAL" in body

    def test_contains_file_location(self):
        f = _make_finding(file="src/auth.py", line=42)
        body = _build_issue_body(f, "Security")
        assert "`src/auth.py:42`" in body

    def test_contains_message(self):
        f = _make_finding(message="Dangerous operation without validation")
        body = _build_issue_body(f, "Logic")
        assert "Dangerous operation without validation" in body

    def test_contains_suggestion_when_present(self):
        f = _make_finding(suggestion="Add input validation")
        body = _build_issue_body(f, "Security")
        assert "Add input validation" in body
        assert "### Suggestion" in body

    def test_no_suggestion_section_when_absent(self):
        f = _make_finding(suggestion=None)
        body = _build_issue_body(f, "Security")
        assert "### Suggestion" not in body

    def test_contains_pr_url(self):
        f = _make_finding()
        body = _build_issue_body(f, "Security", pr_url="https://github.com/o/r/pull/1")
        assert "https://github.com/o/r/pull/1" in body

    def test_contains_commit_sha(self):
        f = _make_finding()
        body = _build_issue_body(f, "Security", commit_sha="abc1234567890")
        assert "`abc1234`" in body

    def test_contains_persona(self):
        f = _make_finding()
        body = _build_issue_body(f, "Performance")
        assert "Performance" in body


# ---------- ensure_vigil_label ----------

class TestEnsureVigilLabel:

    @patch("vigil.issue_manager.httpx.post")
    def test_creates_label_successfully(self, mock_post):
        mock_post.return_value = MagicMock(status_code=201)
        assert ensure_vigil_label("owner", "repo", "token") is True

    @patch("vigil.issue_manager.httpx.post")
    def test_label_already_exists(self, mock_post):
        mock_post.return_value = MagicMock(status_code=422)
        assert ensure_vigil_label("owner", "repo", "token") is True

    @patch("vigil.issue_manager.httpx.post")
    def test_api_error(self, mock_post):
        mock_post.return_value = MagicMock(status_code=403, text="Forbidden")
        assert ensure_vigil_label("owner", "repo", "token") is False

    @patch("vigil.issue_manager.httpx.post")
    def test_network_error(self, mock_post):
        mock_post.side_effect = Exception("Connection refused")
        assert ensure_vigil_label("owner", "repo", "token") is False


# ---------- find_existing_issue ----------

class TestFindExistingIssue:

    @patch("vigil.issue_manager.httpx.get")
    def test_finds_matching_issue(self, mock_get):
        f = _make_finding(message="Shared counter accessed without a lock")
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [{
                "html_url": "https://github.com/o/r/issues/5",
                "body": f"{_VIGIL_ISSUE_MARKER}\n**File:** `src/app.py:10`\n### Finding\n\nShared counter accessed without a lock\n---",
            }],
        )
        mock_get.return_value.raise_for_status = MagicMock()

        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url == "https://github.com/o/r/issues/5"

    @patch("vigil.issue_manager.httpx.get")
    def test_no_matching_issues(self, mock_get):
        f = _make_finding(message="Completely unique finding")
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [{
                "html_url": "https://github.com/o/r/issues/5",
                "body": f"{_VIGIL_ISSUE_MARKER}\n**File:** `other.py:10`\n### Finding\n\nDifferent issue entirely\n---",
            }],
        )
        mock_get.return_value.raise_for_status = MagicMock()

        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url is None

    @patch("vigil.issue_manager.httpx.get")
    def test_no_vigil_issues(self, mock_get):
        f = _make_finding()
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [{
                "html_url": "https://github.com/o/r/issues/1",
                "body": "Regular issue without Vigil marker",
            }],
        )
        mock_get.return_value.raise_for_status = MagicMock()

        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url is None

    @patch("vigil.issue_manager.httpx.get")
    def test_empty_issue_list(self, mock_get):
        f = _make_finding()
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [],
        )
        mock_get.return_value.raise_for_status = MagicMock()

        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url is None

    @patch("vigil.issue_manager.httpx.get")
    def test_api_error_returns_none(self, mock_get):
        f = _make_finding()
        mock_get.side_effect = Exception("Network error")
        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url is None


# ---------- create_issue ----------

class TestCreateIssue:

    @patch("vigil.issue_manager.httpx.post")
    def test_creates_issue_successfully(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"html_url": "https://github.com/o/r/issues/10"},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        f = _make_finding()
        url = create_issue("o", "r", "token", f, "Security")
        assert url == "https://github.com/o/r/issues/10"

        # Verify the request payload
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert _VIGIL_LABEL in payload["labels"]
        assert "[Vigil/Security]" in payload["title"]
        assert _VIGIL_ISSUE_MARKER in payload["body"]

    @patch("vigil.issue_manager.httpx.post")
    def test_api_failure_returns_none(self, mock_post):
        mock_post.side_effect = Exception("API error")
        f = _make_finding()
        url = create_issue("o", "r", "token", f, "Security")
        assert url is None


# ---------- create_issues_for_observations ----------

class TestCreateIssuesForObservations:

    def test_no_observations_returns_empty(self):
        result = _make_result(observations=[])
        issues = create_issues_for_observations("o", "r", "token", result)
        assert issues == []

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager.find_existing_issue")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_creates_new_issues(self, mock_label, mock_find, mock_create):
        mock_label.return_value = True
        mock_find.return_value = None
        mock_create.return_value = "https://github.com/o/r/issues/1"

        obs = _make_finding()
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 1
        assert issues[0][1] == "https://github.com/o/r/issues/1"
        mock_create.assert_called_once()

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager.find_existing_issue")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_deduplicates_against_existing(self, mock_label, mock_find, mock_create):
        mock_label.return_value = True
        mock_find.return_value = "https://github.com/o/r/issues/5"

        obs = _make_finding()
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 1
        assert issues[0][1] == "https://github.com/o/r/issues/5"
        mock_create.assert_not_called()  # Should NOT create a new issue

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager.find_existing_issue")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_uses_observation_sources_for_persona(self, mock_label, mock_find, mock_create):
        mock_label.return_value = True
        mock_find.return_value = None
        mock_create.return_value = "https://github.com/o/r/issues/1"

        obs = _make_finding()
        result = _make_result(
            observations=[obs],
            observation_sources=[("Performance", obs)],
        )
        create_issues_for_observations("o", "r", "token", result)

        # Verify the persona from observation_sources was used
        call_args = mock_create.call_args
        assert call_args[1].get("persona") or call_args[0][4] == "Performance"

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager.find_existing_issue")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_handles_create_failure_gracefully(self, mock_label, mock_find, mock_create):
        mock_label.return_value = True
        mock_find.return_value = None
        mock_create.return_value = None  # Creation failed

        obs = _make_finding()
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 0  # Failed creation means no issue returned

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager.find_existing_issue")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_multiple_observations(self, mock_label, mock_find, mock_create):
        mock_label.return_value = True
        mock_find.return_value = None

        obs1 = _make_finding(file="a.py", message="Issue A")
        obs2 = _make_finding(file="b.py", message="Issue B")

        # Return different URLs for each
        mock_create.side_effect = [
            "https://github.com/o/r/issues/1",
            "https://github.com/o/r/issues/2",
        ]

        verdict = PersonaVerdict(
            persona="Logic", decision="APPROVE",
            checks={}, findings=[], observations=[obs1, obs2],
        )
        result = _make_result(observations=[obs1, obs2], verdicts=[verdict])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 2
        assert mock_create.call_count == 2
