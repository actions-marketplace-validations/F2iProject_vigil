"""Tests for issue_manager: issue creation, dedup, label management, pagination."""

import pytest
from unittest.mock import patch, MagicMock

from vigil.issue_manager import (
    _build_issue_body,
    _build_issue_title,
    _fetch_all_vigil_issues,
    _match_finding_to_issue,
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


def _make_vigil_issue(file="src/app.py", line=10, message="Shared counter accessed without a lock"):
    """Build a mock Vigil issue dict."""
    loc = f"`{file}"
    if line:
        loc += f":{line}"
    loc += "`"
    return {
        "html_url": "https://github.com/o/r/issues/5",
        "body": f"{_VIGIL_ISSUE_MARKER}\n**File:** {loc}\n### Finding\n\n{message}\n---",
    }


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


# ---------- _match_finding_to_issue ----------

class TestMatchFindingToIssue:

    def test_matches_identical_message(self):
        f = _make_finding(message="Shared counter accessed without a lock")
        issues = [_make_vigil_issue(message="Shared counter accessed without a lock")]
        assert _match_finding_to_issue(f, issues) == "https://github.com/o/r/issues/5"

    def test_no_match_different_file(self):
        f = _make_finding(file="other.py", message="Shared counter accessed without a lock")
        issues = [_make_vigil_issue(file="src/app.py")]
        assert _match_finding_to_issue(f, issues) is None

    def test_no_match_different_message(self):
        f = _make_finding(message="Completely different issue")
        issues = [_make_vigil_issue(message="Shared counter accessed without a lock")]
        assert _match_finding_to_issue(f, issues) is None

    def test_no_match_without_marker(self):
        f = _make_finding()
        issues = [{"html_url": "url", "body": "Regular issue without marker"}]
        assert _match_finding_to_issue(f, issues) is None

    def test_empty_issues_list(self):
        f = _make_finding()
        assert _match_finding_to_issue(f, []) is None

    def test_similar_message_matches(self):
        f = _make_finding(message="Shared counter is accessed without proper locking mechanism")
        issues = [_make_vigil_issue(message="Shared counter is accessed without a proper lock mechanism")]
        result = _match_finding_to_issue(f, issues)
        assert result == "https://github.com/o/r/issues/5"


# ---------- find_existing_issue ----------

class TestFindExistingIssue:

    def test_with_prefetched_issues(self):
        f = _make_finding(message="Shared counter accessed without a lock")
        issues = [_make_vigil_issue(message="Shared counter accessed without a lock")]
        url = find_existing_issue("o", "r", "token", f, "Logic", existing_issues=issues)
        assert url == "https://github.com/o/r/issues/5"

    def test_no_match_with_prefetched(self):
        f = _make_finding(message="Unique issue")
        issues = [_make_vigil_issue(message="Different issue entirely")]
        url = find_existing_issue("o", "r", "token", f, "Logic", existing_issues=issues)
        assert url is None

    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    def test_fetches_when_no_prefetched(self, mock_fetch):
        f = _make_finding()
        mock_fetch.return_value = []
        url = find_existing_issue("o", "r", "token", f, "Logic")
        assert url is None
        mock_fetch.assert_called_once_with("o", "r", "token")


# ---------- _fetch_all_vigil_issues (pagination) ----------

class TestFetchAllVigilIssues:

    @patch("vigil.issue_manager.httpx.Client")
    def test_single_page(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"id": 1}, {"id": 2}]
        mock_resp.headers = {}
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        issues = _fetch_all_vigil_issues("o", "r", "token")
        assert len(issues) == 2

    @patch("vigil.issue_manager.httpx.Client")
    def test_pagination_follows_links(self, mock_client_cls):
        # First page: returns Link header with next
        resp1 = MagicMock()
        resp1.json.return_value = [{"id": 1}]
        resp1.headers = {"Link": '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"'}
        resp1.raise_for_status = MagicMock()

        # Second page: no Link header
        resp2 = MagicMock()
        resp2.json.return_value = [{"id": 2}]
        resp2.headers = {}
        resp2.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.side_effect = [resp1, resp2]
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        issues = _fetch_all_vigil_issues("o", "r", "token")
        assert len(issues) == 2
        assert mock_client.get.call_count == 2

    @patch("vigil.issue_manager.httpx.Client")
    def test_api_error_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("Network error")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        issues = _fetch_all_vigil_issues("o", "r", "token")
        assert issues == []


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
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_creates_new_issues(self, mock_label, mock_fetch, mock_create):
        mock_label.return_value = True
        mock_fetch.return_value = []  # No existing issues
        mock_create.return_value = "https://github.com/o/r/issues/1"

        obs = _make_finding()
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 1
        assert issues[0][1] == "https://github.com/o/r/issues/1"
        mock_create.assert_called_once()

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_deduplicates_against_existing(self, mock_label, mock_fetch, mock_create):
        mock_label.return_value = True
        mock_fetch.return_value = [
            _make_vigil_issue(message="Shared counter accessed without a lock")
        ]

        obs = _make_finding(message="Shared counter accessed without a lock")
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 1
        assert issues[0][1] == "https://github.com/o/r/issues/5"
        mock_create.assert_not_called()  # Should NOT create a new issue

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_uses_observation_sources_for_persona(self, mock_label, mock_fetch, mock_create):
        mock_label.return_value = True
        mock_fetch.return_value = []
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
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_handles_create_failure_gracefully(self, mock_label, mock_fetch, mock_create):
        mock_label.return_value = True
        mock_fetch.return_value = []
        mock_create.return_value = None  # Creation failed

        obs = _make_finding()
        result = _make_result(observations=[obs])
        issues = create_issues_for_observations("o", "r", "token", result)

        assert len(issues) == 0  # Failed creation means no issue returned

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_multiple_observations(self, mock_label, mock_fetch, mock_create):
        mock_label.return_value = True
        mock_fetch.return_value = []

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

    @patch("vigil.issue_manager.create_issue")
    @patch("vigil.issue_manager._fetch_all_vigil_issues")
    @patch("vigil.issue_manager.ensure_vigil_label")
    def test_prefetches_issues_once(self, mock_label, mock_fetch, mock_create):
        """Verify issues are fetched once (not per observation) to avoid N+1."""
        mock_label.return_value = True
        mock_fetch.return_value = []
        mock_create.return_value = "https://github.com/o/r/issues/1"

        obs1 = _make_finding(file="a.py", message="Issue A")
        obs2 = _make_finding(file="b.py", message="Issue B")
        obs3 = _make_finding(file="c.py", message="Issue C")

        verdict = PersonaVerdict(
            persona="Logic", decision="APPROVE",
            checks={}, findings=[], observations=[obs1, obs2, obs3],
        )
        result = _make_result(observations=[obs1, obs2, obs3], verdicts=[verdict])
        create_issues_for_observations("o", "r", "token", result)

        # Issues should be fetched exactly ONCE regardless of observation count
        mock_fetch.assert_called_once()
