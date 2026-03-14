"""Tests for HTTP error handling in comment_manager and github modules.

Covers: _paginate, _graphql, get_diff_between_commits,
get_changed_files_between_commits, and fetch_* wrappers under
network failures, HTTP 4xx/5xx, timeouts, and pagination edge cases.
"""

import httpx
import pytest
from unittest.mock import patch, MagicMock

from vigil.comment_manager import (
    _paginate,
    _graphql,
    _github_headers,
    fetch_vigil_reviews,
    fetch_vigil_comments,
    get_last_reviewed_sha,
    resolve_threads_batch,
)
from vigil.github import (
    get_diff_between_commits,
    get_changed_files_between_commits,
    get_pr_data,
    parse_pr_url,
)


# ---------- helpers ----------

def _mock_response(status_code=200, json_data=None, text="", headers=None):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else []
    resp.text = text
    resp.headers = headers or {}
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code}", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# ---------- _paginate ----------

class TestPaginate:

    @patch("vigil.comment_manager.httpx.Client")
    def test_single_page(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(
            json_data=[{"id": 1}, {"id": 2}],
            headers={},
        )

        result = _paginate("https://api.github.com/test", {"Auth": "token"})
        assert len(result) == 2
        assert result[0]["id"] == 1

    @patch("vigil.comment_manager.httpx.Client")
    def test_multi_page_pagination(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        page1 = _mock_response(
            json_data=[{"id": 1}],
            headers={"Link": '<https://api.github.com/test?page=2>; rel="next"'},
        )
        page2 = _mock_response(
            json_data=[{"id": 2}],
            headers={},
        )
        client.get.side_effect = [page1, page2]

        result = _paginate("https://api.github.com/test", {"Auth": "token"})
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 2
        assert client.get.call_count == 2

    @patch("vigil.comment_manager.httpx.Client")
    def test_http_404_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(status_code=404)

        with pytest.raises(httpx.HTTPStatusError):
            _paginate("https://api.github.com/test", {"Auth": "token"})

    @patch("vigil.comment_manager.httpx.Client")
    def test_http_500_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(status_code=500)

        with pytest.raises(httpx.HTTPStatusError):
            _paginate("https://api.github.com/test", {"Auth": "token"})

    @patch("vigil.comment_manager.httpx.Client")
    def test_timeout_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.side_effect = httpx.TimeoutException("Connection timed out")

        with pytest.raises(httpx.TimeoutException):
            _paginate("https://api.github.com/test", {"Auth": "token"})

    @patch("vigil.comment_manager.httpx.Client")
    def test_connection_error_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.side_effect = httpx.ConnectError("Connection refused")

        with pytest.raises(httpx.ConnectError):
            _paginate("https://api.github.com/test", {"Auth": "token"})

    @patch("vigil.comment_manager.httpx.Client")
    def test_empty_response(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(json_data=[], headers={})

        result = _paginate("https://api.github.com/test", {"Auth": "token"})
        assert result == []

    @patch("vigil.comment_manager.httpx.Client")
    def test_link_header_with_multiple_rels(self, mock_client_cls):
        """Link header may contain both next and last rels."""
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        page1 = _mock_response(
            json_data=[{"id": 1}],
            headers={
                "Link": '<https://api.github.com/test?page=2>; rel="next", '
                        '<https://api.github.com/test?page=5>; rel="last"'
            },
        )
        page2 = _mock_response(json_data=[{"id": 2}], headers={})
        client.get.side_effect = [page1, page2]

        result = _paginate("https://api.github.com/test", {"Auth": "token"})
        assert len(result) == 2

    @patch("vigil.comment_manager.httpx.Client")
    def test_params_only_sent_on_first_request(self, mock_client_cls):
        """After first page, params should be None (baked into Link URL)."""
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        page1 = _mock_response(
            json_data=[{"id": 1}],
            headers={"Link": '<https://api.github.com/test?page=2&per_page=100>; rel="next"'},
        )
        page2 = _mock_response(json_data=[{"id": 2}], headers={})
        client.get.side_effect = [page1, page2]

        _paginate("https://api.github.com/test", {"Auth": "token"}, params={"foo": "bar"})

        # First call should have params
        first_call = client.get.call_args_list[0]
        assert first_call.kwargs.get("params") is not None
        # Second call should have params=None
        second_call = client.get.call_args_list[1]
        assert second_call.kwargs.get("params") is None


# ---------- _graphql ----------

class TestGraphql:

    @patch("vigil.comment_manager.httpx.post")
    def test_success(self, mock_post):
        mock_post.return_value = _mock_response(
            json_data={"data": {"repository": {}}},
        )
        result = _graphql("query { viewer { login } }", {}, "token")
        assert "data" in result

    @patch("vigil.comment_manager.httpx.post")
    def test_http_401_raises(self, mock_post):
        mock_post.return_value = _mock_response(status_code=401)
        with pytest.raises(httpx.HTTPStatusError):
            _graphql("query { viewer { login } }", {}, "bad-token")

    @patch("vigil.comment_manager.httpx.post")
    def test_timeout_raises(self, mock_post):
        mock_post.side_effect = httpx.TimeoutException("timed out")
        with pytest.raises(httpx.TimeoutException):
            _graphql("query {}", {}, "token")

    @patch("vigil.comment_manager.httpx.post")
    def test_graphql_errors_logged_not_raised(self, mock_post):
        """GraphQL errors in the response body are logged but don't raise."""
        mock_post.return_value = _mock_response(
            json_data={"data": None, "errors": [{"message": "Not found"}]},
        )
        # Should not raise — errors are logged
        result = _graphql("query {}", {}, "token")
        assert "errors" in result

    @patch("vigil.comment_manager.httpx.post")
    def test_connection_error_raises(self, mock_post):
        mock_post.side_effect = httpx.ConnectError("DNS resolution failed")
        with pytest.raises(httpx.ConnectError):
            _graphql("query {}", {}, "token")


# ---------- resolve_threads_batch ----------

class TestResolveThreadsBatchErrors:

    @patch("vigil.comment_manager._graphql")
    def test_graphql_failure_returns_empty(self, mock_gql):
        """If the batch mutation fails, return empty (don't crash)."""
        mock_gql.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )
        result = resolve_threads_batch(["thread_1", "thread_2"], "token")
        assert result == []

    @patch("vigil.comment_manager._graphql")
    def test_partial_success(self, mock_gql):
        """Some threads resolve, some don't — return only the resolved ones."""
        mock_gql.return_value = {
            "data": {
                "t0": {"thread": {"id": "a", "isResolved": True}},
                "t1": {"thread": {"id": "b", "isResolved": False}},
            }
        }
        result = resolve_threads_batch(["thread_a", "thread_b"], "token")
        assert len(result) == 1
        assert result[0] == "thread_a"


# ---------- get_diff_between_commits ----------

class TestGetDiffBetweenCommits:

    @patch("vigil.github.httpx.Client")
    def test_success(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(text="diff --git a/file b/file\n+new line")

        result = get_diff_between_commits("owner", "repo", "abc123", "def456", "token")
        assert "diff --git" in result

    @patch("vigil.github.httpx.Client")
    def test_404_force_push_raises(self, mock_client_cls):
        """If base SHA no longer exists (force push), GitHub returns 404."""
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(status_code=404)

        with pytest.raises(httpx.HTTPStatusError):
            get_diff_between_commits("owner", "repo", "gone_sha", "head", "token")

    @patch("vigil.github.httpx.Client")
    def test_timeout_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.side_effect = httpx.TimeoutException("timed out")

        with pytest.raises(httpx.TimeoutException):
            get_diff_between_commits("owner", "repo", "a", "b", "token")

    @patch("vigil.github.httpx.Client")
    def test_500_server_error_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(status_code=500)

        with pytest.raises(httpx.HTTPStatusError):
            get_diff_between_commits("owner", "repo", "a", "b", "token")


# ---------- get_changed_files_between_commits ----------

class TestGetChangedFilesBetweenCommits:

    @patch("vigil.github.httpx.Client")
    def test_success(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(
            json_data={"files": [{"filename": "a.py"}, {"filename": "b.py"}]},
        )

        result = get_changed_files_between_commits("o", "r", "a", "b", "token")
        assert result == ["a.py", "b.py"]

    @patch("vigil.github.httpx.Client")
    def test_empty_files_list(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(json_data={"files": []})

        result = get_changed_files_between_commits("o", "r", "a", "b", "token")
        assert result == []

    @patch("vigil.github.httpx.Client")
    def test_no_files_key(self, mock_client_cls):
        """API response missing 'files' key should return empty list."""
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(json_data={})

        result = get_changed_files_between_commits("o", "r", "a", "b", "token")
        assert result == []

    @patch("vigil.github.httpx.Client")
    def test_404_raises(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        client.get.return_value = _mock_response(status_code=404)

        with pytest.raises(httpx.HTTPStatusError):
            get_changed_files_between_commits("o", "r", "gone", "head", "token")


# ---------- fetch_vigil_reviews ----------

class TestFetchVigilReviews:

    @patch("vigil.comment_manager._paginate")
    def test_filters_to_vigil_only(self, mock_paginate):
        mock_paginate.return_value = [
            {"id": 1, "body": "Some other review"},
            {"id": 2, "body": "Reviewed by [Vigil] — AI-powered"},
            {"id": 3, "body": None},
        ]
        result = fetch_vigil_reviews("o", "r", 1, "token")
        assert len(result) == 1
        assert result[0]["id"] == 2

    @patch("vigil.comment_manager._paginate")
    def test_empty_reviews(self, mock_paginate):
        mock_paginate.return_value = []
        result = fetch_vigil_reviews("o", "r", 1, "token")
        assert result == []


# ---------- get_last_reviewed_sha ----------

class TestGetLastReviewedSha:

    @patch("vigil.comment_manager.fetch_vigil_reviews")
    def test_returns_latest_commit_id(self, mock_fetch):
        mock_fetch.return_value = [
            {"submitted_at": "2026-01-01T00:00:00Z", "commit_id": "old_sha"},
            {"submitted_at": "2026-03-01T00:00:00Z", "commit_id": "new_sha"},
        ]
        result = get_last_reviewed_sha("o", "r", 1, "token")
        assert result == "new_sha"

    @patch("vigil.comment_manager.fetch_vigil_reviews")
    def test_no_reviews_returns_none(self, mock_fetch):
        mock_fetch.return_value = []
        result = get_last_reviewed_sha("o", "r", 1, "token")
        assert result is None


# ---------- parse_pr_url ----------

class TestParsePrUrl:

    def test_valid_url(self):
        owner, repo, num = parse_pr_url("https://github.com/F2iProject/vigil/pull/2")
        assert owner == "F2iProject"
        assert repo == "vigil"
        assert num == 2

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            parse_pr_url("https://example.com/not/a/pr")

    def test_missing_number_raises(self):
        with pytest.raises(ValueError):
            parse_pr_url("https://github.com/owner/repo/pull/")
