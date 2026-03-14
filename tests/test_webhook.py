"""Tests for the webhook server: signature verification, event routing, app creation."""

import hashlib
import hmac
import json

import pytest

from vigil.webhook import (
    _extract_pr_url,
    _should_dismiss,
    _should_review,
    _verify_signature,
    create_app,
)


# ---------- _verify_signature ----------

class TestVerifySignature:

    def test_valid_signature(self):
        payload = b'{"action": "opened"}'
        secret = "test-secret"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert _verify_signature(payload, f"sha256={expected}", secret) is True

    def test_invalid_signature(self):
        payload = b'{"action": "opened"}'
        assert _verify_signature(payload, "sha256=invalid", "test-secret") is False

    def test_missing_signature(self):
        assert _verify_signature(b"payload", "", "secret") is False

    def test_missing_secret(self):
        assert _verify_signature(b"payload", "sha256=abc", "") is False

    def test_wrong_prefix(self):
        assert _verify_signature(b"payload", "sha1=abc", "secret") is False


# ---------- _extract_pr_url ----------

class TestExtractPrUrl:

    def test_pull_request_event(self):
        payload = {"pull_request": {"html_url": "https://github.com/o/r/pull/1"}}
        assert _extract_pr_url("pull_request", payload) == "https://github.com/o/r/pull/1"

    def test_issue_comment_on_pr(self):
        payload = {
            "issue": {
                "html_url": "https://github.com/o/r/issues/1",
                "pull_request": {"url": "..."},
            }
        }
        assert _extract_pr_url("issue_comment", payload) == "https://github.com/o/r/pull/1"

    def test_issue_comment_on_issue(self):
        payload = {"issue": {"html_url": "https://github.com/o/r/issues/1"}}
        assert _extract_pr_url("issue_comment", payload) is None

    def test_unknown_event(self):
        assert _extract_pr_url("push", {}) is None

    def test_missing_pr_data(self):
        assert _extract_pr_url("pull_request", {}) is None


# ---------- _should_review ----------

class TestShouldReview:

    def test_pr_opened(self):
        payload = {
            "action": "opened",
            "pull_request": {"draft": False, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is True

    def test_pr_reopened(self):
        payload = {
            "action": "reopened",
            "pull_request": {"draft": False, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is True

    def test_pr_ready_for_review(self):
        payload = {
            "action": "ready_for_review",
            "pull_request": {"draft": False, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is True

    def test_pr_synchronize_skipped(self):
        payload = {
            "action": "synchronize",
            "pull_request": {"draft": False, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is False

    def test_pr_draft_skipped(self):
        payload = {
            "action": "opened",
            "pull_request": {"draft": True, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is False

    def test_pr_bot_skipped(self):
        payload = {
            "action": "opened",
            "pull_request": {"draft": False, "user": {"type": "Bot"}},
        }
        assert _should_review("pull_request", payload) is False

    def test_vigil_review_command(self):
        payload = {
            "action": "created",
            "comment": {"body": "/vigil review"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_review("issue_comment", payload) is True

    def test_vigil_review_command_with_text(self):
        payload = {
            "action": "created",
            "comment": {"body": "Please /vigil review this PR"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_review("issue_comment", payload) is True

    def test_non_vigil_comment_skipped(self):
        payload = {
            "action": "created",
            "comment": {"body": "LGTM"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_review("issue_comment", payload) is False

    def test_comment_on_issue_not_pr(self):
        payload = {
            "action": "created",
            "comment": {"body": "/vigil review"},
            "issue": {},
        }
        assert _should_review("issue_comment", payload) is False

    def test_comment_edited_skipped(self):
        payload = {
            "action": "edited",
            "comment": {"body": "/vigil review"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_review("issue_comment", payload) is False

    def test_push_event_skipped(self):
        assert _should_review("push", {}) is False

    def test_pr_closed_skipped(self):
        payload = {
            "action": "closed",
            "pull_request": {"draft": False, "user": {"type": "User"}},
        }
        assert _should_review("pull_request", payload) is False


# ---------- _should_dismiss ----------

class TestShouldDismiss:

    def test_resolved_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "resolved"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_fixed_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "fixed"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_addressed_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "addressed"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_done_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "done"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_issue_link_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "Fixed in #45"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_full_issue_url_reply(self):
        payload = {
            "action": "created",
            "comment": {"body": "See https://github.com/org/repo/issues/123"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is True

    def test_unrelated_comment(self):
        payload = {
            "action": "created",
            "comment": {"body": "LGTM"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is False

    def test_not_on_pr(self):
        payload = {
            "action": "created",
            "comment": {"body": "resolved"},
            "issue": {},
        }
        assert _should_dismiss("issue_comment", payload) is False

    def test_wrong_event(self):
        payload = {"action": "created"}
        assert _should_dismiss("pull_request", payload) is False

    def test_edited_action_skipped(self):
        payload = {
            "action": "edited",
            "comment": {"body": "resolved"},
            "issue": {"pull_request": {"url": "..."}},
        }
        assert _should_dismiss("issue_comment", payload) is False


# ---------- create_app ----------

class TestCreateApp:

    def test_app_created(self):
        app = create_app()
        assert app.title == "Vigil Webhook Server"

    def test_health_endpoint(self):
        from fastapi.testclient import TestClient
        app = create_app()
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_ping_event(self):
        from fastapi.testclient import TestClient
        app = create_app()
        client = TestClient(app)
        resp = client.post(
            "/webhook",
            json={"zen": "Keep it simple"},
            headers={"X-GitHub-Event": "ping"},
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "pong"

    def test_invalid_signature_rejected(self):
        from fastapi.testclient import TestClient
        app = create_app(webhook_secret="my-secret")
        client = TestClient(app)
        resp = client.post(
            "/webhook",
            json={"action": "opened"},
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=invalid",
            },
        )
        assert resp.status_code == 401

    def test_no_signature_check_without_secret(self):
        from fastapi.testclient import TestClient
        app = create_app(webhook_secret="")
        client = TestClient(app)
        resp = client.post(
            "/webhook",
            json={"zen": "Keep it simple"},
            headers={"X-GitHub-Event": "ping"},
        )
        assert resp.status_code == 200

    def test_skip_event(self):
        from fastapi.testclient import TestClient
        app = create_app()
        client = TestClient(app)
        resp = client.post(
            "/webhook",
            json={"action": "closed", "pull_request": {"html_url": "https://github.com/o/r/pull/1"}},
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "skip"

    def test_review_triggered(self):
        from unittest.mock import patch
        from fastapi.testclient import TestClient
        app = create_app()
        client = TestClient(app)
        with patch("vigil.webhook.threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: None
            resp = client.post(
                "/webhook",
                json={
                    "action": "opened",
                    "pull_request": {
                        "html_url": "https://github.com/o/r/pull/1",
                        "draft": False,
                        "user": {"type": "User"},
                    },
                },
                headers={"X-GitHub-Event": "pull_request"},
            )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Review triggered"

    def test_invalid_json(self):
        from fastapi.testclient import TestClient
        app = create_app()
        client = TestClient(app)
        resp = client.post(
            "/webhook",
            content=b"not json",
            headers={
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        # FastAPI will return 422 for invalid JSON
        assert resp.status_code in (400, 422)
