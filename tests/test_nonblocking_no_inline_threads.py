"""Tests for issue #52 — a review that does not block must open no threads.

GitHub renders every inline review comment as an *unresolved* review thread.
Under a ruleset that requires all threads resolved, a Vigil review that
approves while posting inline comments blocks the very PR it just approved.

The line between blocking and non-blocking already exists in this codebase
and is not redrawn here: observations are non-blocking notes and were always
summary-only, and a non-blocking persona's findings are moved into
observations by the reviewer. What was left was the narrow case these tests
pin down — findings that survive into a review whose aggregate verdict is
APPROVE. By that review's own conclusion they do not block the merge, so
they must not open threads; they are reported in the body instead, so no
information is lost.

Mocking policy matches TestPostReviewOutcome in test_rereview_and_dismissal:
only the HTTP boundary is mocked, so the real placement logic, body builder
and 422 fallback ladder all run.

The diff fixture matters. Its lines are genuinely commentable, which is what
makes these tests non-vacuous: the same findings DO land inline when the
verdict blocks (asserted below), so an APPROVE asserting "no comments" is
asserting the suppression, not an accident of placement.
"""

from unittest.mock import MagicMock, patch

import pytest

from vigil.github_review import is_blocking_decision, post_review
from vigil.models import Finding, PersonaVerdict, ReviewResult, Severity


SHA = "a1b2c3d" + "0" * 33

# commentable_lines(DIFF) == {"src/auth.py": {40, 41, 42}}
DIFF = """diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -40,2 +40,3 @@
 def login(user):
+    query = "SELECT * FROM users WHERE name = " + user
     return run(query)
"""

SQL_MESSAGE = "Concatenated SQL built from user input"
NAMING_MESSAGE = "Variable name could be clearer"
OBSERVATION_MESSAGE = "Consider a docstring here"


# ---------- helpers ----------

def _finding(message=SQL_MESSAGE, line=41, category="SQL Injection", severity=Severity.high):
    return Finding(
        file="src/auth.py",
        line=line,
        severity=severity,
        category=category,
        message=message,
    )


def _observation(message=OBSERVATION_MESSAGE):
    return Finding(
        file="src/auth.py",
        line=42,
        severity=Severity.low,
        category="Style",
        message=message,
    )


def _result(decision, findings=(), observations=(), lead_findings=()):
    """One specialist verdict plus optional lead findings and observations."""
    verdict = PersonaVerdict(
        persona="Security",
        session_id="VGL-abc123",
        decision="APPROVE" if decision == "APPROVE" else "REQUEST_CHANGES",
        checks={},
        findings=list(findings),
        observations=list(observations),
    )
    return ReviewResult(
        decision=decision,
        summary="Reviewed.",
        commit_sha=SHA,
        specialist_verdicts=[verdict],
        lead_findings=list(lead_findings),
        observations=list(observations),
    )


def _ok():
    resp = MagicMock(status_code=200, text="")
    resp.json.return_value = {"html_url": "https://github.com/o/r/pull/1#review"}
    return resp


def _rejected():
    return MagicMock(status_code=422, text="Unprocessable Entity")


def _payloads(mock_post):
    return [call.kwargs["json"] for call in mock_post.call_args_list]


def _urls(mock_post):
    return [call.args[0] for call in mock_post.call_args_list]


def _inline_bodies(payload):
    return [c["body"] for c in payload.get("comments", [])]


# ---------- the verdicts that earn a thread ----------

class TestBlockingDecisionPredicate:

    @pytest.mark.parametrize("decision", ["REQUEST_CHANGES", "BLOCK"])
    def test_blocking_verdicts(self, decision):
        assert is_blocking_decision(decision) is True

    @pytest.mark.parametrize("decision", ["APPROVE", "COMMENT", "", "approve"])
    def test_everything_else_is_non_blocking(self, decision):
        assert is_blocking_decision(decision) is False


# ---------- APPROVE opens no threads ----------

class TestApproveOpensNoThreads:

    @patch("vigil.github_review.httpx.post")
    def test_approve_with_findings_sends_no_comments_key(self, mock_post):
        mock_post.return_value = _ok()

        post_review("o", "r", 1, _result("APPROVE", findings=[_finding()]), "tok", diff=DIFF)

        payload = _payloads(mock_post)[0]
        assert "comments" not in payload
        assert payload["event"] == "APPROVE"

    @patch("vigil.github_review.httpx.post")
    def test_the_same_finding_is_inline_when_the_verdict_blocks(self, mock_post):
        """Guards the test above from passing for the wrong reason."""
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1, _result("REQUEST_CHANGES", findings=[_finding()]), "tok", diff=DIFF,
        )

        payload = _payloads(mock_post)[0]
        assert len(payload["comments"]) == 1
        assert payload["comments"][0]["path"] == "src/auth.py"
        assert payload["comments"][0]["line"] == 41
        assert SQL_MESSAGE in payload["comments"][0]["body"]

    @patch("vigil.github_review.httpx.post")
    def test_block_still_posts_inline(self, mock_post):
        mock_post.return_value = _ok()

        post_review("o", "r", 1, _result("BLOCK", findings=[_finding()]), "tok", diff=DIFF)

        payload = _payloads(mock_post)[0]
        assert len(payload["comments"]) == 1
        assert payload["event"] == "REQUEST_CHANGES"  # GitHub has no BLOCK event

    @patch("vigil.github_review.httpx.post")
    def test_suppressed_findings_are_reported_in_the_body_as_non_blocking(self, mock_post):
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1,
            _result("APPROVE", findings=[_finding()], lead_findings=[_finding(NAMING_MESSAGE)]),
            "tok", diff=DIFF,
        )

        body = _payloads(mock_post)[0]["body"]
        # Nothing is lost: both findings, with their locations, are still there.
        assert SQL_MESSAGE in body
        assert NAMING_MESSAGE in body
        assert "src/auth.py:41" in body
        # And they are labelled for what they are.
        assert "Advisory Findings (2 non-blocking)" in body
        assert "Not merge-blocking" in body

    @patch("vigil.github_review.httpx.post")
    def test_lead_findings_are_suppressed_too(self, mock_post):
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1, _result("APPROVE", lead_findings=[_finding()]), "tok", diff=DIFF,
        )

        assert "comments" not in _payloads(mock_post)[0]

    @patch("vigil.github_review.httpx.post")
    def test_an_unrecognised_verdict_opens_no_threads(self, mock_post):
        """A decision that maps to a bare COMMENT is not a blocking verdict."""
        mock_post.return_value = _ok()

        post_review("o", "r", 1, _result("MAYBE", findings=[_finding()]), "tok", diff=DIFF)

        payload = _payloads(mock_post)[0]
        assert "comments" not in payload
        assert payload["event"] == "COMMENT"
        assert SQL_MESSAGE in payload["body"]

    @patch("vigil.github_review.httpx.post")
    def test_approve_without_findings_is_unchanged(self, mock_post):
        mock_post.return_value = _ok()

        post_review("o", "r", 1, _result("APPROVE"), "tok", diff=DIFF)

        payload = _payloads(mock_post)[0]
        assert "comments" not in payload
        assert "Advisory Findings" not in payload["body"]

    @patch("vigil.github_review.httpx.post")
    def test_the_verdict_itself_is_untouched(self, mock_post):
        """Scope is the posting artifact — the review still approves."""
        mock_post.return_value = _ok()

        outcome: dict = {}
        post_review(
            "o", "r", 1, _result("APPROVE", findings=[_finding()]), "tok",
            diff=DIFF, outcome=outcome,
        )

        assert outcome["requested_event"] == "APPROVE"
        assert outcome["submitted_event"] == "APPROVE"


# ---------- observations stay summary-only, as they already were ----------

class TestObservationsNeverInline:

    @patch("vigil.github_review.httpx.post")
    def test_observations_are_not_inline_on_approve(self, mock_post):
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1, _result("APPROVE", observations=[_observation()]), "tok", diff=DIFF,
        )

        payload = _payloads(mock_post)[0]
        assert "comments" not in payload
        assert OBSERVATION_MESSAGE in payload["body"]
        assert "non-blocking" in payload["body"]

    @patch("vigil.github_review.httpx.post")
    def test_observations_are_not_inline_on_request_changes(self, mock_post):
        """A mixed review: blocking findings inline, advisory observations in the body."""
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1,
            _result("REQUEST_CHANGES", findings=[_finding()], observations=[_observation()]),
            "tok", diff=DIFF,
        )

        payload = _payloads(mock_post)[0]
        assert len(payload["comments"]) == 1
        inline = _inline_bodies(payload)
        assert SQL_MESSAGE in inline[0]
        assert all(OBSERVATION_MESSAGE not in b for b in inline)
        assert OBSERVATION_MESSAGE in payload["body"]

    @patch("vigil.github_review.httpx.post")
    def test_observation_issue_links_survive_suppression(self, mock_post):
        """The observations→issues flow is unchanged on the suppressed path."""
        mock_post.return_value = _ok()
        obs = _observation()

        post_review(
            "o", "r", 1, _result("APPROVE", findings=[_finding()], observations=[obs]), "tok",
            diff=DIFF,
            observation_issues=[(obs, "https://github.com/o/r/issues/77")],
        )

        body = _payloads(mock_post)[0]["body"]
        assert "[#77](https://github.com/o/r/issues/77)" in body


# ---------- the body must not lie about what was posted ----------

class TestBodyCountersStayHonest:

    @patch("vigil.github_review.httpx.post")
    def test_approve_body_claims_no_inline_comments(self, mock_post):
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1,
            _result("APPROVE", findings=[_finding(), _finding(NAMING_MESSAGE, line=42)]),
            "tok", diff=DIFF,
        )

        body = _payloads(mock_post)[0]["body"]
        assert "inline comments" not in body
        # The findings still happened, and the footer still counts them.
        assert "2 findings" in body
        assert "Advisory Findings (2 non-blocking)" in body

    @patch("vigil.github_review.httpx.post")
    def test_blocking_body_still_counts_its_inline_comments(self, mock_post):
        mock_post.return_value = _ok()

        post_review(
            "o", "r", 1,
            _result("REQUEST_CHANGES", findings=[_finding(), _finding(NAMING_MESSAGE, line=42)]),
            "tok", diff=DIFF,
        )

        payload = _payloads(mock_post)[0]
        assert len(payload["comments"]) == 2
        assert "2 inline comments" in payload["body"]
        assert "Advisory Findings" not in payload["body"]

    @patch("vigil.github_review.httpx.post")
    def test_findings_outside_the_diff_still_use_the_not_in_diff_section(self, mock_post):
        """Unchanged behaviour on the blocking path: unplaceable findings go in the body."""
        mock_post.return_value = _ok()
        stray = Finding(
            file="untouched/module.py", line=9, severity=Severity.medium,
            category="Logic", message=NAMING_MESSAGE,
        )

        post_review(
            "o", "r", 1, _result("REQUEST_CHANGES", findings=[stray]), "tok", diff="",
        )

        payload = _payloads(mock_post)[0]
        assert "comments" not in payload
        assert "Findings (not in diff)" in payload["body"]
        assert NAMING_MESSAGE in payload["body"]


# ---------- the 422 fallback ladder cannot smuggle threads back in ----------

class TestFallbackLadder:

    @patch("vigil.github_review.httpx.post")
    def test_no_rung_of_the_ladder_regains_comments_on_approve(self, mock_post):
        """422 → COMMENT retry → issue comment, and none of them carry threads."""
        mock_post.side_effect = [_rejected(), _rejected(), _ok()]

        outcome: dict = {}
        post_review(
            "o", "r", 1, _result("APPROVE", findings=[_finding()]), "tok",
            diff=DIFF, outcome=outcome,
        )

        payloads = _payloads(mock_post)
        assert len(payloads) == 3
        assert all("comments" not in p for p in payloads)
        assert payloads[1]["event"] == "COMMENT"
        assert outcome["submitted_event"] == "ISSUE_COMMENT"
        # The last rung is the plain issue comment, and it kept the findings.
        assert "/issues/1/comments" in _urls(mock_post)[2]
        assert SQL_MESSAGE in payloads[2]["body"]
        assert "Advisory Findings (1 non-blocking)" in payloads[2]["body"]

    @patch("vigil.github_review.httpx.post")
    def test_approve_skips_the_strip_inline_rungs_entirely(self, mock_post):
        """Attempts 2 and 4 exist only to strip inline comments — nothing to strip."""
        mock_post.side_effect = [_rejected(), _ok()]

        post_review(
            "o", "r", 1, _result("APPROVE", findings=[_finding()]), "tok", diff=DIFF,
        )

        payloads = _payloads(mock_post)
        assert len(payloads) == 2
        assert payloads[0]["event"] == "APPROVE"
        assert payloads[1]["event"] == "COMMENT"
        assert all("comments" not in p for p in payloads)

    @patch("vigil.github_review.httpx.post")
    def test_blocking_ladder_still_walks_every_rung(self, mock_post):
        """The blocking path is untouched: inline, strip, COMMENT, strip, issue."""
        mock_post.side_effect = [
            _rejected(), _rejected(), _rejected(), _rejected(), _ok(),
        ]

        outcome: dict = {}
        post_review(
            "o", "r", 1, _result("REQUEST_CHANGES", findings=[_finding()]), "tok",
            diff=DIFF, outcome=outcome,
        )

        payloads = _payloads(mock_post)
        assert len(payloads) == 5
        # Rungs 1 and 3 carry the threads; 2 and 4 fold them into the body.
        assert len(payloads[0]["comments"]) == 1
        assert "comments" not in payloads[1]
        assert len(payloads[2]["comments"]) == 1
        assert "comments" not in payloads[3]
        assert SQL_MESSAGE in payloads[1]["body"]
        assert outcome["submitted_event"] == "ISSUE_COMMENT"

    @patch("vigil.github_review.httpx.post")
    def test_body_only_retry_keeps_observation_links(self, mock_post):
        """Rung 2 rebuilds the body — it must rebuild the whole body."""
        mock_post.side_effect = [_rejected(), _ok()]
        obs = _observation()

        post_review(
            "o", "r", 1,
            _result("REQUEST_CHANGES", findings=[_finding()], observations=[obs]),
            "tok", diff=DIFF,
            observation_issues=[(obs, "https://github.com/o/r/issues/77")],
        )

        second = _payloads(mock_post)[1]["body"]
        assert "[#77](https://github.com/o/r/issues/77)" in second
        assert SQL_MESSAGE in second
