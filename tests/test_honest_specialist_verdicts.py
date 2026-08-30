"""Tests for issue #66 — a verdict table implies verdicts were reached.

Vigil synthesizes an APPROVE `PersonaVerdict` for specialists that never ran:
one when no file in the diff matches the specialist's patterns, one when its
model call fails transiently. Both rendered in the review body exactly like a
specialist that read the diff and found nothing — `| ✅ | **Security** | APPROVE
|` — and the lead's prompt was told the same thing. #66 was reported after a
formal GitHub approval showed six specialists each ✅ APPROVE for a code path
that made zero model calls, and two automated readers took that table as
evidence a review had happened.

That specific bypass (the documentation-only short-circuit) was deleted in #63
and is not what these tests cover. What survives on main is the class the issue
names, and this repo has a written policy against it: Vigil must never render
green for review work that did not happen (#51 item 1, #53, and the #62
CHANGELOG entry — "here Vigil ran, reported success, and did nothing").

The fix is reporting-only, and these tests pin both halves of that:

- What Vigil *says* changes. A verdict with `reviewed=False` renders as NOT
  REVIEWED with a skip marker, never a check-mark and never the word APPROVE;
  a stable `<!-- vigil-specialists-not-run: ... -->` marker names them for
  machines; the "Reviewed commit X with Y" header stops claiming a review that
  did not occur; and the lead model is told the domain was UNEXAMINED.
- What Vigil *does* is unchanged. `decision` stays "APPROVE",
  `is_blocking_decision()` still says False, and the review still submits an
  APPROVE event with no inline threads. TestGatingDidNotChange guards that
  boundary explicitly — a fix for a misleading report must not quietly become
  a merge-gating change.

The CLI's live per-specialist line is covered here too. It is a different
surface but the same false statement, and a worse one: its zero-findings
fallback printed the word "clean" about a domain nobody examined, on the
output an operator watches while deciding whether to trust a run.

The non-transient specialist error path is deliberately untouched: it already
sets `decision="ERROR"` and renders as `⚠️ ERROR`, which no reader mistakes
for a completed clean review. A regression test below holds it in place, and
the marker's comment states that absence from it is not a claim that a
specialist reached a verdict.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from vigil import cli
from vigil.github_review import (
    SPECIALISTS_NOT_RUN_MARKER,
    _build_review_body,
    is_blocking_decision,
    post_review,
)
from vigil.models import (
    SKIP_NO_FILES_IN_SCOPE,
    SKIP_REVIEWER_UNAVAILABLE,
    Finding,
    PersonaVerdict,
    ReviewResult,
    Severity,
)
from vigil.personas import Persona, ReviewProfile
from vigil.reviewer import review_diff
from vigil.utils import not_reviewed_label


SHA = "abc1234" + "0" * 33
MODEL = "gemini/gemini-3.1-flash-lite"

# Matches only *.py, so a specialist scoped to *.tsx gets an empty diff and is
# skipped without a model call — the no_files_in_scope path.
DIFF = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 def handler():
+    return compute()
     pass
"""


# ---------- helpers ----------

def _verdict(
    persona="Security",
    reviewed=True,
    skip_reason="",
    decision="APPROVE",
    checks=None,
    observations=(),
):
    return PersonaVerdict(
        persona=persona,
        session_id="VGL-abc123",
        decision=decision,
        checks={"input_validation": "PASS"} if checks is None else checks,
        findings=[],
        observations=list(observations),
        reviewed=reviewed,
        skip_reason=skip_reason,
    )


def _not_reviewed(persona="Security", skip_reason=SKIP_NO_FILES_IN_SCOPE, observations=()):
    """A synthesized verdict: APPROVE decision, but no model call was made."""
    return _verdict(
        persona=persona,
        reviewed=False,
        skip_reason=skip_reason,
        checks={},
        observations=observations,
    )


def _result(verdicts, decision="APPROVE", commit_sha=SHA):
    return ReviewResult(
        decision=decision,
        summary="Reviewed.",
        commit_sha=commit_sha,
        model=MODEL,
        specialist_verdicts=list(verdicts),
        lead_findings=[],
        observations=[obs for v in verdicts for obs in v.observations],
    )


def _row(body: str, persona: str) -> str:
    """Return the specialist table row for ``persona``."""
    matches = [
        line for line in body.splitlines()
        if line.startswith("|") and f"**{persona}**" in line
    ]
    assert len(matches) == 1, f"expected exactly one table row for {persona}: {matches}"
    return matches[0]


def _profile(*specialists):
    return ReviewProfile(
        name="test", specialists=list(specialists), lead_prompt="You are the lead.",
    )


def _pr_context():
    return {
        "title": "Test PR", "author": "user", "head": "feature", "base": "main",
        "additions": 1, "deletions": 0, "changed_files": 1, "body": "",
    }


class _RecordingConsole:
    """Captures the rich markup `cli` prints, tags and all.

    Asserting on the markup rather than the rendered text is deliberate: the
    colour is part of what #66 is about — a green line reads as a pass at a
    glance, before any word is read — so the tests need to see `[green]`.
    Monkeypatched over `cli.console`, matching how test_cli.py substitutes
    module attributes instead of driving the CLI end to end.
    """

    def __init__(self):
        self.lines: list[str] = []

    def print(self, *args, **kwargs):
        self.lines.append(str(args[0]) if args else "")

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _llm_response(payload: dict):
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(content=json.dumps(payload)))]
    return resp


def _specialist_response():
    return _llm_response(
        {"decision": "APPROVE", "checks": {"logic": "PASS"}, "findings": [], "observations": []}
    )


def _lead_response():
    return _llm_response({"decision": "APPROVE", "summary": "Looks good", "findings": []})


# ---------- the reviewer records whether a model was actually asked ----------

class TestVerdictProvenanceIsRecorded:

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_no_files_in_scope_specialist_is_marked_not_reviewed(self, mock_llm, mock_alerts):
        """A specialist whose patterns match nothing made no model call."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        result = review_diff(DIFF, _pr_context(), profile)

        logic, frontend = result.specialist_verdicts
        assert (logic.reviewed, logic.skip_reason) == (True, "")
        assert frontend.reviewed is False
        assert frontend.skip_reason == SKIP_NO_FILES_IN_SCOPE
        # Only Logic and the lead were called — Frontend cost zero model calls,
        # which is exactly why its verdict may not read as a review.
        assert mock_llm.call_count == 2

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_transient_unavailable_specialist_is_marked_not_reviewed(self, mock_llm, mock_alerts):
        """A 503'd specialist is unavailable, not clean — and keeps its observation."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [Exception("503 Service Unavailable"), _lead_response()]

        profile = _profile(
            Persona(name="Architecture", focus="Design", system_prompt="p"),
        )
        result = review_diff(DIFF, _pr_context(), profile)

        specialist = result.specialist_verdicts[0]
        assert specialist.reviewed is False
        assert specialist.skip_reason == SKIP_REVIEWER_UNAVAILABLE
        # The pre-existing observation is preserved, not replaced by the flag.
        assert len(specialist.observations) == 1
        assert specialist.observations[0].category == "reviewer_unavailable"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_non_transient_error_verdict_is_left_alone(self, mock_llm, mock_alerts):
        """The ERROR path already reports honestly, so #66 does not touch it.

        An ERROR verdict renders as ⚠️ ERROR and carries a `reviewer_error`
        finding — nobody reads that as a completed clean review, which is the
        whole complaint in #66. Rewriting it as NOT REVIEWED would lose the
        error signal for no gain.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [Exception("Invalid API key"), _lead_response()]

        profile = _profile(Persona(name="Architecture", focus="Design", system_prompt="p"))
        result = review_diff(DIFF, _pr_context(), profile)

        specialist = result.specialist_verdicts[0]
        assert specialist.decision == "ERROR"
        assert specialist.findings[0].category == "reviewer_error"

        body = _build_review_body(_result([specialist], decision="APPROVE"))
        assert "⚠️" in _row(body, "Architecture")
        assert "ERROR" in _row(body, "Architecture")
        assert SPECIALISTS_NOT_RUN_MARKER not in body

    def test_verdicts_parsed_from_model_json_default_to_reviewed(self):
        """The default keeps every pre-existing construction site meaningful."""
        assert PersonaVerdict(
            persona="Security", decision="APPROVE", checks={}, findings=[], observations=[],
        ).reviewed is True


# ---------- the review body says so ----------

class TestNotReviewedRendersHonestly:

    @pytest.mark.parametrize(
        "skip_reason, expected",
        [
            (SKIP_NO_FILES_IN_SCOPE, "NOT REVIEWED — no files in scope"),
            (SKIP_REVIEWER_UNAVAILABLE, "NOT REVIEWED — reviewer unavailable"),
        ],
    )
    def test_row_states_the_specialist_did_not_run(self, skip_reason, expected):
        body = _build_review_body(_result([_not_reviewed(skip_reason=skip_reason)]))

        assert expected in _row(body, "Security")

    @pytest.mark.parametrize(
        "skip_reason", [SKIP_NO_FILES_IN_SCOPE, SKIP_REVIEWER_UNAVAILABLE],
    )
    def test_row_carries_neither_a_check_mark_nor_the_word_approve(self, skip_reason):
        """The two things that made #66's table read as a completed review."""
        row = _row(
            _build_review_body(_result([_not_reviewed(skip_reason=skip_reason)])), "Security",
        )

        assert "✅" not in row
        assert "APPROVE" not in row

    def test_unknown_skip_reason_still_never_renders_as_reviewed(self):
        """A future skip reason must fail safe, not fall back to a green row."""
        row = _row(
            _build_review_body(_result([_not_reviewed(skip_reason="something_new")])), "Security",
        )

        assert "NOT REVIEWED" in row
        assert "✅" not in row
        assert "APPROVE" not in row

    def test_a_specialist_that_ran_renders_exactly_as_before(self):
        """Regression guard: the real clean-review row is byte-for-byte unchanged."""
        body = _build_review_body(_result([_verdict(persona="Logic")]))

        assert _row(body, "Logic") == "| ✅ | **Logic** `VGL-abc123` | APPROVE (1/1 checks pass) |"

    def test_footer_tally_does_not_count_a_skipped_specialist_as_an_approval(self):
        """"2/2 specialists approved" was the same false green in prose."""
        body = _build_review_body(
            _result([_verdict(persona="Logic"), _not_reviewed(persona="Security")])
        )

        assert "1/2 specialists approved · 1 not reviewed" in body

    def test_footer_tally_is_unchanged_when_every_specialist_ran(self):
        body = _build_review_body(
            _result([_verdict(persona="Logic"), _verdict(persona="Security")])
        )

        assert "2/2 specialists approved · 0 findings" in body
        assert "not reviewed" not in body


# ---------- the machine-readable marker ----------

class TestSpecialistsNotRunMarker:

    def test_marker_names_every_specialist_that_did_not_run(self):
        """#66 asks for a detectable signal, so automation need not parse prose."""
        body = _build_review_body(
            _result([
                _not_reviewed(persona="Security"),
                _verdict(persona="Logic"),
                _not_reviewed(persona="Performance", skip_reason=SKIP_REVIEWER_UNAVAILABLE),
            ])
        )

        assert "<!-- vigil-specialists-not-run: Security,Performance -->" in body

    def test_marker_is_absent_when_every_specialist_ran(self):
        """Presence alone is the signal, mirroring `<!-- vigil-did-not-run -->`."""
        body = _build_review_body(
            _result([_verdict(persona="Logic"), _verdict(persona="Security")])
        )

        assert SPECIALISTS_NOT_RUN_MARKER not in body

    @patch("vigil.github_review.httpx.post")
    def test_marker_survives_into_the_posted_review_body(self, mock_post):
        resp = MagicMock(status_code=200, text="")
        resp.json.return_value = {"html_url": "https://github.com/o/r/pull/1#review"}
        mock_post.return_value = resp

        post_review(
            "o", "r", 1, _result([_not_reviewed(persona="Security")]), "tok", diff=DIFF,
        )

        posted_body = mock_post.call_args_list[0].kwargs["json"]["body"]
        assert "<!-- vigil-specialists-not-run: Security -->" in posted_body


# ---------- the "Reviewed commit X with Y" header ----------

class TestReviewedCommitHeaderLine:

    def test_header_does_not_claim_a_review_when_no_specialist_ran(self):
        """#66: boilerplate printed whether or not the model was called."""
        body = _build_review_body(
            _result([
                _not_reviewed(persona="Security"),
                _not_reviewed(persona="Performance", skip_reason=SKIP_REVIEWER_UNAVAILABLE),
            ])
        )

        assert f"*Reviewed commit `abc1234` with `{MODEL}`*" not in body
        assert "No specialist reviewed commit `abc1234`" in body
        # The model is still named — an operator debugging the skip needs it.
        assert MODEL in body

    def test_header_is_unchanged_when_any_specialist_ran(self):
        body = _build_review_body(
            _result([_verdict(persona="Logic"), _not_reviewed(persona="Security")])
        )

        assert f"*Reviewed commit `abc1234` with `{MODEL}`*" in body

    def test_header_is_unchanged_when_no_specialists_are_configured(self):
        """Nothing was skipped here, so there is no false green to correct."""
        body = _build_review_body(_result([]))

        assert f"*Reviewed commit `abc1234` with `{MODEL}`*" in body


# ---------- the live CLI surface an operator watches ----------

class TestCliDoesNotPrintCleanForASpecialistThatNeverRan:
    """`vigil review` streams a line per specialist as it finishes.

    For a skipped specialist that line read `APPROVE Security VGL-xxxx -
    clean`, in green. Every word of it was wrong: nothing was approved, and
    "clean" is an affirmative claim about a domain no model looked at. The
    detail slot now carries the reason instead.
    """

    @pytest.fixture
    def recorder(self, monkeypatch):
        console = _RecordingConsole()
        monkeypatch.setattr(cli, "console", console)
        return console

    @pytest.mark.parametrize(
        "skip_reason, reason_text",
        [
            (SKIP_NO_FILES_IN_SCOPE, "no files in scope"),
            (SKIP_REVIEWER_UNAVAILABLE, "reviewer unavailable"),
        ],
    )
    def test_skipped_specialist_line_states_the_reason(self, recorder, skip_reason, reason_text):
        cli._print_specialist_done(_not_reviewed(skip_reason=skip_reason))

        assert recorder.text == (
            f"  [yellow]⏭️ NOT REVIEWED[/yellow] Security [dim]VGL-abc123[/dim] - {reason_text}"
        )

    @pytest.mark.parametrize(
        "skip_reason", [SKIP_NO_FILES_IN_SCOPE, SKIP_REVIEWER_UNAVAILABLE],
    )
    def test_skipped_specialist_line_is_never_green_approve_or_clean(self, recorder, skip_reason):
        cli._print_specialist_done(_not_reviewed(skip_reason=skip_reason))

        assert "[green]" not in recorder.text
        assert "APPROVE" not in recorder.text
        assert "clean" not in recorder.text

    def test_unknown_skip_reason_drops_the_detail_rather_than_inventing_one(self, recorder):
        cli._print_specialist_done(_not_reviewed(skip_reason="something_new"))

        assert recorder.text == "  [yellow]⏭️ NOT REVIEWED[/yellow] Security [dim]VGL-abc123[/dim]"
        assert "clean" not in recorder.text

    def test_a_specialist_that_ran_clean_prints_exactly_as_before(self, recorder):
        """Regression guard: a real clean review still says APPROVE, in green."""
        cli._print_specialist_done(_verdict(persona="Logic"))

        assert recorder.text == "  [green]APPROVE[/green] Logic [dim]VGL-abc123[/dim] - clean"

    def test_a_specialist_that_ran_with_findings_prints_exactly_as_before(self, recorder):
        verdict = _verdict(persona="Logic", decision="REQUEST_CHANGES")
        verdict.findings = [
            Finding(file="a.py", line=1, severity=Severity.high, category="bug", message="Boom")
        ]

        cli._print_specialist_done(verdict)

        assert recorder.text == (
            "  [red]REQUEST_CHANGES[/red] Logic [dim]VGL-abc123[/dim] - 1 findings"
        )

    def test_summary_tally_excludes_a_specialist_that_never_ran(self, recorder):
        cli._print_summary_stats(
            _result([_verdict(persona="Logic"), _not_reviewed(persona="Security")])
        )

        assert "1/2 specialists approved · 1 not reviewed" in recorder.text

    def test_summary_tally_is_unchanged_when_every_specialist_ran(self, recorder):
        cli._print_summary_stats(
            _result([_verdict(persona="Logic"), _verdict(persona="Security")])
        )

        assert "2/2 specialists approved · 0 findings" in recorder.text
        assert "not reviewed" not in recorder.text


# ---------- the lead model is a reader too ----------

class TestLeadPromptReportsSpecialistsThatNeverRan:

    def _lead_prompt(self, mock_llm) -> str:
        return mock_llm.call_args_list[-1].kwargs["messages"][1]["content"]

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_lead_is_not_told_approve_for_a_specialist_that_never_ran(self, mock_llm, mock_alerts):
        """The lead was misled by the same defect, in its own prompt."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        review_diff(DIFF, _pr_context(), profile)

        prompt = self._lead_prompt(mock_llm)
        frontend_block = prompt.split("### Frontend")[1]
        assert "APPROVE" not in frontend_block
        assert not_reviewed_label(SKIP_NO_FILES_IN_SCOPE) in frontend_block
        assert "UNEXAMINED" in frontend_block

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_lead_still_sees_a_real_verdict_unchanged(self, mock_llm, mock_alerts):
        """Regression guard: a specialist that ran reports the way it always did."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        review_diff(DIFF, _pr_context(), profile)

        prompt = self._lead_prompt(mock_llm)
        logic_block = prompt.split("### Logic")[1].split("### Frontend")[0]
        assert logic_block.startswith(" [VGL-")
        assert "APPROVE" in logic_block
        assert "Checks: logic: PASS" in logic_block
        assert "No findings." in logic_block

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_lead_still_sees_the_unavailable_specialists_observation(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [Exception("503 Service Unavailable"), _lead_response()]

        profile = _profile(Persona(name="Architecture", focus="Design", system_prompt="p"))
        review_diff(DIFF, _pr_context(), profile)

        prompt = self._lead_prompt(mock_llm)
        assert not_reviewed_label(SKIP_REVIEWER_UNAVAILABLE) in prompt
        assert "Observations:" in prompt
        assert "temporarily unavailable" in prompt


# ---------- the boundary: reporting only ----------

class TestGatingDidNotChange:
    """#66 is a reporting defect. Nothing here may change what Vigil does.

    A synthesized verdict still means "this does not block the merge" — no
    file in the specialist's domain changed, or the provider blipped. Turning
    an honest label into a merge block would be a different (and unrequested)
    decision, so these tests pin the gating side in place.
    """

    @pytest.mark.parametrize(
        "skip_reason", [SKIP_NO_FILES_IN_SCOPE, SKIP_REVIEWER_UNAVAILABLE],
    )
    def test_synthesized_verdicts_keep_their_approve_decision(self, skip_reason):
        verdict = _not_reviewed(skip_reason=skip_reason)

        assert verdict.decision == "APPROVE"
        assert is_blocking_decision(verdict.decision) is False

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_review_diff_still_emits_approve_for_a_skipped_specialist(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        result = review_diff(DIFF, _pr_context(), profile)

        assert [v.decision for v in result.specialist_verdicts] == ["APPROVE", "APPROVE"]
        assert result.decision == "APPROVE"

    @patch("vigil.github_review.httpx.post")
    def test_posted_review_still_submits_approve_with_no_threads(self, mock_post):
        """The formal GitHub verdict is untouched; only its body changed."""
        resp = MagicMock(status_code=200, text="")
        resp.json.return_value = {"html_url": "https://github.com/o/r/pull/1#review"}
        mock_post.return_value = resp
        outcome: dict = {}

        post_review(
            "o", "r", 1,
            _result([_verdict(persona="Logic"), _not_reviewed(persona="Security")]),
            "tok", diff=DIFF, outcome=outcome,
        )

        payload = mock_post.call_args_list[0].kwargs["json"]
        assert payload["event"] == "APPROVE"
        assert "comments" not in payload
        assert outcome["submitted_event"] == "APPROVE"

    def test_observations_still_flow_from_an_unavailable_specialist(self):
        """The transient path's existing observation is additive, not replaced."""
        observation = Finding(
            file="N/A",
            severity=Severity.low,
            category="reviewer_unavailable",
            message="Security specialist was temporarily unavailable.",
        )
        body = _build_review_body(
            _result([
                _not_reviewed(skip_reason=SKIP_REVIEWER_UNAVAILABLE, observations=[observation])
            ])
        )

        assert "Observations (1 non-blocking)" in body
        assert "temporarily unavailable" in body
