"""Tests for the Conformance specialist — reviewing a PR against its spec.

Every other persona asks "is this code good?". Those questions are answerable
from the diff alone, which is why Vigil could answer them with nothing but the
diff, the PR description, and the thread. "Is this the thing that was asked
for?" is not answerable that way: it needs the governing spec, and the spec
lives outside the PR.

The seam that carries outside material already exists (``external_context.py``,
F2iLLC/vigil#47). What did not exist was a reviewer whose job is agreement with
it. The lead's "scope drift" check is the closest prior art and it compares the
diff to *the PR's own description* — self-consistency, not conformance. An
author who describes what they built accurately passes it while building
something nobody asked for.

The load-bearing property here is the skip, not the review. A conformance
reviewer handed no spec has only the PR's self-description left to check
against, so it would grade the PR against itself and report a pass. That pass
is worse than silence: it renders as a satisfied conformance check on a PR
whose spec was never consulted. So no context means NOT REVIEWED, following the
same contract as #66 — ``decision`` stays APPROVE so a fleet with no provider
configured is never blocked, while ``reviewed=False`` stops every surface from
reporting it as a conformance pass.
"""

import json
from unittest.mock import MagicMock, patch

from vigil.external_context import ExternalContext
from vigil.models import SKIP_NO_EXTERNAL_CONTEXT
from vigil.personas import (
    DEFAULT_PROFILE,
    ENTERPRISE_PROFILE,
    Persona,
    ReviewProfile,
)
from vigil.reviewer import review_diff
from vigil.utils import not_reviewed_label


DIFF = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 def handler():
+    return compute()
     pass
"""


def _llm_response(payload: dict):
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(content=json.dumps(payload)))]
    return resp


def _specialist_response():
    return _llm_response(
        {"decision": "APPROVE", "checks": {"conformance": "PASS"}, "findings": [], "observations": []}
    )


def _lead_response():
    return _llm_response({"decision": "APPROVE", "summary": "Looks good", "findings": []})


def _pr_context():
    return {
        "title": "Test PR", "author": "user", "head": "feature", "base": "main",
        "additions": 1, "deletions": 0, "changed_files": 1, "body": "",
    }


def _spec_persona(name="Conformance"):
    return Persona(
        name=name,
        focus="Agreement with the governing spec",
        system_prompt="p",
        requires_external_context=True,
    )


def _profile(*specialists):
    return ReviewProfile(
        name="test", specialists=list(specialists), lead_prompt="You are the lead.",
    )


def _context(text="REQ-1: the handler must return a computed value.", label="Spec"):
    return ExternalContext(text=text, label=label)


class TestSkipWithoutASpec:
    """No governing material means unexamined, never a conformance pass."""

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_absent_context_skips_the_specialist(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        result = review_diff(
            DIFF, _pr_context(), _profile(_spec_persona()),
            external_context_provider=lambda **_: None,
        )

        (verdict,) = result.specialist_verdicts
        assert verdict.reviewed is False
        assert verdict.skip_reason == SKIP_NO_EXTERNAL_CONTEXT
        # Only the lead was called. A conformance reviewer with no spec must
        # cost zero model calls rather than produce a verdict from the diff.
        assert mock_llm.call_count == 1

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_empty_and_whitespace_context_also_skips(self, mock_llm, mock_alerts):
        """A provider that returns nothing supplied no spec, whatever it returned.

        The provider contract is fail-open, so "" and "   " are both ordinary
        outcomes — an unmapped repo, a spec store with no match. Treating a
        blank payload as context would run the reviewer against an empty spec,
        which is the self-grading case wearing a different hat.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        result = review_diff(
            DIFF, _pr_context(), _profile(_spec_persona()),
            external_context_provider=lambda **_: _context(text="   \n  "),
        )

        (verdict,) = result.specialist_verdicts
        assert verdict.reviewed is False
        assert verdict.skip_reason == SKIP_NO_EXTERNAL_CONTEXT
        assert mock_llm.call_count == 1

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_skip_does_not_block_the_merge(self, mock_llm, mock_alerts):
        """Reporting-only, exactly as #66 established.

        Vigil gates merges fleet-wide and most repos configure no provider. A
        conformance reviewer that blocked whenever it lacked a spec would fail
        every PR in every repo that has not adopted this yet.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        result = review_diff(
            DIFF, _pr_context(), _profile(_spec_persona()),
            external_context_provider=lambda **_: None,
        )

        (verdict,) = result.specialist_verdicts
        assert verdict.decision == "APPROVE"
        assert verdict.findings == []

    def test_the_skip_reason_renders_as_not_reviewed(self):
        """The reason has display text, so it cannot degrade to a bare label."""
        label = not_reviewed_label(SKIP_NO_EXTERNAL_CONTEXT)
        assert "NOT REVIEWED" in label
        assert "no governing spec supplied" in label


class TestRunsWithASpec:

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_supplied_context_runs_the_specialist(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        result = review_diff(
            DIFF, _pr_context(), _profile(_spec_persona()),
            external_context_provider=lambda **_: _context(),
        )

        (verdict,) = result.specialist_verdicts
        assert verdict.reviewed is True
        assert verdict.skip_reason == ""
        assert mock_llm.call_count == 2

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_the_spec_reaches_the_specialist_prompt(self, mock_llm, mock_alerts):
        """The reviewer must actually receive the requirement text.

        Wiring a persona that never sees the spec would still pass every test
        above — it runs, it returns APPROVE — while checking nothing.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        review_diff(
            DIFF, _pr_context(), _profile(_spec_persona()),
            external_context_provider=lambda **_: _context(
                text="REQ-42: every handler must emit an audit event."
            ),
        )

        specialist_messages = mock_llm.call_args_list[0].kwargs.get("messages") or \
            mock_llm.call_args_list[0].args[0]
        prompt = "\n".join(m["content"] for m in specialist_messages)
        assert "REQ-42" in prompt

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_other_specialists_are_unaffected_by_a_missing_spec(self, mock_llm, mock_alerts):
        """The gate is per-persona, not per-review.

        A repo with no provider must still get its ordinary review; only the
        conformance question goes unanswered.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        result = review_diff(
            DIFF,
            _pr_context(),
            _profile(
                Persona(name="Logic", focus="Bugs", system_prompt="p"),
                _spec_persona(),
            ),
            external_context_provider=lambda **_: None,
        )

        logic, conformance = result.specialist_verdicts
        assert (logic.reviewed, logic.skip_reason) == (True, "")
        assert conformance.reviewed is False


class TestProfileWiring:

    def test_conformance_ships_in_both_profiles(self):
        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            names = [p.name for p in profile.specialists]
            assert "Conformance" in names, f"{profile.name} profile is missing it"

    def test_conformance_requires_external_context(self):
        """Without the flag the persona self-grades instead of skipping."""
        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            persona = next(p for p in profile.specialists if p.name == "Conformance")
            assert persona.requires_external_context is True

    def test_conformance_sees_the_whole_diff(self):
        """File-pattern routing would hide the very changes it must account for.

        Unrequested scope and unimplemented requirements can land in any file,
        so a domain-scoped diff would let both through in the files it filtered
        out.
        """
        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            persona = next(p for p in profile.specialists if p.name == "Conformance")
            assert persona.file_patterns == []

    def test_every_other_persona_still_runs_without_a_provider(self):
        """Only Conformance may depend on outside material.

        If a future persona quietly sets the flag, every repo without a
        provider silently loses that reviewer — so the blast radius stays
        pinned here.
        """
        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            dependent = [
                p.name for p in profile.specialists if p.requires_external_context
            ]
            assert dependent == ["Conformance"]
