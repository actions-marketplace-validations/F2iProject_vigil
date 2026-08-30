"""Tests for issue #79 — a review nobody performed is not an approval.

A PR touching only shell or script files matched **no** persona's
``file_patterns``. Every specialist was skipped as "no files in scope", and the
aggregate verdict came back APPROVE with 0/7 specialists having run. At the API
level that approval was indistinguishable from a real one — ``reviewDecision=
APPROVED`` — so it satisfied the org ruleset's required-approval rule and the PR
merged with zero review. Observed on F2iLLC/LunaOS#5028, whose entire diff was
``scripts/heartbeat-ping.sh``.

This is the descendant of #66, which made a skipped specialist *say* it was
skipped but deliberately left gating alone. That was right for the partial case
and left the total one open: #66's own tests all keep at least one specialist
alive, so "every single one was skipped" was never exercised as a gating
question. Here it is the whole question.

The fix has two halves, and the tests below are grouped to match:

- **Categorical** (``TestNoSpecialistRanIsNotAnApproval``). When no specialist
  runs, the verdict is NOT_REVIEWED, which posts as a GitHub COMMENT: it
  approves nothing, and it blocks nothing either. This half holds for any file
  type no persona happens to scope, including extensions nobody has thought of
  yet, so it does not depend on the list below staying complete.

- **Instance** (``TestScriptFilesAreInScope``). Script extensions are now
  scoped by the correctness and security personas, and ``.mjs``/``.cjs`` are
  scoped everywhere ``*.js`` already was — ``*.js`` does not glob-match
  ``foo.mjs``, so ordinary Node JavaScript was unreviewable by accident.

Two boundaries get their own tests because crossing either would be worse than
the bug:

- ``TestGatingBoundariesHold`` — a partial skip still approves (that is #66's
  settled behavior), and a blocking lead verdict is never downgraded to
  non-blocking, which would be this same fail-open pointed the other way.
- ``TestDocumentationOnlyPathIsUnaffected`` — documentation PRs must keep
  working. They are how the heartbeat lands its own state, and a fix to the
  review gate that stalls the fleet a different way is not a fix.
"""

import fnmatch
import json
from unittest.mock import MagicMock, patch

import pytest

from vigil.diff_parser import filter_hunks, parse_diff
from vigil.github_review import _build_review_body, is_blocking_decision, post_review
from vigil.models import (
    DECISION_NOT_REVIEWED,
    Finding,
    PersonaVerdict,
    ReviewResult,
    Severity,
)
from vigil.personas import (
    DEFAULT_PROFILE,
    ENTERPRISE_PROFILE,
    JS_PATTERNS,
    SCRIPT_PATTERNS,
    TS_PATTERNS,
    Persona,
    ReviewProfile,
)
from vigil.reviewer import review_diff
from vigil.utils import NOT_REVIEWED_ICON


SHA = "9ed6d50" + "0" * 33
MODEL = "gemini/gemini-3.1-flash-lite"

PROFILES = [
    pytest.param(DEFAULT_PROFILE, id="default"),
    pytest.param(ENTERPRISE_PROFILE, id="enterprise"),
]


# ---------- helpers ----------

def _diff(*paths: str) -> str:
    """Build a minimal unified diff touching each given path."""
    return "".join(
        f"diff --git a/{p} b/{p}\n"
        f"--- a/{p}\n"
        f"+++ b/{p}\n"
        f"@@ -1,1 +1,2 @@\n"
        f" existing\n"
        f"+added\n"
        for p in paths
    )


def _personas_that_would_run(profile: ReviewProfile, *paths: str) -> list[str]:
    """Names of specialists that would actually make a model call for ``paths``.

    Mirrors the two skip gates in ``review_diff``: a persona is skipped when no
    changed file matches its patterns, and a persona requiring external context
    is skipped whenever none is configured — which is the default everywhere,
    so Conformance never counts toward a diff being reviewed.
    """
    hunks = parse_diff(_diff(*paths))
    return [
        p.name
        for p in profile.specialists
        if not p.requires_external_context
        and (not p.file_patterns or filter_hunks(hunks, p.file_patterns))
    ]


def _scoped_by(persona: Persona, path: str) -> bool:
    return bool(filter_hunks(parse_diff(_diff(path)), persona.file_patterns))


def _persona_named(profile: ReviewProfile, name: str) -> Persona:
    return next(p for p in profile.specialists if p.name == name)


def _llm_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(content=json.dumps(payload)))]
    return resp


def _lead_response(decision: str = "APPROVE", findings: list | None = None) -> MagicMock:
    return _llm_response({
        "decision": decision,
        "summary": (
            "The PR effectively addresses the bug with a robust startup probe. "
            "The changes are well-scoped and follow existing project idioms."
        ),
        "findings": findings or [],
    })


def _specialist_response() -> MagicMock:
    return _llm_response({"decision": "APPROVE", "checks": {}, "findings": [], "observations": []})


def _pr_context() -> dict:
    return {
        "title": "chore: add heartbeat ping script",
        "author": "user",
        "head": "feature",
        "base": "main",
        "additions": 1,
        "deletions": 0,
        "changed_files": 1,
        "body": "",
        "head_sha": SHA,
        "url": "https://github.com/F2iLLC/LunaOS/pull/5028",
    }


def _profile(*specialists: Persona) -> ReviewProfile:
    return ReviewProfile(
        name="test", specialists=list(specialists), lead_prompt="You are the lead.",
    )


def _not_reviewed(persona: str = "Logic", skip_reason: str = "no_files_in_scope") -> PersonaVerdict:
    return PersonaVerdict(
        persona=persona,
        session_id="VGL-fe2bc6",
        decision="APPROVE",
        checks={},
        findings=[],
        observations=[],
        reviewed=False,
        skip_reason=skip_reason,
    )


def _result(verdicts: list[PersonaVerdict], decision: str, summary: str = "Looks good") -> ReviewResult:
    return ReviewResult(
        decision=decision,
        summary=summary,
        commit_sha=SHA,
        pr_url="https://github.com/o/r/pull/1",
        model=MODEL,
        specialist_verdicts=verdicts,
        lead_findings=[],
        observations=[],
    )


# ---------- the categorical fix ----------

class TestNoSpecialistRanIsNotAnApproval:
    """0/N specialists is an absence of a review, not the granting of one."""

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_every_specialist_skipped_does_not_approve(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]  # lead only; no specialist call

        # Both personas are scoped to extensions the diff does not contain.
        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Security", focus="Vulns", system_prompt="p", file_patterns=["*.py"]),
        )
        result = review_diff(_diff("scripts/deploy.sh"), _pr_context(), profile)

        assert all(not v.reviewed for v in result.specialist_verdicts)
        assert result.decision == DECISION_NOT_REVIEWED
        assert result.decision != "APPROVE"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_the_verdict_still_does_not_block_the_merge(self, mock_llm, mock_alerts):
        """Non-approving, but not a block: nothing was examined, so there is
        nothing to object to. Failing closed on every unscoped diff would stall
        the fleet, which is the opposite mistake."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
        )
        result = review_diff(_diff("scripts/deploy.sh"), _pr_context(), profile)

        assert is_blocking_decision(result.decision) is False

    @patch("vigil.github_review.httpx.post")
    def test_it_posts_as_comment_so_it_cannot_satisfy_required_approval(self, mock_post):
        """The whole defect was that this satisfied a required-approval rule.

        A COMMENT review carries no verdict on GitHub: it does not count toward
        an approval requirement and does not block. That is the exact semantics
        wanted for "no specialist examined this".
        """
        resp = MagicMock(status_code=200, text="")
        resp.json.return_value = {"html_url": "https://github.com/o/r/pull/1#review"}
        mock_post.return_value = resp
        outcome: dict = {}

        post_review(
            "o", "r", 1,
            _result([_not_reviewed()], decision=DECISION_NOT_REVIEWED),
            "tok", diff=_diff("scripts/deploy.sh"), outcome=outcome,
        )

        payload = mock_post.call_args_list[0].kwargs["json"]
        assert payload["event"] == "COMMENT"
        assert payload["event"] != "APPROVE"
        assert outcome["submitted_event"] == "COMMENT"

    def test_the_review_body_never_renders_a_green_check(self):
        body = _build_review_body(_result([_not_reviewed()], decision=DECISION_NOT_REVIEWED))

        header = body.splitlines()[0]
        assert DECISION_NOT_REVIEWED in header
        assert "✅" not in header
        assert NOT_REVIEWED_ICON in header

    def test_the_lead_summary_carries_a_caveat_when_nothing_was_reviewed(self):
        """#79 item 3. The lead does see the diff, so the summary is not
        invented — but it is written to read as a synthesis of specialist
        verdicts that in this case do not exist. The caveat sits above it
        rather than deleting it."""
        body = _build_review_body(_result([_not_reviewed()], decision=DECISION_NOT_REVIEWED))

        assert "No specialist reviewed this diff" in body
        assert "does not approve" in body
        # The summary itself is preserved, not suppressed.
        assert "Looks good" in body

    def test_no_caveat_when_a_specialist_actually_ran(self):
        reviewed = PersonaVerdict(
            persona="Logic", session_id="VGL-aaaaaa", decision="APPROVE",
            checks={"correctness": "PASS"}, findings=[], observations=[], reviewed=True,
        )
        body = _build_review_body(_result([reviewed, _not_reviewed("Security")], decision="APPROVE"))

        assert "No specialist reviewed this diff" not in body

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_it_closes_the_class_not_just_the_known_extensions(self, mock_llm, mock_alerts):
        """The point of the categorical half: an extension nobody has scoped —
        or thought of — still cannot produce an approval."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
        )
        result = review_diff(_diff("infra/main.hypothetical"), _pr_context(), profile)

        assert result.decision == DECISION_NOT_REVIEWED


# ---------- the instance fix ----------

class TestScriptFilesAreInScope:
    """Shell, batch and Node-module files now route to a specialist."""

    @pytest.mark.parametrize("profile", PROFILES)
    @pytest.mark.parametrize(
        "path",
        [
            "scripts/heartbeat-ping.sh",     # the file from LunaOS#5028
            "scripts/deploy.bash",
            "tools/run.zsh",
            "tools/run.fish",
            "scripts/Deploy.ps1",
            "scripts/Module.psm1",
            "scripts/build.bat",
            "scripts/build.cmd",
            "scripts/setup-git-hooks.mjs",   # wires core.hooksPath
            "scripts/legacy.cjs",
        ],
    )
    def test_a_script_only_pr_reaches_at_least_one_specialist(self, profile, path):
        assert _personas_that_would_run(profile, path), (
            f"{path} matches no persona in the {profile.name} profile — "
            "every specialist would skip and #79 would reopen"
        )

    def test_the_lunaos_5028_diff_is_no_longer_unreviewed(self):
        """The exact reproduction from the issue: one file, scripts/heartbeat-ping.sh."""
        assert _personas_that_would_run(DEFAULT_PROFILE, "scripts/heartbeat-ping.sh")

    # Deliberately a hardcoded list, NOT derived from SCRIPT_PATTERNS: a test
    # parametrized over the constant it is checking silently stops checking an
    # extension the moment someone deletes it from that constant, which is the
    # one edit this test exists to catch.
    @pytest.mark.parametrize(
        "extension",
        [".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd"],
    )
    def test_correctness_and_security_both_scope_every_script_extension(self, extension):
        """Not just *a* persona: scripts are where deploy steps, credential
        handling and `curl | sh` live, so both the correctness and the security
        reviewer must see them."""
        for profile, logic_name in ((DEFAULT_PROFILE, "Logic"), (ENTERPRISE_PROFILE, "Architecture")):
            for name in (logic_name, "Security"):
                persona = _persona_named(profile, name)
                assert _scoped_by(persona, f"scripts/thing{extension}"), (
                    f"{name} in the {profile.name} profile does not scope {extension}"
                )

    @pytest.mark.parametrize("profile", PROFILES)
    def test_mjs_and_cjs_are_scoped_wherever_plain_js_is(self, profile):
        """`*.js` does not glob-match `foo.mjs`. Any persona that reviews
        JavaScript must review all three module flavors or the gap reappears
        one extension over."""
        for persona in profile.specialists:
            if not _scoped_by(persona, "src/app.js"):
                continue
            for path in ("src/app.mjs", "src/app.cjs"):
                assert _scoped_by(persona, path), (
                    f"{persona.name} in the {profile.name} profile scopes .js but not "
                    f"{path.rsplit('.', 1)[1]}"
                )

    def test_script_coverage_does_not_depend_on_a_lucky_filename(self):
        """Before the fix, Security's substring globs (*auth*, *token*, ...)
        accidentally caught `deploy-token.sh` while `deploy.sh` matched nothing,
        so a script's coverage depended on whether its name happened to contain
        one of five words."""
        security = _persona_named(DEFAULT_PROFILE, "Security")

        assert _scoped_by(security, "scripts/deploy-token.sh")
        assert _scoped_by(security, "scripts/deploy.sh")

    def test_the_pattern_groups_are_actually_wired_into_the_personas(self):
        """Asserting the constants contain their own literals would pass even if
        no persona referenced the groups at all. Assert the *effective* patterns
        of a persona that is supposed to use each group."""
        logic = _persona_named(DEFAULT_PROFILE, "Logic")

        for extension in ("*.sh", "*.bash", "*.zsh", "*.fish", "*.ps1", "*.psm1", "*.bat", "*.cmd"):
            assert extension in logic.file_patterns, f"{extension} never reached Logic"
        for extension in ("*.js", "*.jsx", "*.mjs", "*.cjs"):
            assert extension in logic.file_patterns, f"{extension} never reached Logic"
        for extension in ("*.ts", "*.tsx", "*.mts", "*.cts"):
            assert extension in logic.file_patterns, f"{extension} never reached Logic"

        # And the groups themselves are non-empty, so the assertions above
        # cannot be satisfied by a persona that hardcodes the literals.
        assert SCRIPT_PATTERNS and JS_PATTERNS and TS_PATTERNS

    def test_mts_and_cts_are_scoped_wherever_plain_ts_is(self):
        """`*.ts` does not glob-match `foo.mts`, exactly as `*.js` does not match
        `foo.mjs`. Found while reviewing the JS half of this fix — the same hole,
        one language over, and the likelier one in a TypeScript monorepo."""
        assert fnmatch.fnmatch("src/a.mts", "*.ts") is False
        assert fnmatch.fnmatch("src/a.cts", "*.ts") is False

        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            for persona in profile.specialists:
                if not _scoped_by(persona, "src/app.ts"):
                    continue
                for path in ("src/app.mts", "src/app.cts"):
                    assert _scoped_by(persona, path), (
                        f"{persona.name} in the {profile.name} profile scopes .ts but not {path}"
                    )


# ---------- boundaries that must not move ----------

class TestGatingBoundariesHold:
    """Two ways this fix could become a worse bug than the one it fixes."""

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_a_partial_skip_still_approves(self, mock_llm, mock_alerts):
        """#66's settled behavior. A specialist with nothing in its domain must
        not drag down a review that other specialists actually performed."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        result = review_diff(_diff("src/app.py"), _pr_context(), profile)

        assert [v.reviewed for v in result.specialist_verdicts] == [True, False]
        assert result.decision == "APPROVE"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_a_blocking_lead_verdict_is_never_downgraded(self, mock_llm, mock_alerts):
        """The lead reads the full diff, so it can object even when no
        specialist ran. Rewriting that REQUEST_CHANGES into a non-blocking
        NOT_REVIEWED would be this same fail-open, pointed the other way."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response(decision="REQUEST_CHANGES")]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
        )
        result = review_diff(_diff("scripts/deploy.sh"), _pr_context(), profile)

        assert all(not v.reviewed for v in result.specialist_verdicts)
        assert result.decision == "REQUEST_CHANGES"
        assert is_blocking_decision(result.decision) is True

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_a_profile_with_no_specialists_is_left_alone(self, mock_llm, mock_alerts):
        """Nothing was skipped here — there was nothing to skip — so there is no
        false green to correct."""
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_lead_response()]

        result = review_diff(_diff("src/app.py"), _pr_context(), _profile())

        assert result.specialist_verdicts == []
        assert result.decision == "APPROVE"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_individual_skipped_verdicts_keep_their_approve_decision(self, mock_llm, mock_alerts):
        """#66 pinned this: the per-persona decision is what keeps a skipped
        domain from blocking. Only the aggregate changed.

        Asserted against a verdict **production actually built**, not against
        this module's `_not_reviewed()` helper — that helper hardcodes
        `decision="APPROVE"`, so asserting on it would be checking the fixture
        against itself and would pass with the whole fix reverted.
        """
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(name="Logic", focus="Bugs", system_prompt="p", file_patterns=["*.py"]),
            Persona(name="Frontend", focus="UI", system_prompt="p", file_patterns=["*.tsx"]),
        )
        result = review_diff(_diff("src/app.py"), _pr_context(), profile)

        skipped = [v for v in result.specialist_verdicts if not v.reviewed]
        assert len(skipped) == 1
        assert skipped[0].decision == "APPROVE"
        assert is_blocking_decision(skipped[0].decision) is False


class TestKnownCoverageGapsAreDeliberate:
    """The file shapes that still reach the NOT_REVIEWED branch.

    This test does not assert that the gap is *good*. It asserts that the gap
    is *known*, so that changing it is a deliberate act with a visible diff
    rather than an accident — the same failure mode that produced #79, where
    nobody could see which extensions no persona scoped.

    It matters because `NOT_REVIEWED` is non-blocking but also non-approving,
    and in a repo whose ruleset requires an approval that Vigil is the one
    supplying, "no approval" stops the merge just as effectively as a block —
    and unlike a block it is deterministic: re-running Vigil produces the same
    verdict forever, with no automated way out. Every path below therefore
    needs a human approval today.

    Whether that is the right trade is an owner decision, recorded on #79 and
    in the CHANGELOG rather than silently settled here. The two options on the
    table are broadening these personas' patterns, or adding a catch-all
    specialist so the NOT_REVIEWED branch becomes a true last resort. Until
    one is chosen, this list is the honest statement of the cost.
    """

    # Verified against the real profiles, not asserted from memory.
    UNCOVERED = [
        "styles/main.css", "styles/main.scss",     # deliberately excluded everywhere (!*.css)
        "Dockerfile", "Makefile",                  # no extension to match on
        "scripts/deploy",                          # extensionless shell script
        "infra/main.tf",                           # Terraform
        ".gitignore", "CODEOWNERS", "LICENSE",     # repo-root convention files
        "src/app.vue", "index.html",               # web templates
        "src/main.c", "src/App.kt",                # languages no persona lists
        "data.csv",
    ]

    @pytest.mark.parametrize("path", UNCOVERED)
    def test_these_shapes_reach_no_specialist_in_either_profile(self, path):
        assert not _personas_that_would_run(DEFAULT_PROFILE, path)
        assert not _personas_that_would_run(ENTERPRISE_PROFILE, path)

    @pytest.mark.parametrize("path", UNCOVERED)
    def test_and_therefore_produce_a_non_approving_verdict(self, path):
        """The consequence, stated once rather than left to be discovered:
        a PR touching only one of these gets no approval from Vigil."""
        hunks = parse_diff(_diff(path))
        for profile in (DEFAULT_PROFILE, ENTERPRISE_PROFILE):
            would_run = [
                p for p in profile.specialists
                if not p.requires_external_context
                and (not p.file_patterns or filter_hunks(hunks, p.file_patterns))
            ]
            assert would_run == []

    def test_the_shapes_this_pr_did_fix_are_not_in_that_list(self):
        """Guards against the list quietly growing to cover a regression."""
        for path in ("scripts/heartbeat-ping.sh", "scripts/setup-git-hooks.mjs",
                     "src/app.mts", "src/legacy.cjs", "README.md"):
            assert path not in self.UNCOVERED
            assert _personas_that_would_run(DEFAULT_PROFILE, path)


class TestDocumentationOnlyPathIsUnaffected:
    """Documentation PRs must not become collateral damage.

    They are how the heartbeat lands its own RUNLOG state, so turning them
    non-approving would stall the fleet in a different way. They are safe for a
    structural reason rather than a special case: the DX persona scopes ``*.md``
    in both profiles, so a documentation diff always has a live specialist and
    never reaches the all-skipped branch at all.

    Note that the documentation-only *auto-approve short-circuit* described in
    older supervisor guidance no longer exists in this codebase — it was removed
    in #62 after a "documentation-only" PR committed confidential material and
    Vigil approved it green. ``is_documentation_only`` survives as a classifier
    with no production caller. Documentation PRs take the ordinary specialist
    path, which is why this fix leaves them alone.
    """

    @pytest.mark.parametrize("profile", PROFILES)
    @pytest.mark.parametrize(
        "path", ["README.md", "docs/setup/install.md", "docs/guide.mdx", "CHANGELOG.md"],
    )
    def test_a_documentation_only_diff_still_has_a_live_specialist(self, profile, path):
        assert _personas_that_would_run(profile, path), (
            f"{path} would skip every specialist in the {profile.name} profile, which "
            "would make documentation PRs non-approving — a fleet stall, not a fix"
        )

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer._call_llm_with_retry")
    def test_a_documentation_only_review_can_still_approve(self, mock_llm, mock_alerts):
        mock_alerts.return_value = 0
        mock_llm.side_effect = [_specialist_response(), _lead_response()]

        profile = _profile(
            Persona(
                name="DX", focus="Docs", system_prompt="p",
                file_patterns=["*.md", "*.mdx", "*.rst", "*.txt"],
            ),
        )
        result = review_diff(_diff("docs/setup/install.md"), _pr_context(), profile)

        assert result.specialist_verdicts[0].reviewed is True
        assert result.decision == "APPROVE"
