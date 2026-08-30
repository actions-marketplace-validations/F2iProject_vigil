"""Deterministic regression replay for the LunaOS #4761 failure pattern.

The fixture deliberately contains no GitHub or model seam.  It models the
seven reviewed heads, one historical TS2591 conversation item, specialist
paraphrases, and the posting/issue identities that amplified the original
claim.
"""

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

from vigil.comment_manager import build_conversation_context, deduplicate_comments
from vigil.context_manager import stable_finding_key
from vigil.cross_specialist_dedup import merge_specialist_findings
from vigil.finding_validation import (
    STALE_HISTORICAL_EVIDENCE,
    validate_findings_against_head,
)
from vigil import github_review
from vigil.github_review import _format_inline_comment, _place_finding_inline, post_review
from vigil.issue_manager import _build_issue_body, _match_finding_to_issue, create_issues_for_observations
from vigil.models import Finding, PersonaVerdict, ReviewResult, Severity


@dataclass(frozen=True)
class ReplayHead:
    sha: str
    node_overlay_present: bool
    checks_green: bool


HEADS = (
    ReplayHead("1fd1ba0", False, False),
    ReplayHead("bebe0d9", True, False),
    ReplayHead("9b6aaa3", True, False),
    ReplayHead("f506477", True, False),
    ReplayHead("3886bd9", True, False),
    ReplayHead("48ac969", True, True),
    ReplayHead("4bead6e", True, True),
)


def _node_finding(
    *,
    file: str = "packages/writing-style/src/loader.ts",
    category: str = "build-failure",
    message: str = "TS2591: writing-style cannot resolve node:crypto",
    source: str = "current_diff",
    commit: str = "1fd1ba0",
    predicate: str = "TS2591 Node built-in types unavailable",
) -> Finding:
    return Finding(
        file=file,
        line=4,
        severity=Severity.high,
        category=category,
        message=message,
        suggestion="Add the package's Node type overlay.",
        component="packages/writing-style",
        predicate=predicate,
        evidence_source=source,
        evidence_commit=commit,
    )


def _result(observations: list[Finding]) -> ReviewResult:
    verdict = PersonaVerdict(
        persona="Testing",
        decision="APPROVE",
        checks={},
        findings=[],
        observations=observations,
    )
    return ReviewResult(
        decision="APPROVE",
        summary="Replay",
        commit_sha=HEADS[-1].sha,
        specialist_verdicts=[verdict],
        lead_findings=[],
        observations=observations,
        observation_sources=[("Testing", item) for item in observations],
    )


def test_historical_conversation_is_explicitly_not_current_head_evidence():
    context = build_conversation_context(
        [{
            "created_at": "2026-08-20T00:00:00Z",
            "user": {"login": "maintainer"},
            "body": "The writing-style build failed with TS2591 for node:crypto.",
        }],
        head_sha=HEADS[-1].sha,
    )

    assert "source=human_comment" in context
    assert "commit=unattributed" in context
    assert "current_head=false" in context


def test_seven_head_replay_allows_initial_defect_and_withholds_six_stale_repeats():
    fetches: list[tuple[str, str]] = []

    def fetch(_owner, _repo, path, sha, _token):
        fetches.append((path, sha))
        return "export const loader = true"

    first_supported, first_suppressed = validate_findings_against_head(
        [_node_finding()], "F2iLLC", "LunaOS", HEADS[0].sha, "token",
        fetch_content=fetch,
        fetch_checks=lambda *_: [{
            "name": "typecheck",
            "status": "completed",
            "conclusion": "failure",
            "output": {"summary": "TS2591 in packages/writing-style"},
        }],
    )
    assert len(first_supported) == 1
    assert first_suppressed == []

    for head in HEADS[1:]:
        stale = _node_finding(source="historical_conversation", commit=HEADS[0].sha)
        supported, suppressed = validate_findings_against_head(
            [stale], "F2iLLC", "LunaOS", head.sha, "token",
            fetch_content=fetch,
        )
        assert supported == []
        assert [item.reason for item in suppressed] == [STALE_HISTORICAL_EVIDENCE]

    # Historical provenance is resolved before any blob/API lookup.
    assert fetches == [("packages/writing-style/src/loader.ts", HEADS[0].sha)]


def test_pending_check_cannot_support_a_current_build_failure():
    supported, suppressed = validate_findings_against_head(
        [_node_finding()], "F2iLLC", "LunaOS", HEADS[0].sha, "token",
        fetch_checks=lambda *_: [{
            "name": "typecheck",
            "status": "in_progress",
            "conclusion": None,
            "output": {"summary": ""},
        }],
        fetch_content=lambda *_: "unused",
    )

    assert supported == []
    assert suppressed[0].reason == "current_status_not_supported_by_failed_check"


def test_stale_only_request_changes_posts_as_nonblocking_comment(monkeypatch):
    # The suite-wide fixture stubs post_review's network-backed validation;
    # this replay uses the real guard, whose provenance path performs no I/O.
    monkeypatch.setattr(
        github_review,
        "validate_findings_against_head",
        validate_findings_against_head,
    )
    stale = _node_finding(source="historical_conversation", commit=HEADS[0].sha)
    verdict = PersonaVerdict(
        persona="Testing",
        decision="REQUEST_CHANGES",
        checks={},
        findings=[stale],
        observations=[],
    )
    result = ReviewResult(
        decision="REQUEST_CHANGES",
        summary="Historical TS2591 appears unresolved.",
        commit_sha=HEADS[-1].sha,
        specialist_verdicts=[verdict],
        lead_findings=[],
        observations=[],
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"html_url": "https://example.test/review/1"}
    response.raise_for_status.return_value = None

    with patch("vigil.github_review.httpx.post", return_value=response) as send:
        post_review(
            "F2iLLC", "LunaOS", 4761, result, "token",
            diff=(
                "diff --git a/packages/writing-style/src/loader.ts "
                "b/packages/writing-style/src/loader.ts\n"
                "@@ -1 +1 @@\n-export const x = 1\n+export const x = 2\n"
            ),
        )

    payload = send.call_args_list[0].kwargs["json"]
    assert payload["event"] == "COMMENT"
    assert payload.get("comments", []) == []
    assert "No current blocking finding remained" in payload["body"]


def test_check_api_failure_keeps_current_finding_fail_loud():
    def unavailable(*_args):
        raise RuntimeError("check API unavailable")

    supported, suppressed = validate_findings_against_head(
        [_node_finding()], "F2iLLC", "LunaOS", HEADS[0].sha, "token",
        fetch_checks=unavailable,
        fetch_content=lambda *_: "export const loader = true",
    )

    assert len(supported) == 1
    assert suppressed == []


def test_six_specialists_collapse_paraphrases_categories_paths_and_lines():
    variants = [
        ("Architecture", "build-failure", "packages/writing-style/src/loader.ts", 4,
         "TS2591: Node built-ins are unresolved in writing-style"),
        ("DX", "type-mismatch", "packages/writing-style/tsconfig.json", 11,
         "writing-style cannot type node:fs (TS2591)"),
        ("Logic", "factual-accuracy", "docker/Dockerfile.api", 70,
         "The package still reports TS2591 for node:path"),
        ("Testing", "test-failure", "packages/writing-style/src/index.ts", 2,
         "Current builds fail to resolve node:url with TS2591"),
        ("Performance", "breaking-contracts", "benchmarks/hermes/tsconfig.json", 8,
         "TS2591 means Node modules are unavailable to writing-style"),
        ("Security", "build-failure", "packages/writing-style/src/loader.ts", 99,
         "Node type resolution is broken (TS2591)"),
    ]
    verdicts = []
    for persona, category, file, line, message in variants:
        finding = _node_finding(file=file, category=category, message=message)
        finding.line = line
        verdicts.append(PersonaVerdict(
            persona=persona,
            decision="REQUEST_CHANGES",
            checks={},
            findings=[finding],
            observations=[],
        ))

    deduped, merged = merge_specialist_findings(verdicts)

    assert len(deduped) == 1
    assert len(merged) == 1
    assert merged[0].count == 6


def test_distinct_predicates_in_same_component_remain_distinct():
    node_types = _node_finding()
    docker_context = _node_finding(
        predicate="Docker image omits tsconfig.node.json",
        message="Docker cannot read /app/tsconfig.node.json",
        category="container-build",
    )
    assert stable_finding_key(node_types) != stable_finding_key(docker_context)


def test_unplaceable_finding_is_not_relocated_to_unrelated_changed_file():
    finding = _node_finding()
    valid_lines = {"docker/Dockerfile.api": {20}, "benchmarks/hermes/tsconfig.json": {3}}

    assert _place_finding_inline(finding, "Testing", "VGL-abc123", valid_lines) is None


def test_same_semantic_finding_is_idempotent_across_comment_anchors():
    old = _node_finding(file="packages/writing-style/src/loader.ts")
    new = _node_finding(file="docker/Dockerfile.api", category="type-mismatch")
    existing = [{
        "path": old.file,
        "line": old.line,
        "body": _format_inline_comment(old, "Testing", "VGL-abc123"),
    }]
    candidate = {
        "path": new.file,
        "line": 70,
        "body": _format_inline_comment(new, "Architecture", "VGL-def456"),
    }

    assert deduplicate_comments([candidate], existing) == []


def test_observation_issue_identity_is_idempotent_within_and_across_rounds():
    first = _node_finding(source="historical_conversation")
    paraphrase = _node_finding(
        file="docker/Dockerfile.api",
        category="type-mismatch",
        message="Node type resolution still reports TS2591 in writing-style",
        source="historical_conversation",
    )
    existing = [{
        "html_url": "https://github.com/F2iLLC/LunaOS/issues/4787",
        "body": _build_issue_body(first, "Testing"),
    }]
    assert _match_finding_to_issue(paraphrase, existing) == existing[0]["html_url"]

    with (
        patch("vigil.issue_manager.ensure_priority_label", return_value=True),
        patch("vigil.issue_manager._fetch_all_issues", return_value=[]),
        patch("vigil.issue_manager.create_issue", return_value="https://example.test/issues/1") as create,
    ):
        tracked = create_issues_for_observations(
            "F2iLLC", "LunaOS", "token", _result([first, paraphrase]),
        )

    assert create.call_count == 1
    assert [url for _, url in tracked] == [
        "https://example.test/issues/1",
        "https://example.test/issues/1",
    ]
