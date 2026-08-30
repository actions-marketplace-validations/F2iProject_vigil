"""Post review results as GitHub PR review comments with inline annotations."""

import difflib
import logging
from collections import defaultdict
from pathlib import PurePosixPath

import httpx

from .comment_manager import deduplicate_comments
from .context_manager import stable_finding_key
from .diff_parser import commentable_lines, nearest_commentable_line
from .finding_validation import (
    STALE_EVIDENCE_COMMIT,
    STALE_HISTORICAL_EVIDENCE,
    UNSUPPORTED_CURRENT_STATUS,
    SuppressedFinding,
    validate_findings_against_head,
)
from .models import (
    BLOCKING_DECISIONS,
    DECISION_NOT_REVIEWED,
    Finding,
    PersonaVerdict,
    ReviewResult,
    Severity,
)
from .utils import (
    NOT_REVIEWED_ICON,
    embed_json_metadata,
    extract_message_content,
    github_headers,
    not_reviewed_label,
    severity_emoji,
)

log = logging.getLogger(__name__)

# The verdicts that actually block a merge. Only these earn inline review
# threads (issue #52): GitHub renders every inline comment as an unresolved
# thread, so any other verdict — APPROVE above all — must keep its findings in
# the review body or it blocks its own PR under a resolve-all-threads ruleset.
#
# The set itself moved to models.py in #79 so the review engine and this
# posting layer read one definition. It is imported above, which keeps
# `from vigil.github_review import BLOCKING_DECISIONS` working unchanged.


# Machine-readable marker naming the specialists that never ran, appended to
# the review body so downstream automation can detect a partial review without
# substring-matching prose. Mirrors the `<!-- vigil-did-not-run -->` marker the
# composite action posts when Vigil itself could not run (#51 item 1); this is
# the same promise at specialist granularity (F2iLLC/vigil#66). Emitted only
# when at least one specialist was skipped, so its mere presence is the signal.
#
# Scope is exactly "skipped" (PersonaVerdict.reviewed False): no files in
# scope, or a transiently unavailable reviewer. A specialist whose model call
# failed non-transiently is reported separately as decision="ERROR" and is
# deliberately NOT listed here — that row already renders as ⚠️ ERROR with a
# reviewer_error finding, which no reader mistakes for a completed review.
# So absence from this marker does NOT mean a specialist produced a verdict;
# automation that needs "did every specialist actually reach a conclusion?"
# must check the ERROR decision too.
SPECIALISTS_NOT_RUN_MARKER = "vigil-specialists-not-run"


def is_blocking_decision(decision: str) -> bool:
    """Return True when a review verdict is one that blocks the merge."""
    return decision in BLOCKING_DECISIONS


def react(owner: str, repo: str, pr_number: int, token: str, content: str) -> int | None:
    """Add a reaction to the PR. Returns the reaction ID (for later removal) or None."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/reactions"
    headers = github_headers(token)
    try:
        resp = httpx.post(url, headers=headers, json={"content": content}, timeout=10)
        if resp.status_code in (200, 201):
            return resp.json().get("id")
    except Exception:
        pass
    return None


def remove_reaction(owner: str, repo: str, pr_number: int, token: str, reaction_id: int) -> bool:
    """Remove a reaction from the PR by its ID."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/reactions/{reaction_id}"
    headers = github_headers(token)
    try:
        resp = httpx.delete(url, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def _format_finding(f: Finding, persona: str | None = None) -> str:
    """Format a single finding as markdown."""
    icon = severity_emoji(f.severity)
    source = f" ({persona})" if persona else ""
    line = f"  \n`{f.file}:{f.line}`" if f.line else f"  \n`{f.file}`"
    suggestion = f"  \n**Suggestion:** {f.suggestion}" if f.suggestion else ""
    return f"{icon} **[{f.severity.value.upper()}]** [{f.category}]{source}{line}  \n{f.message}{suggestion}"


def _format_inline_comment(f: Finding, persona: str | None = None, session_id: str = "") -> str:
    """Format a finding for an inline diff comment (no file/line since GitHub shows that)."""
    icon = severity_emoji(f.severity)
    source = f" **{persona}**" if persona else ""
    sid = f" `{session_id}`" if session_id else ""
    suggestion = f"\n\n**Suggestion:** {f.suggestion}" if f.suggestion else ""
    metadata = embed_json_metadata({
        "severity": f.severity.value,
        "category": f.category,
        "message": f.message,
        "suggestion": f.suggestion,
        "component": f.component,
        "predicate": f.predicate,
        "evidence_source": f.evidence_source,
        "evidence_commit": f.evidence_commit,
        "finding_key": stable_finding_key(f),
    })
    return (
        f"{icon} **[{f.severity.value.upper()}]** [{f.category}]{source}{sid}\n\n"
        f"{f.message}{suggestion}\n\n{metadata}"
    )


def _build_review_body(
    result: ReviewResult,
    inline_count: int = 0,
    observation_issues: list[tuple[Finding, str]] | None = None,
) -> str:
    """Build the review body. Findings posted inline are excluded from the body.

    Specialists that made no model call (``PersonaVerdict.reviewed`` False)
    are rendered as NOT REVIEWED rather than as the APPROVE their decision
    still carries \u2014 a verdict table implies verdicts were reached, and a
    synthesized green row was read as a completed review by two automated
    readers in F2iLLC/vigil#66. Their ``decision`` is untouched, so merge
    gating is byte-for-byte what it was; only what this body *says* changes.
    """
    sections = []

    # Which specialists actually got a model call (F2iLLC/vigil#66). Computed
    # once \u2014 the header line, the verdict table, the footer tally and the
    # machine-readable marker must all tell the same story.
    not_run = [v for v in result.specialist_verdicts if not v.reviewed]
    any_reviewed = any(v.reviewed for v in result.specialist_verdicts)

    # Header
    decision_emoji = {
        "APPROVE": "\u2705",
        "REQUEST_CHANGES": "\u274c",
        "BLOCK": "\U0001f6ab",
        # Never a check-mark: this verdict's whole point is that nothing was
        # reviewed. It reuses the skip marker the specialist rows use (#79).
        DECISION_NOT_REVIEWED: NOT_REVIEWED_ICON,
    }
    emoji = decision_emoji.get(result.decision, "\u2753")
    sections.append(f"## {emoji} Vigil Review: **{result.decision}**\n")
    if result.commit_sha:
        short_sha = result.commit_sha[:7]
        if not_run and not any_reviewed:
            # Every specialist was skipped, so this line's boilerplate claim
            # ("Reviewed commit X with Y") would be false \u2014 #66 calls it out
            # as printed whether or not the model was called. The model is
            # still named: it is what an operator needs to debug the skip.
            sections.append(
                f"*No specialist reviewed commit `{short_sha}` \u2014 every specialist was "
                f"skipped, so `{result.model}` was never asked about this diff.*\n"
            )
        else:
            # Unchanged whenever at least one specialist ran, and also when no
            # specialists are configured at all: nothing was skipped there, so
            # there is no false green to correct.
            sections.append(f"*Reviewed commit `{short_sha}` with `{result.model}`*\n")
    if not_run and not any_reviewed and result.summary:
        # The lead does see the full diff, so this summary is not invented —
        # but it is one generalist pass with no domain review behind it, and
        # it is written to read as a synthesis of specialist verdicts that in
        # this case do not exist. On F2iLLC/LunaOS#5028 it produced a fluent
        # paragraph ("well-scoped, follows existing project idioms") that a
        # human skimming the review had no way to discount (#79). The caveat
        # goes above it rather than deleting it: a reader who wants the lead's
        # read can still have it, they just cannot mistake it for a review.
        sections.append(
            f"> {NOT_REVIEWED_ICON} **No specialist reviewed this diff.** The summary below is a "
            "single lead-model pass with no specialist review behind it — not a "
            "substitute for one. This verdict does not approve the PR.\n"
        )
    sections.append(f"{result.summary}\n")

    # Specialist verdicts summary
    sections.append("### Specialist Verdicts\n")
    verdict_lines = []
    for v in result.specialist_verdicts:
        if not v.reviewed:
            # No model call was made for this specialist. No check-mark, and
            # never the word APPROVE \u2014 this row must be unmistakable.
            sid = f" `{v.session_id}`" if v.session_id else ""
            verdict_lines.append(
                f"| {NOT_REVIEWED_ICON} | **{v.persona}**{sid} | "
                f"{not_reviewed_label(v.skip_reason)} |"
            )
            continue

        icon = "\u2705" if v.decision == "APPROVE" else "\u274c" if v.decision == "REQUEST_CHANGES" else "\u26a0\ufe0f"
        n_findings = len(v.findings)
        n_obs = len(v.observations)
        detail = ""
        if n_findings:
            detail += f" \u2014 {n_findings} finding{'s' if n_findings != 1 else ''}"
        if n_obs:
            detail += f", {n_obs} observation{'s' if n_obs != 1 else ''}"
        checks_pass = sum(1 for c in v.checks.values() if c == "PASS")
        checks_total = len(v.checks)
        check_str = f" ({checks_pass}/{checks_total} checks pass)" if checks_total else ""
        sid = f" `{v.session_id}`" if v.session_id else ""
        verdict_lines.append(f"| {icon} | **{v.persona}**{sid} | {v.decision}{check_str}{detail} |")

    sections.append("| | Reviewer | Verdict |")
    sections.append("|---|---------|---------|")
    sections.extend(verdict_lines)
    sections.append("")

    # Non-inline findings go in body
    # (the caller separates inline vs body findings before calling this)

    # Observations — show as issue links if available, otherwise fallback to details block
    if result.observations:
        if observation_issues:
            # Build a lookup from finding id to issue URL
            issue_url_map: dict[int, str] = {id(f): url for f, url in observation_issues}
            tracked = sum(1 for f in result.observations if id(f) in issue_url_map)
            label = f"tracked as issue{'s' if tracked != 1 else ''}" if tracked else "non-blocking"
            sections.append(f"### Observations ({len(result.observations)} non-blocking \u2192 {label})\n")
            for obs in result.observations:
                sev_icon = severity_emoji(obs.severity)
                loc = f"`{obs.file}"
                if obs.line:
                    loc += f":{obs.line}"
                loc += "`"
                msg = obs.message
                if len(msg) > 80:
                    msg = msg[:77] + "..."
                url = issue_url_map.get(id(obs))
                if url:
                    # Extract issue number from URL for compact display
                    issue_num = url.rstrip("/").split("/")[-1]
                    sections.append(
                        f"- {sev_icon} [{obs.severity.value.upper()}] {loc} \u2014 {msg} \u2192 [#{issue_num}]({url})"
                    )
                else:
                    sections.append(
                        f"- {sev_icon} [{obs.severity.value.upper()}] {loc} \u2014 {msg}"
                    )
            sections.append("")
        else:
            # Fallback: no issue URLs, use collapsible details block
            sections.append(f"### Observations ({len(result.observations)} non-blocking)\n")
            sections.append("<details>\n<summary>Expand observations</summary>\n")
            for obs in result.observations:
                sections.append(_format_finding(obs))
                sections.append("")
            sections.append("</details>\n")

    # Footer
    total_findings = sum(len(v.findings) for v in result.specialist_verdicts) + len(result.lead_findings)
    # A specialist that never ran did not approve anything. Counting it in the
    # tally reproduced the same false green the table used to carry, in prose
    # ("6/6 specialists approved") \u2014 so it is counted separately (#66).
    approvals = sum(
        1 for v in result.specialist_verdicts if v.reviewed and v.decision == "APPROVE"
    )
    total = len(result.specialist_verdicts)
    inline_note = f" \u00b7 {inline_count} inline comments" if inline_count else ""
    not_run_note = f" \u00b7 {len(not_run)} not reviewed" if not_run else ""
    sections.append(f"---\n*{approvals}/{total} specialists approved{not_run_note} \u00b7 {total_findings} findings \u00b7 {len(result.observations)} observations{inline_note}*  ")
    sections.append("*Reviewed by [Vigil](https://github.com/F2iProject/vigil) \u2014 AI-powered, model-agnostic PR review*")

    # Machine-readable marker for the specialists that never ran (#66 asks for
    # this explicitly). Downstream automation gets a stable thing to match on
    # instead of parsing the prose above, which is free to change. Nothing is
    # emitted when every specialist ran, so presence alone is the signal.
    if not_run:
        skipped_names = ",".join(v.persona for v in not_run)
        sections.append(f"\n<!-- {SPECIALISTS_NOT_RUN_MARKER}: {skipped_names} -->")

    return "\n".join(sections)


def _build_body_findings_section(body_findings: list[tuple[str | None, Finding]]) -> str:
    """Build markdown for findings that couldn't be placed inline."""
    if not body_findings:
        return ""
    lines = ["### Findings (not in diff)\n"]
    for persona, f in body_findings:
        lines.append(_format_finding(f, persona))
        lines.append("")
    return "\n".join(lines)


def _build_advisory_findings_section(
    advisory_findings: list[tuple[str | None, Finding]],
) -> str:
    """Build markdown for findings carried by a review that does not block.

    A review whose verdict is neither REQUEST_CHANGES nor BLOCK has, by its
    own conclusion, found nothing merge-blocking. GitHub renders every inline
    review comment as an unresolved review thread, so placing these inline
    would make an approving review block its own PR under a ruleset that
    requires all threads resolved (issue #52). They are reported here instead,
    so nothing the review found is lost.
    """
    if not advisory_findings:
        return ""
    count = len(advisory_findings)
    lines = [
        f"### Advisory Findings ({count} non-blocking)\n",
        "*Not merge-blocking. This review does not request changes, so these "
        "are reported here as advisory notes rather than as inline review "
        "threads.*\n",
    ]
    for persona, f in advisory_findings:
        lines.append(_format_finding(f, persona))
        lines.append("")
    return "\n".join(lines)


def _build_suppressed_findings_section(
    suppressed: list[SuppressedFinding],
    head_sha: str = "",
) -> str:
    """Build markdown for findings the head-content guard withheld (#74).

    These are reported, not deleted. The defect this guard exists to fix was
    a review asserting things about content the cited commit did not contain;
    a guard that answered it by quietly removing findings would leave nobody
    able to tell a suppression from a review that simply found less. Each
    entry keeps its location and severity and states why it was withheld, so
    a wrong suppression is arguable on the PR itself.
    """
    if not suppressed:
        return ""
    at = f" at `{head_sha[:7]}`" if head_sha else ""
    lines = [
        f"### Suppressed Findings ({len(suppressed)} not supported{at})\n",
        "*Withheld before posting: the file each one cites, or the change it "
        "asks for, is not what the reviewed commit actually contains — so the "
        "finding describes older content than the SHA it carries "
        "(F2iLLC/vigil#74). Listed here rather than dropped silently.*\n",
    ]
    for item in suppressed:
        f = item.finding
        loc = f"`{f.file}" + (f":{f.line}" if f.line else "") + "`"
        msg = f.message if len(f.message) <= 100 else f.message[:97] + "..."
        lines.append(
            f"- {severity_emoji(f.severity)} [{f.severity.value.upper()}] "
            f"{loc} — {msg} — *withheld: {item.reason_text}*"
        )
    lines.append("")
    return "\n".join(lines)


def _place_finding_inline(
    f: Finding,
    persona: str | None,
    session_id: str,
    valid_lines: dict[str, set[int]],
) -> dict | None:
    """Place a finding only on its own file (or a unique path repair).

    Returns an inline comment dict, or None if no valid position exists.
    """
    # Try exact match first
    result = nearest_commentable_line(f.file, f.line, valid_lines)
    relocated_from = None

    if result is None:
        # File not in diff — find the best alternative file
        cited = f.file.replace("\\", "/").strip("./")
        cited_name = PurePosixPath(cited).name
        candidates = [
            path for path, lines in valid_lines.items()
            if lines and (
                path == cited
                or path.endswith("/" + cited)
                or cited.endswith("/" + path)
                or PurePosixPath(path).name == cited_name
            )
        ]
        result = None
        if len(candidates) == 1:
            result = nearest_commentable_line(candidates[0], f.line, valid_lines)
            relocated_from = f"{f.file}:{f.line or '?'}"

    elif result[1] != f.line or result[0] != f.file:
        # Same file but different line
        relocated_from = f"{f.file}:{f.line or '?'}"

    if result is None:
        return None

    path, line = result
    body = _format_inline_comment(f, persona, session_id)
    if relocated_from:
        body = f"*Originally for `{relocated_from}` (nearest diff location)*\n\n" + body

    return {"path": path, "line": line, "side": "RIGHT", "body": body}


def _group_similar_inline_comments(
    comments: list[dict],
    similarity_threshold: float = 0.85,
) -> list[dict]:
    """Group inline comments with near-identical messages across different locations.

    When the same finding (e.g. "redundant db.commit()") appears at N locations,
    post ONE representative comment and append a summary of the other locations.
    This prevents review spam where 20+ identical comments flood the PR.

    Returns a deduplicated list of inline comment dicts.
    """
    if len(comments) <= 1:
        return list(comments)

    # Extract normalized message text for each comment
    texts = [extract_message_content(c.get("body", "")) for c in comments]

    # Group by message similarity — union-find style
    # group_id[i] = canonical index for comment i
    group_id = list(range(len(comments)))

    def find(i: int) -> int:
        while group_id[i] != i:
            group_id[i] = group_id[group_id[i]]
            i = group_id[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            group_id[rb] = ra

    for i in range(len(comments)):
        if not texts[i]:
            continue
        for j in range(i + 1, len(comments)):
            if not texts[j]:
                continue
            # Skip if already in same group
            if find(i) == find(j):
                continue
            ratio = difflib.SequenceMatcher(None, texts[i], texts[j]).ratio()
            if ratio >= similarity_threshold:
                union(i, j)

    # Collect groups
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(comments)):
        groups[find(i)].append(i)

    result: list[dict] = []
    for members in groups.values():
        if len(members) == 1:
            result.append(comments[members[0]])
            continue

        # Pick the representative (first comment in the group)
        rep_idx = members[0]
        rep = dict(comments[rep_idx])  # shallow copy
        others = members[1:]

        # Build "also found at" summary
        locations = []
        for idx in others:
            c = comments[idx]
            locations.append(f"`{c['path']}:{c['line']}`")

        also_note = (
            f"\n\n---\n🔁 **Same pattern in {len(others)} other location{'s' if len(others) != 1 else ''}:** "
            + ", ".join(locations)
        )
        rep["body"] = rep["body"] + also_note
        result.append(rep)
        log.info(
            "Grouped %d similar findings into 1 comment (%s:%s)",
            len(members), rep["path"], rep["line"],
        )

    return result


def post_review(
    owner: str,
    repo: str,
    pr_number: int,
    result: ReviewResult,
    token: str,
    diff: str = "",
    existing_comments: list[dict] | None = None,
    observation_issues: list[tuple[Finding, str]] | None = None,
    outcome: dict | None = None,
) -> str:
    """Post the review result as a GitHub PR review with inline comments.

    Inline placement is reserved for verdicts that block the merge
    (REQUEST_CHANGES / BLOCK). On those, findings are forced inline where
    possible and only fall back to the review body when no commentable
    position exists. On any other verdict — APPROVE, or a decision that maps
    to a bare COMMENT — the review carries **zero** inline comments and its
    findings are reported in the body as advisory notes (issue #52). GitHub
    turns every inline comment into an unresolved review thread, so an
    approving review that posted them would block its own PR wherever a
    ruleset requires all threads resolved.

    Observations were already summary-only and stay that way.

    Before any of that, findings are checked against the content of
    ``result.commit_sha`` itself and any that the reviewed commit positively
    contradicts are withheld and reported under **Suppressed Findings**
    (F2iLLC/vigil#74). That check never alters ``result.decision`` and fails
    open on every error, so it can subtract text from a review but can never
    turn a blocking one into an approval.

    When multiple specialists flag the same issue, merged findings are posted
    with special formatting showing which specialists flagged the issue.

    Args:
        owner: Repository owner.
        repo: Repository name.
        pr_number: Pull request number.
        result: The aggregated ReviewResult with findings and observations.
            result.lead_findings may include merged findings from multiple
            specialists (see cross_specialist_dedup for formatting).
        token: GitHub API token.
        diff: Raw diff text for computing commentable lines.
        existing_comments: Pre-fetched Vigil comments for deduplication.
        observation_issues: Pairs of (Finding, issue_url) for observations
            that were opened as GitHub issues. When provided, the review body
            renders observations as compact issue links instead of a
            collapsible details block.
        outcome: Optional dict, populated in place with what was actually
            submitted: ``requested_event`` (what result.decision maps to) and
            ``submitted_event`` (what GitHub accepted — one of APPROVE,
            REQUEST_CHANGES, COMMENT, or ISSUE_COMMENT when every review
            attempt failed). Callers that act on the verdict landing — e.g.
            dismissing Vigil's own stale blocks (issue #48) — must check
            ``submitted_event``, because a degraded COMMENT review does not
            clear a block and dismissing on that path would leave the PR
            unguarded.

    Returns the URL of the created review.
    """
    # Build the map of commentable lines from the diff
    valid_lines: dict[str, set[int]] = {}
    if diff:
        valid_lines = commentable_lines(diff)

    # --- Step 0: Cross-round context filtering ---
    # Filter out findings that match ones from previous review rounds
    all_new_findings: list[Finding] = []
    
    # Collect all specialist and lead findings
    for v in result.specialist_verdicts:
        all_new_findings.extend(v.findings)
    all_new_findings.extend(result.lead_findings)
    
    # Filter cross-round duplicates
    if existing_comments and all_new_findings:
        try:
            from .context_manager import filter_cross_round_duplicates
            filtered_findings = filter_cross_round_duplicates(all_new_findings, existing_comments)
            
            # Rebuild verdicts with filtered findings
            removed_ids = {id(f) for f in all_new_findings} - {id(f) for f in filtered_findings}
            if removed_ids:
                log.info("Filtered %d cross-round duplicate finding(s)", len(removed_ids))
                for v in result.specialist_verdicts:
                    v.findings = [f for f in v.findings if id(f) not in removed_ids]
                result.lead_findings = [f for f in result.lead_findings if id(f) not in removed_ids]
        except Exception as e:
            log.debug("Cross-round filtering failed: %s", e)

    # --- Step 0b: Head-content validation (#74) ---
    # Findings are stamped with result.commit_sha and posted as the review's
    # commit_id. Nothing checked that the cited file and code support the
    # claim at that commit, so a finding about pre-rebase content could be
    # published under a correct-looking post-rebase SHA. Anything the guard
    # cannot positively disprove survives; see finding_validation for why the
    # bias runs that way and only that way.
    #
    # The legacy #74 reasons deliberately do NOT touch result.decision. Losing every finding does
    # not turn a REQUEST_CHANGES into an APPROVE here: the verdict, the
    # submitted event, and therefore the approve-only cleanup paths in cli.py
    # (dismissing Vigil's own stale blocks, #48, and resolving its open
    # threads, #61) behave exactly as they did before. The structured
    # provenance/status reasons added by #77 are handled narrowly below: when
    # they are the only reasons and no blocker remains, the submitted event is
    # COMMENT rather than REQUEST_CHANGES. A validation outage
    # must never be able to hand a PR a green gate.
    suppressed_findings: list[SuppressedFinding] = []
    findings_at_head = [f for v in result.specialist_verdicts for f in v.findings]
    findings_at_head.extend(result.lead_findings)
    if result.commit_sha and findings_at_head:
        try:
            _, suppressed_findings = validate_findings_against_head(
                findings_at_head, owner, repo, result.commit_sha, token,
                diff_files=list(valid_lines),
            )

            # The rebuild lives inside the `try` on purpose: it is the step
            # that actually removes findings from the review, so an exception
            # here has to fail open the same way the validation call does.
            # Outside it, a raise mid-rebuild would leave findings deleted
            # from the verdicts with `suppressed_findings` never reported —
            # i.e. silently dropped, which is the #74 failure mode itself.
            if suppressed_findings:
                stale_ids = {id(item.finding) for item in suppressed_findings}
                # Every list is computed before anything is assigned, so a
                # partially-applied rebuild is not a reachable state.
                kept_per_verdict = [
                    (v, [f for f in v.findings if id(f) not in stale_ids])
                    for v in result.specialist_verdicts
                ]
                kept_lead = [
                    f for f in result.lead_findings if id(f) not in stale_ids
                ]
                log.info(
                    "Withheld %d finding(s) not supported by %s",
                    len(stale_ids), result.commit_sha[:7],
                )
                for verdict, kept in kept_per_verdict:
                    verdict.findings = kept
                result.lead_findings = kept_lead
        except Exception as e:  # noqa: BLE001 — validation never fails a review
            log.warning(
                "Head-content validation failed (%s: %s) — posting every "
                "finding unvalidated",
                type(e).__name__, e,
            )
            suppressed_findings = []

    # --- Step 1: Route findings — inline only on a blocking verdict (#52) ---
    remaining_findings = [
        f for verdict in result.specialist_verdicts for f in verdict.findings
    ] + list(result.lead_findings)
    nonblocking_evidence_reasons = {
        STALE_HISTORICAL_EVIDENCE,
        STALE_EVIDENCE_COMMIT,
        UNSUPPORTED_CURRENT_STATUS,
    }
    deblocked_stale_only = bool(
        is_blocking_decision(result.decision)
        and findings_at_head
        and not remaining_findings
        and suppressed_findings
        and all(
            item.reason in nonblocking_evidence_reasons
            for item in suppressed_findings
        )
    )
    blocking_verdict = is_blocking_decision(result.decision) and not deblocked_stale_only

    inline_comments: list[dict] = []
    body_findings: list[tuple[str | None, Finding]] = []
    advisory_findings: list[tuple[str | None, Finding]] = []

    if blocking_verdict:
        # Place all findings inline where possible
        # Specialist findings
        for v in result.specialist_verdicts:
            for f in v.findings:
                comment = _place_finding_inline(f, v.persona, v.session_id, valid_lines)
                if comment:
                    inline_comments.append(comment)
                else:
                    body_findings.append((v.persona, f))

        # Lead findings
        for f in result.lead_findings:
            comment = _place_finding_inline(f, "Lead", "", valid_lines)
            if comment:
                inline_comments.append(comment)
            else:
                body_findings.append((None, f))
    else:
        # Either the review is nonblocking or its only blockers were
        # deterministically stale/unsupported. Nothing here may open a thread.
        for v in result.specialist_verdicts:
            for f in v.findings:
                advisory_findings.append((v.persona, f))
        for f in result.lead_findings:
            advisory_findings.append((None, f))
        if advisory_findings:
            log.info(
                "Verdict %s does not block — reporting %d finding(s) in the review "
                "body instead of inline (issue #52)",
                result.decision, len(advisory_findings),
            )

    # Deduplicate against existing Vigil comments
    if existing_comments:
        before_count = len(inline_comments)
        inline_comments = deduplicate_comments(inline_comments, existing_comments)
        dupes = before_count - len(inline_comments)
        if dupes:
            log.info("Deduplicated %d comments (already posted)", dupes)

    # Group similar findings within this review to avoid spam
    before_group = len(inline_comments)
    inline_comments = _group_similar_inline_comments(inline_comments)
    grouped = before_group - len(inline_comments)
    if grouped:
        log.info("Grouped %d similar comments into representative comments", grouped)

    def _compose_body(inline_count: int, appended: list[dict] | None = None) -> str:
        """Build the review body. One composer, so no fallback path drifts.

        ``inline_count`` is what the body claims was posted inline; the
        fallback ladder passes 0 once the inline comments have been folded
        into the text via ``appended``.
        """
        displayed_result = result
        if deblocked_stale_only:
            displayed_result = result.model_copy(update={
                "decision": "COMMENT",
                "summary": (
                    "No current blocking finding remained after exact-head "
                    "evidence validation. " + result.summary
                ),
            })
        text = _build_review_body(
            displayed_result,
            inline_count=inline_count,
            observation_issues=observation_issues,
        )
        if advisory_findings:
            text += "\n\n" + _build_advisory_findings_section(advisory_findings)
        if body_findings:
            text += "\n\n" + _build_body_findings_section(body_findings)
        if suppressed_findings:
            text += "\n\n" + _build_suppressed_findings_section(
                suppressed_findings, result.commit_sha,
            )
        for c in appended or []:
            text += f"\n\n**{c['path']}:{c['line']}**\n{c['body']}"
        return text

    # Build the body
    body = _compose_body(len(inline_comments))

    event_map = {
        "APPROVE": "APPROVE",
        "REQUEST_CHANGES": "REQUEST_CHANGES",
        "BLOCK": "REQUEST_CHANGES",  # GitHub has no BLOCK event
        # Posts, but approves nothing. A COMMENT review does not satisfy a
        # required-approval rule and does not block the merge either, which is
        # exactly right for "no specialist examined this" (#79). Stated
        # explicitly rather than left to the default below, so a future edit to
        # that default cannot silently turn this back into an approval.
        DECISION_NOT_REVIEWED: "COMMENT",
    }
    event = event_map.get(result.decision, "COMMENT")
    if deblocked_stale_only:
        event = "COMMENT"

    # Tracks what GitHub actually accepted, as the fallback ladder degrades.
    submitted_event = event

    def _record_outcome() -> None:
        if outcome is not None:
            outcome["requested_event"] = event
            outcome["submitted_event"] = submitted_event

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    headers = github_headers(token)

    def _attach_inline(review_payload: dict) -> dict:
        """Attach inline comments — and only on a blocking verdict (#52).

        Every review-creating attempt below builds its payload through here,
        so no rung of the fallback ladder can smuggle inline threads back
        onto a review that does not block. ``inline_comments`` is already
        empty on that path; this is the second lock on the same door.
        """
        if blocking_verdict and inline_comments:
            review_payload["comments"] = inline_comments
        return review_payload

    payload: dict = _attach_inline({
        "body": body,
        "event": event,
        "commit_id": result.commit_sha,  # Required for inline comments
    })

    pr_url_fallback = f"https://github.com/{owner}/{repo}/pull/{pr_number}"

    # --- Attempt 1: Full review with inline comments + event ---
    resp = httpx.post(url, headers=headers, json=payload, timeout=30)
    log.info("Attempt 1 (inline+event=%s): %s %s", event, resp.status_code, resp.text[:500])

    if resp.status_code == 422 and payload.get("comments"):
        # --- Attempt 2: Body-only review (inline comments may have bad positions) ---
        body_with_inlines = _compose_body(0, appended=inline_comments)
        resp = httpx.post(
            url, headers=headers,
            json={"body": body_with_inlines, "event": event, "commit_id": result.commit_sha},
            timeout=30,
        )
        log.info("Attempt 2 (body-only+event=%s): %s %s", event, resp.status_code, resp.text[:500])
        if resp.status_code != 422:
            body = body_with_inlines  # update for fallback use

    if resp.status_code == 422 and event != "COMMENT":
        # --- Attempt 3: Retry with event=COMMENT ---
        # APPROVE and REQUEST_CHANGES require write/collaborator access.
        # On third-party repos we can only submit COMMENT reviews.
        log.info("Event '%s' rejected (likely no write access) - retrying with COMMENT", event)
        # From here on the review carries no verdict: a COMMENT review neither
        # approves nor blocks, so it cannot clear a standing CHANGES_REQUESTED.
        submitted_event = "COMMENT"
        payload_comment: dict = _attach_inline({
            "body": body,
            "event": "COMMENT",
            "commit_id": result.commit_sha,
        })
        resp = httpx.post(url, headers=headers, json=payload_comment, timeout=30)
        log.info("Attempt 3 (inline+COMMENT): %s %s", resp.status_code, resp.text[:500])

        if resp.status_code == 422 and payload_comment.get("comments"):
            # --- Attempt 4: COMMENT without inline comments ---
            body_with_inlines = _compose_body(0, appended=inline_comments)
            resp = httpx.post(
                url, headers=headers,
                json={"body": body_with_inlines, "event": "COMMENT", "commit_id": result.commit_sha},
                timeout=30,
            )
            log.info("Attempt 4 (body-only+COMMENT): %s %s", resp.status_code, resp.text[:500])
            body = body_with_inlines

    if resp.status_code == 422:
        # --- Final fallback: post as a regular issue comment ---
        log.warning("All PR Review API attempts failed — falling back to issue comment")
        submitted_event = "ISSUE_COMMENT"
        comment_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        resp = httpx.post(comment_url, headers=headers, json={"body": body}, timeout=30)
        resp.raise_for_status()
        _record_outcome()
        return resp.json().get("html_url", pr_url_fallback)

    resp.raise_for_status()
    review_data = resp.json()
    _record_outcome()
    return review_data.get("html_url", pr_url_fallback)
