"""Post review results as GitHub PR review comments with inline annotations."""

import logging

import httpx

from .comment_manager import deduplicate_comments
from .diff_parser import commentable_lines, find_best_file_for_finding, nearest_commentable_line
from .models import Finding, PersonaVerdict, ReviewResult, Severity

log = logging.getLogger(__name__)


def react(owner: str, repo: str, pr_number: int, token: str, content: str) -> int | None:
    """Add a reaction to the PR. Returns the reaction ID (for later removal) or None."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/reactions"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
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
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    try:
        resp = httpx.delete(url, headers=headers, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def _format_finding(f: Finding, persona: str | None = None) -> str:
    """Format a single finding as markdown."""
    sev_emoji = {
        Severity.critical: "\U0001f534",
        Severity.high: "\U0001f7e0",
        Severity.medium: "\U0001f7e1",
        Severity.low: "\U0001f535",
    }
    icon = sev_emoji.get(f.severity, "")
    source = f" ({persona})" if persona else ""
    line = f"  \n`{f.file}:{f.line}`" if f.line else f"  \n`{f.file}`"
    suggestion = f"  \n**Suggestion:** {f.suggestion}" if f.suggestion else ""
    return f"{icon} **[{f.severity.value.upper()}]** [{f.category}]{source}{line}  \n{f.message}{suggestion}"


def _format_inline_comment(f: Finding, persona: str | None = None, session_id: str = "") -> str:
    """Format a finding for an inline diff comment (no file/line since GitHub shows that)."""
    sev_emoji = {
        Severity.critical: "\U0001f534",
        Severity.high: "\U0001f7e0",
        Severity.medium: "\U0001f7e1",
        Severity.low: "\U0001f535",
    }
    icon = sev_emoji.get(f.severity, "")
    source = f" **{persona}**" if persona else ""
    sid = f" `{session_id}`" if session_id else ""
    suggestion = f"\n\n**Suggestion:** {f.suggestion}" if f.suggestion else ""
    return f"{icon} **[{f.severity.value.upper()}]** [{f.category}]{source}{sid}\n\n{f.message}{suggestion}"


def _build_review_body(
    result: ReviewResult,
    inline_count: int = 0,
    observation_issues: list[tuple[Finding, str]] | None = None,
) -> str:
    """Build the review body. Findings posted inline are excluded from the body."""
    sections = []

    # Header
    decision_emoji = {"APPROVE": "\u2705", "REQUEST_CHANGES": "\u274c", "BLOCK": "\U0001f6ab"}
    emoji = decision_emoji.get(result.decision, "\u2753")
    sections.append(f"## {emoji} Vigil Review: **{result.decision}**\n")
    if result.commit_sha:
        short_sha = result.commit_sha[:7]
        sections.append(f"*Reviewed commit `{short_sha}` with `{result.model}`*\n")
    sections.append(f"{result.summary}\n")

    # Specialist verdicts summary
    sections.append("### Specialist Verdicts\n")
    verdict_lines = []
    for v in result.specialist_verdicts:
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
                sev_emoji = {
                    Severity.critical: "\U0001f534",
                    Severity.high: "\U0001f7e0",
                    Severity.medium: "\U0001f7e1",
                    Severity.low: "\U0001f535",
                }.get(obs.severity, "")
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
                        f"- {sev_emoji} [{obs.severity.value.upper()}] {loc} \u2014 {msg} \u2192 [#{issue_num}]({url})"
                    )
                else:
                    sections.append(
                        f"- {sev_emoji} [{obs.severity.value.upper()}] {loc} \u2014 {msg}"
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
    approvals = sum(1 for v in result.specialist_verdicts if v.decision == "APPROVE")
    total = len(result.specialist_verdicts)
    inline_note = f" \u00b7 {inline_count} inline comments" if inline_count else ""
    sections.append(f"---\n*{approvals}/{total} specialists approved \u00b7 {total_findings} findings \u00b7 {len(result.observations)} observations{inline_note}*  ")
    sections.append("*Reviewed by [Vigil](https://github.com/F2iProject/vigil) \u2014 AI-powered, model-agnostic PR review*")

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


def _place_finding_inline(
    f: Finding,
    persona: str | None,
    session_id: str,
    valid_lines: dict[str, set[int]],
) -> dict | None:
    """Try to place a finding as an inline comment, relocating if needed.

    Returns an inline comment dict, or None if no valid position exists.
    """
    # Try exact match first
    result = nearest_commentable_line(f.file, f.line, valid_lines)
    relocated_from = None

    if result is None:
        # File not in diff — find the best alternative file
        result = find_best_file_for_finding(f.file, valid_lines)
        if result is not None:
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


def post_review(
    owner: str,
    repo: str,
    pr_number: int,
    result: ReviewResult,
    token: str,
    diff: str = "",
    existing_comments: list[dict] | None = None,
    observation_issues: list[tuple[Finding, str]] | None = None,
) -> str:
    """Post the review result as a GitHub PR review with inline comments.

    All findings are forced inline where possible. Only falls back to the
    review body when the diff is completely empty.

    Returns the URL of the created review.
    """
    # Build the map of commentable lines from the diff
    valid_lines: dict[str, set[int]] = {}
    if diff:
        valid_lines = commentable_lines(diff)

    # Place all findings inline where possible
    inline_comments: list[dict] = []
    body_findings: list[tuple[str | None, Finding]] = []

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

    # Deduplicate against existing Vigil comments
    if existing_comments:
        before_count = len(inline_comments)
        inline_comments = deduplicate_comments(inline_comments, existing_comments)
        dupes = before_count - len(inline_comments)
        if dupes:
            log.info("Deduplicated %d comments (already posted)", dupes)

    # Build the body
    body = _build_review_body(result, inline_count=len(inline_comments), observation_issues=observation_issues)
    if body_findings:
        body += "\n\n" + _build_body_findings_section(body_findings)

    event_map = {
        "APPROVE": "APPROVE",
        "REQUEST_CHANGES": "REQUEST_CHANGES",
        "BLOCK": "REQUEST_CHANGES",  # GitHub has no BLOCK event
    }
    event = event_map.get(result.decision, "COMMENT")

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }

    payload: dict = {
        "body": body,
        "event": event,
        "commit_id": result.commit_sha,  # Required for inline comments
    }
    if inline_comments:
        payload["comments"] = inline_comments

    pr_url_fallback = f"https://github.com/{owner}/{repo}/pull/{pr_number}"

    # --- Attempt 1: Full review with inline comments + event ---
    resp = httpx.post(url, headers=headers, json=payload, timeout=30)
    log.info("Attempt 1 (inline+event=%s): %s %s", event, resp.status_code, resp.text[:500])

    if resp.status_code == 422 and inline_comments:
        # --- Attempt 2: Body-only review (inline comments may have bad positions) ---
        body_with_inlines = _build_review_body(result, inline_count=0)
        if body_findings:
            body_with_inlines += "\n\n" + _build_body_findings_section(body_findings)
        for c in inline_comments:
            body_with_inlines += f"\n\n**{c['path']}:{c['line']}**\n{c['body']}"
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
        payload_comment: dict = {
            "body": body,
            "event": "COMMENT",
            "commit_id": result.commit_sha,
        }
        if inline_comments:
            payload_comment["comments"] = inline_comments
        resp = httpx.post(url, headers=headers, json=payload_comment, timeout=30)
        log.info("Attempt 3 (inline+COMMENT): %s %s", resp.status_code, resp.text[:500])

        if resp.status_code == 422 and inline_comments:
            # --- Attempt 4: COMMENT without inline comments ---
            body_with_inlines = _build_review_body(result, inline_count=0)
            if body_findings:
                body_with_inlines += "\n\n" + _build_body_findings_section(body_findings)
            for c in inline_comments:
                body_with_inlines += f"\n\n**{c['path']}:{c['line']}**\n{c['body']}"
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
        comment_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        resp = httpx.post(comment_url, headers=headers, json={"body": body}, timeout=30)
        resp.raise_for_status()
        return resp.json().get("html_url", pr_url_fallback)

    resp.raise_for_status()
    review_data = resp.json()
    return review_data.get("html_url", pr_url_fallback)
