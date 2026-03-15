"""GitHub issue creation for non-blocking observations.

Automatically creates GitHub issues for observations and deduplicates
against existing open issues with the 'vigil' label.
"""

import difflib
import logging
import re

import httpx

from .models import Finding, ReviewResult, Severity
from .utils import extract_message_content, github_headers, severity_emoji

log = logging.getLogger(__name__)

_VIGIL_LABEL = "vigil"
_VIGIL_LABEL_COLOR = "6f42c1"
_VIGIL_LABEL_DESCRIPTION = "Auto-created by Vigil — AI-powered PR review"

# Marker in issue body to identify Vigil-created issues
_VIGIL_ISSUE_MARKER = "<!-- vigil-observation -->"


def ensure_vigil_label(owner: str, repo: str, token: str) -> bool:
    """Create the 'vigil' label if it doesn't exist. Returns True if created or exists."""
    url = f"https://api.github.com/repos/{owner}/{repo}/labels"
    try:
        resp = httpx.post(
            url,
            headers=github_headers(token),
            json={
                "name": _VIGIL_LABEL,
                "color": _VIGIL_LABEL_COLOR,
                "description": _VIGIL_LABEL_DESCRIPTION,
            },
            timeout=10,
        )
        if resp.status_code in (201, 200):
            return True
        if resp.status_code == 422:
            # Already exists
            return True
        log.warning("Failed to create label: %d %s", resp.status_code, resp.text)
        return False
    except Exception as e:
        log.warning("Failed to create label: %s", e)
        return False


def _build_issue_title(finding: Finding, persona: str) -> str:
    """Build a concise issue title."""
    msg = finding.message
    # Truncate message for title
    if len(msg) > 60:
        msg = msg[:57] + "..."
    return f"[Vigil/{persona}] {finding.category}: {msg}"


def _build_issue_body(
    finding: Finding,
    persona: str,
    pr_url: str = "",
    commit_sha: str = "",
) -> str:
    """Build the GitHub issue body with full finding details."""
    emoji = severity_emoji(finding.severity)
    loc = finding.file
    if finding.line:
        loc += f":{finding.line}"

    sections = [
        _VIGIL_ISSUE_MARKER,
        f"## {emoji} {finding.severity.value.upper()} — {finding.category}\n",
        f"**File:** `{loc}`",
        f"**Reviewer:** {persona}",
    ]

    if pr_url:
        sections.append(f"**PR:** {pr_url}")
    if commit_sha:
        sections.append(f"**Commit:** `{commit_sha[:7]}`")

    sections.append(f"\n### Finding\n\n{finding.message}")

    if finding.suggestion:
        sections.append(f"\n### Suggestion\n\n{finding.suggestion}")

    sections.append(
        "\n---\n"
        "*This issue was auto-created by [Vigil](https://github.com/F2iProject/vigil) "
        "from a non-blocking observation. It does not block the PR but should be tracked.*"
    )

    return "\n".join(sections)


def _fetch_all_vigil_issues(
    owner: str, repo: str, token: str,
) -> list[dict]:
    """Fetch all open issues with the 'vigil' label, paginating through all pages.

    Returns a list of issue dicts from the GitHub API.
    """
    url: str | None = f"https://api.github.com/repos/{owner}/{repo}/issues"
    params: dict | None = {"labels": _VIGIL_LABEL, "state": "open", "per_page": "100"}
    all_issues: list[dict] = []

    try:
        with httpx.Client() as client:
            while url:
                resp = client.get(url, headers=github_headers(token), params=params, timeout=15)
                resp.raise_for_status()
                all_issues.extend(resp.json())
                # Follow Link: <url>; rel="next" for pagination
                link = resp.headers.get("Link", "")
                url = None
                for part in link.split(","):
                    if 'rel="next"' in part:
                        url = part.split(";")[0].strip().strip("<>")
                params = None  # params baked into Link URL on subsequent pages
    except Exception as e:
        log.warning("Failed to fetch existing issues: %s", e)

    return all_issues


def _match_finding_to_issue(
    finding: Finding,
    issues: list[dict],
) -> str | None:
    """Check if any existing issue matches a finding.

    Matches by:
    1. Vigil issue marker present in body
    2. File path appearing in the body
    3. Message similarity >= 0.85

    Returns the issue HTML URL if found, None otherwise.
    """
    finding_text = extract_message_content(finding.message)
    if not finding_text:
        return None

    for issue in issues:
        body = issue.get("body") or ""
        # Must be a Vigil-created issue
        if _VIGIL_ISSUE_MARKER not in body:
            continue
        # Check file path match
        if f"`{finding.file}" not in body:
            continue
        # Extract and compare message content
        # The finding message is in the "### Finding" section
        finding_match = re.search(r"### Finding\s*\n\n(.+?)(?:\n###|\n---|$)", body, re.DOTALL)
        if not finding_match:
            continue
        existing_text = extract_message_content(finding_match.group(1))
        if not existing_text:
            continue
        ratio = difflib.SequenceMatcher(None, finding_text, existing_text).ratio()
        if ratio >= 0.85:
            return issue.get("html_url")

    return None


def find_existing_issue(
    owner: str,
    repo: str,
    token: str,
    finding: Finding,
    persona: str,
    existing_issues: list[dict] | None = None,
) -> str | None:
    """Check if an open Vigil issue already exists for this finding.

    Searches open issues with the 'vigil' label, matches by:
    1. File path appearing in the body
    2. Message similarity >= 0.85

    Args:
        owner: Repository owner.
        repo: Repository name.
        token: GitHub token.
        finding: The finding to check for duplicates.
        persona: Specialist persona name (unused in matching, kept for API compat).
        existing_issues: Pre-fetched list of open Vigil issues. If None, fetches them.

    Returns the issue HTML URL if found, None otherwise.
    """
    if existing_issues is None:
        existing_issues = _fetch_all_vigil_issues(owner, repo, token)
    return _match_finding_to_issue(finding, existing_issues)


def create_issue(
    owner: str,
    repo: str,
    token: str,
    finding: Finding,
    persona: str,
    pr_url: str = "",
    commit_sha: str = "",
) -> str | None:
    """Create a GitHub issue for a finding. Returns the issue HTML URL or None on failure."""
    title = _build_issue_title(finding, persona)
    body = _build_issue_body(finding, persona, pr_url, commit_sha)

    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    try:
        resp = httpx.post(
            url,
            headers=github_headers(token),
            json={
                "title": title,
                "body": body,
                "labels": [_VIGIL_LABEL],
            },
            timeout=15,
        )
        resp.raise_for_status()
        issue_url = resp.json().get("html_url", "")
        log.info("Created issue: %s", issue_url)
        return issue_url
    except Exception as e:
        log.warning("Failed to create issue: %s", e)
        return None


def create_issues_for_observations(
    owner: str,
    repo: str,
    token: str,
    result: ReviewResult,
    pr_url: str = "",
) -> list[tuple[Finding, str]]:
    """Create GitHub issues for all observations in the review result.

    Pre-fetches all existing open Vigil issues once to avoid N+1 API calls,
    then deduplicates each observation against the cache before creating.
    Groups observations with their source persona from specialist verdicts.

    Args:
        owner: Repository owner.
        repo: Repository name.
        token: GitHub token.
        result: The full review result containing observations.
        pr_url: PR URL for context in the issue body.

    Returns list of (finding, issue_url) tuples.
    """
    if not result.observations:
        return []

    # Ensure the vigil label exists
    ensure_vigil_label(owner, repo, token)

    # Pre-fetch all open Vigil issues once (avoids N+1 API calls)
    existing_issues = _fetch_all_vigil_issues(owner, repo, token)

    # Build persona lookup from observation_sources if available
    persona_map: dict[int, str] = {}
    if result.observation_sources:
        for persona_name, obs in result.observation_sources:
            persona_map[id(obs)] = persona_name

    # Fallback: map observations to personas from verdicts
    if not persona_map:
        for v in result.specialist_verdicts:
            for obs in v.observations:
                persona_map[id(obs)] = v.persona

    issues: list[tuple[Finding, str]] = []
    for obs in result.observations:
        persona = persona_map.get(id(obs), "Vigil")

        # Check for existing issue using pre-fetched cache
        existing_url = _match_finding_to_issue(obs, existing_issues)
        if existing_url:
            log.info("Observation already tracked: %s", existing_url)
            issues.append((obs, existing_url))
            continue

        # Create new issue
        issue_url = create_issue(
            owner, repo, token, obs, persona,
            pr_url=pr_url,
            commit_sha=result.commit_sha,
        )
        if issue_url:
            issues.append((obs, issue_url))

    return issues
