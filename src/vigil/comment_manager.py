"""Manage Vigil review comment lifecycle: fetch, resolve, deduplicate."""

import difflib
import logging
import re
from dataclasses import dataclass, field

import httpx

from .utils import (
    content_fingerprint,
    extract_message_content,
    github_headers,
    STRIP_PATTERNS,
)

log = logging.getLogger(__name__)

VIGIL_SIGNATURE = "Reviewed by [Vigil]"
VIGIL_SESSION_PATTERN = re.compile(r"VGL-[0-9a-f]{6}")

# Resolution reply detection
_RESOLUTION_KEYWORDS = re.compile(
    r"\b(resolved|fixed|addressed|done|over\s*ruled|overridden|wontfix|acceptable|follow[-\s]?up|tracked)\b",
    re.IGNORECASE,
)
_TRACKING_LINK_PATTERN = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/(?:issues|pull)/(\d+)"
)
_SHORT_ISSUE_REF = re.compile(r"#(\d+)")
_ISSUE_RELEVANCE_THRESHOLD = 0.25

# Backward-compatible aliases (used internally and by some imports)
_STRIP_PATTERNS = STRIP_PATTERNS

# Max thread IDs per batch mutation (GitHub GraphQL has a ~500KB payload limit)
_BATCH_SIZE = 50


def _github_headers(token: str) -> dict[str, str]:
    """Build standard GitHub API headers. Delegates to utils.github_headers."""
    return github_headers(token)


def _paginate(url: str, headers: dict[str, str], params: dict | None = None) -> list[dict]:
    """Fetch all pages from a GitHub REST API endpoint."""
    results: list[dict] = []
    params = {**(params or {}), "per_page": "100"}
    with httpx.Client() as client:
        while url:
            resp = client.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            results.extend(resp.json())
            # Follow Link: <url>; rel="next"
            link = resp.headers.get("Link", "")
            url = ""
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
            params = None  # params are baked into the Link URL
    return results


def fetch_vigil_reviews(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Fetch all PR reviews authored by Vigil (identified by signature in body)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    all_reviews = _paginate(url, _github_headers(token))
    return [r for r in all_reviews if VIGIL_SIGNATURE in (r.get("body") or "")]


def fetch_vigil_comments(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Fetch all inline review comments on the PR that belong to Vigil."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    all_comments = _paginate(url, _github_headers(token))
    return [c for c in all_comments if VIGIL_SESSION_PATTERN.search(c.get("body", ""))]


def fetch_all_pr_comments(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Fetch ALL review comments on the PR (for finding 'resolved' replies)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    return _paginate(url, _github_headers(token))


def fetch_pr_conversation_comments(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Fetch top-level PR conversation comments (the Conversation tab).

    A pull request is a GitHub issue under the hood. Inline diff comments live
    under /pulls/{n}/comments (see fetch_all_pr_comments); general discussion,
    bot replies (e.g. a connector announcing it reviews PRs), and non-review
    commentary live under /issues/{n}/comments instead. This is where a claim
    made in the diff or PR body can be contradicted by something already said
    in the thread.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    return _paginate(url, _github_headers(token))


def fetch_all_pr_reviews(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Fetch all PR reviews (not just Vigil's), for their summary bodies.

    Prior review verdicts are also conversation evidence — a PR that reasserts
    something a previous review already addressed should be checked against it.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    return _paginate(url, _github_headers(token))


_MAX_CONVERSATION_CHARS = 6000
_MAX_CONVERSATION_ITEM_CHARS = 800


def build_conversation_context(
    comments: list[dict],
    reviews: list[dict] | None = None,
    max_total_chars: int = _MAX_CONVERSATION_CHARS,
    max_item_chars: int = _MAX_CONVERSATION_ITEM_CHARS,
    head_sha: str = "",
) -> str:
    """Format PR conversation comments + review summaries for specialist context.

    Vigil's own output is excluded from **both** sources: a prior verdict is
    generated evidence about an older head, not independent conversation.

    Returns chronologically-ordered, truncated plain text — empty string if
    there's nothing to show. Items are dropped (not further truncated) once
    the total budget is exhausted, with a note of how many were omitted, so
    the most recent thread activity is always preserved in favor of older
    entries when a PR has an unusually long history.
    """
    # timestamp, author, body, kind, attributed commit.  Top-level comments
    # are intentionally unattributed: their creation time does not prove what
    # tree the author inspected.
    items: list[tuple[str, str, str, str, str]] = []

    for c in comments:
        body = (c.get("body") or "").strip()
        if not body:
            continue
        # Same exclusion as the reviews loop below, and for the same reason —
        # it was missing here, which made the exclusion ineffective. When the
        # PR Review API rejects every attempt, post_review falls back to
        # posting the whole review body as an *issue* comment, and issue
        # comments arrive through this loop. So Vigil's own prior findings
        # re-entered the next round's prompt as "PR Conversation" evidence and
        # could anchor a re-review on a defect a later commit removed
        # (F2iLLC/vigil#74). A human reply that quotes the whole review
        # verbatim, signature included, is excluded too; that is the safe
        # direction, and a human's own words are only lost when they carry no
        # text of their own.
        if VIGIL_SIGNATURE in body:
            continue
        items.append((
            c.get("created_at", ""),
            c.get("user", {}).get("login", "unknown"),
            body,
            "human_comment",
            "",
        ))

    for r in reviews or []:
        body = (r.get("body") or "").strip()
        if not body:
            continue
        # A prior Vigil verdict is generated evidence about an older head, not
        # independent conversation evidence. Feeding it back into a re-review
        # can anchor the model on findings that a later commit removed. Human
        # reviews remain useful context; Vigil's own summaries are handled by
        # the dedicated cross-round lifecycle instead.
        if VIGIL_SIGNATURE in body:
            continue
        state = (r.get("state") or "").lower()
        items.append((
            r.get("submitted_at", ""),
            r.get("user", {}).get("login", "unknown"),
            body,
            f"review:{state}" if state else "review",
            r.get("commit_id") or "",
        ))

    if not items:
        return ""

    items.sort(key=lambda item: item[0])

    # Fill the budget from most recent backwards, so a long thread keeps its
    # latest activity (where a claim is most likely to have been contradicted
    # or resolved) instead of losing it to older entries filling the quota.
    kept: list[str] = []
    total = 0
    omitted = 0
    for created_at, author, body, kind, evidence_commit in reversed(items):
        if len(body) > max_item_chars:
            body = body[:max_item_chars] + " …[truncated]"
        attributable = bool(
            head_sha and evidence_commit and evidence_commit.lower() == head_sha.lower()
        )
        commit_label = evidence_commit[:12] if evidence_commit else "unattributed"
        entry = (
            f"[vigil-evidence source={kind} commit={commit_label} "
            f"current_head={'true' if attributable else 'false'}]\n"
            f"**{author}** ({kind}, {created_at}):\n{body}"
        )
        if total + len(entry) > max_total_chars:
            omitted += 1
            continue
        kept.append(entry)
        total += len(entry)

    entries = list(reversed(kept))
    if omitted:
        entries.insert(0, f"…[{omitted} earlier thread item(s) omitted for length]")

    return "\n\n---\n\n".join(entries)


def get_last_reviewed_sha(owner: str, repo: str, pr_number: int, token: str) -> str | None:
    """Find the most recent Vigil review and return its commit SHA.

    NOTE: this deliberately ignores review ``state`` — a DISMISSED review is
    returned exactly like a live one. That is why it cannot be the only input
    to the re-review decision; see ``get_vigil_review_state`` (issue #49).
    """
    reviews = fetch_vigil_reviews(owner, repo, pr_number, token)
    if not reviews:
        return None
    latest = sorted(reviews, key=lambda r: r.get("submitted_at", ""), reverse=True)[0]
    return latest.get("commit_id")


# --- Review-state inspection (issue #49) ---------------------------------
#
# GitHub review states we care about:
#   APPROVED           - a standing approval
#   CHANGES_REQUESTED  - a standing block
#   COMMENTED          - a non-verdict review (what Vigil degrades to when it
#                        lacks the write access to APPROVE/REQUEST_CHANGES)
#   DISMISSED          - a verdict that has been withdrawn, by a human or by
#                        the branch rule `dismiss_stale_reviews_on_push`.
#                        Still returned by the reviews API.
VIGIL_BLOCK_STATE = "CHANGES_REQUESTED"

# States that mean "Vigil has already said its piece about this exact commit
# and does not need to say it again". A DISMISSED review is excluded because
# it has been withdrawn — that is the praxislms#263 shape, where the gate
# could not be reopened even though nothing live remained at head.
# CHANGES_REQUESTED is excluded because a standing block is precisely the
# thing Vigil must be able to reconsider — that is the bioqms-core#1472 shape.
# COMMENTED IS included on purpose: on a repo with no VIGIL_REVIEW_TOKEN every
# Vigil review degrades to COMMENT, and treating those as unsettled would
# re-review on every PR event forever.
_SETTLED_VERDICT_STATES = frozenset({"APPROVED", "COMMENTED"})


def _review_state(review: dict) -> str:
    """Normalized upper-case review state ('' when absent)."""
    return (review.get("state") or "").strip().upper()


def select_outstanding_vigil_blocks(reviews: list[dict]) -> list[dict]:
    """Vigil reviews still standing as CHANGES_REQUESTED.

    Pure. A review that was later dismissed comes back from the API with
    state DISMISSED, so filtering on CHANGES_REQUESTED already excludes it.
    """
    return [r for r in reviews if _review_state(r) == VIGIL_BLOCK_STATE]


def has_settled_vigil_verdict_at(reviews: list[dict], head_sha: str | None) -> bool:
    """True when Vigil has a live, settled verdict on this exact commit.

    "Settled" means APPROVED or COMMENTED (see ``_SETTLED_VERDICT_STATES``).
    A DISMISSED review at head does not count, which is what lets a
    dismissed-verdict head reopen the review gate.

    When ``head_sha`` is unknown this returns True — the conservative answer,
    because the caller uses it to decide whether to spend a review, and we
    would rather skip than re-review the world on missing data.
    """
    if not head_sha:
        return True
    return any(
        r.get("commit_id") == head_sha and _review_state(r) in _SETTLED_VERDICT_STATES
        for r in reviews
    )


@dataclass(frozen=True)
class VigilReviewState:
    """Everything the re-review decision needs, from a single reviews fetch."""

    last_reviewed_sha: str | None = None
    outstanding_blocks: list[dict] = field(default_factory=list)
    settled_verdict_at_head: bool = True


def get_vigil_review_state(
    owner: str, repo: str, pr_number: int, token: str, head_sha: str | None = None,
) -> VigilReviewState:
    """Fetch Vigil's reviews once and summarize them for the review gate.

    Sibling of ``get_last_reviewed_sha`` (whose signature is unchanged because
    other callers depend on it). This one keeps the review ``state`` that
    ``get_last_reviewed_sha`` collapses away.
    """
    reviews = fetch_vigil_reviews(owner, repo, pr_number, token)
    if not reviews:
        return VigilReviewState()
    latest = sorted(reviews, key=lambda r: r.get("submitted_at", ""), reverse=True)[0]
    return VigilReviewState(
        last_reviewed_sha=latest.get("commit_id"),
        outstanding_blocks=select_outstanding_vigil_blocks(reviews),
        settled_verdict_at_head=has_settled_vigil_verdict_at(reviews, head_sha),
    )


def _dismiss_review(
    owner: str, repo: str, pr_number: int, review_id: int, message: str, token: str,
) -> bool:
    """Dismiss one PR review via the REST dismissal endpoint. Never raises.

    This is the injectable seam for issue #48: tests patch this function to
    exercise both the accepted and the rejected branch without network access,
    the same way ``_paginate`` and ``_graphql`` are patched elsewhere.

    OPEN QUESTION (issue #48): GitHub hides self-dismissal in the UI, and
    whether the REST endpoint permits an identity to dismiss its own review is
    UNVERIFIED — it has deliberately not been exercised against a live PR. If
    runtime logs show 403/422 here, the fallback the issue proposes is to
    perform the dismissal under a second identity (GITHUB_TOKEN rather than
    VIGIL_REVIEW_TOKEN). That credential switch is NOT implemented here
    because it is equally untested; adding it blind would trade one unverified
    path for another. Until then this degrades safely: log and carry on, so a
    rejected dismissal costs a stale block, never an unguarded PR.
    """
    url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/pulls/{pr_number}/reviews/{review_id}/dismissals"
    )
    try:
        resp = httpx.put(
            url,
            headers=_github_headers(token),
            json={"message": message, "event": "DISMISS"},
            timeout=30,
        )
    except Exception as e:  # network error, timeout, DNS, ...
        log.warning("Dismissal request for review %s failed: %s", review_id, e)
        return False

    if resp.status_code >= 400:
        # No retry: a 403/422 here is a permission verdict, not a blip, and a
        # retry storm against a merge-gating control is worse than a stale block.
        log.warning(
            "GitHub rejected dismissal of review %s: %s %s",
            review_id, resp.status_code, (resp.text or "")[:300],
        )
        return False

    log.info("Dismissed stale Vigil block (review %s)", review_id)
    return True


def dismiss_stale_vigil_blocks(
    owner: str, repo: str, pr_number: int, token: str, message: str,
    reviews: list[dict] | None = None,
) -> list[int]:
    """Withdraw every Vigil review still standing as CHANGES_REQUESTED.

    Returns the ids actually dismissed. Never raises — the caller has just put
    a replacement verdict on record and must not fail the review because the
    cleanup did not take.

    Callers MUST have posted a genuine replacement approval first; see the
    guards at the call site in cli.py (issue #48).
    """
    try:
        candidates = (
            reviews if reviews is not None
            else fetch_vigil_reviews(owner, repo, pr_number, token)
        )
    except Exception as e:
        log.warning("Could not fetch Vigil reviews to dismiss stale blocks: %s", e)
        return []

    dismissed: list[int] = []
    for review in select_outstanding_vigil_blocks(candidates):
        review_id = review.get("id")
        if review_id is None:
            continue
        if _dismiss_review(owner, repo, pr_number, review_id, message, token):
            dismissed.append(review_id)
    return dismissed


def _graphql(query: str, variables: dict, token: str) -> dict:
    """Execute a GitHub GraphQL query."""
    resp = httpx.post(
        "https://api.github.com/graphql",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "variables": variables},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        log.warning("GraphQL errors: %s", data["errors"])
    return data


def fetch_review_threads(
    owner: str, repo: str, pr_number: int, token: str
) -> list[dict]:
    """Fetch review threads via GraphQL with path, line, body, and resolution status.

    Returns list of dicts: {id, isResolved, path, line, body, comments}
    """
    query = """
    query($owner: String!, $repo: String!, $pr: Int!, $cursor: String) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr) {
          reviewThreads(first: 100, after: $cursor) {
            pageInfo { hasNextPage endCursor }
            nodes {
              id
              isResolved
              comments(first: 20) {
                nodes {
                  id
                  body
                  path
                  line
                  author {
                    login
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    threads: list[dict] = []
    cursor = None
    while True:
        variables = {"owner": owner, "repo": repo, "pr": pr_number, "cursor": cursor}
        data = _graphql(query, variables, token)
        pr_data = data.get("data", {}).get("repository", {}).get("pullRequest", {})
        thread_data = pr_data.get("reviewThreads", {})
        for node in thread_data.get("nodes", []):
            comments = node.get("comments", {}).get("nodes") or []
            first_comment = (comments or [{}])[0]
            threads.append({
                "id": node["id"],
                "isResolved": node["isResolved"],
                "path": first_comment.get("path"),
                "line": first_comment.get("line"),
                "body": first_comment.get("body", ""),
                "comments": comments,
            })
        page_info = thread_data.get("pageInfo", {})
        if page_info.get("hasNextPage"):
            cursor = page_info["endCursor"]
        else:
            break
    return threads


def resolve_thread_by_node_id(node_id: str, token: str) -> bool:
    """Resolve a single review thread using the GraphQL resolveReviewThread mutation."""
    resolved = resolve_threads_batch([node_id], token)
    return len(resolved) == 1


def resolve_threads_batch(thread_ids: list[str], token: str) -> list[str]:
    """Resolve multiple review threads in batched GraphQL mutations.

    Sends up to _BATCH_SIZE mutations per request to avoid N+1 round-trips.
    Returns list of successfully resolved thread IDs.
    """
    if not thread_ids:
        return []

    resolved: list[str] = []
    for batch_start in range(0, len(thread_ids), _BATCH_SIZE):
        batch = thread_ids[batch_start : batch_start + _BATCH_SIZE]

        # Build a single mutation with aliased resolveReviewThread calls
        mutation_parts = []
        variables: dict[str, str] = {}
        for i, tid in enumerate(batch):
            var_name = f"tid{i}"
            variables[var_name] = tid
            mutation_parts.append(
                f"  t{i}: resolveReviewThread(input: {{threadId: ${var_name}}}) {{"
                f"    thread {{ id isResolved }}"
                f"  }}"
            )

        # Build variable declarations
        var_decls = ", ".join(f"${k}: ID!" for k in variables)
        mutation = f"mutation({var_decls}) {{\n" + "\n".join(mutation_parts) + "\n}"

        try:
            data = _graphql(mutation, variables, token)
            result_data = data.get("data", {})
            for i, tid in enumerate(batch):
                alias = f"t{i}"
                thread_result = result_data.get(alias, {}).get("thread", {})
                if thread_result.get("isResolved"):
                    resolved.append(tid)
        except Exception as e:
            log.warning("Batch resolve failed for %d threads: %s", len(batch), e)

    return resolved


def _thread_has_addressing_reply(thread: dict) -> bool:
    """Return true when a Vigil thread has at least one non-empty reply."""
    comments = thread.get("comments") or []
    if len(comments) < 2:
        return False

    root_author = ((comments[0].get("author") or {}).get("login") or "").lower()
    for reply in comments[1:]:
        body = (reply.get("body") or "").strip()
        if not body:
            continue
        author = ((reply.get("author") or {}).get("login") or "").lower()
        if author and root_author and author == root_author:
            continue
        return True
    return False


def resolve_addressed_threads(
    owner: str, repo: str, pr_number: int, token: str,
    changed_files: dict[str, set[int]],
) -> int:
    """Resolve Vigil comment threads where the underlying code has changed.

    A thread is considered 'addressed' if:
      - It's a Vigil thread (body contains VGL session ID)
      - It's not already resolved
      - Its file is in changed_files AND either:
        - its line is in the changed lines set, or
        - someone replied in the thread and the same file changed

    Returns count of resolved threads.
    """
    threads = fetch_review_threads(owner, repo, pr_number, token)

    # Collect thread IDs that need resolution
    to_resolve: list[str] = []
    for t in threads:
        if t["isResolved"]:
            continue
        if not VIGIL_SESSION_PATTERN.search(t.get("body", "")):
            continue
        path = t.get("path")
        line = t.get("line")
        if path and path in changed_files:
            file_lines = changed_files[path]
            line_changed = line is None or line in file_lines
            file_changed_with_reply = bool(file_lines) and _thread_has_addressing_reply(t)
            if line_changed or file_changed_with_reply:
                to_resolve.append(t["id"])

    if not to_resolve:
        return 0

    resolved = resolve_threads_batch(to_resolve, token)
    for tid in resolved:
        log.info("Resolved addressed thread %s", tid)
    return len(resolved)


def resolve_vigil_threads_on_approval(
    owner: str, repo: str, pr_number: int, token: str,
) -> int:
    """Resolve every still-open Vigil thread on a PR Vigil has just approved.

    Decision-driven, not diff-driven — and that is the whole point. Its sibling
    `resolve_addressed_threads` only ever considers threads whose file appears
    in the incremental diff since the last review, so a thread opened in an
    earlier round on a file that later rounds never touch is never revisited.
    Cross-round dedup then suppresses re-posting the same finding, so nothing
    re-touches the thread either. The PR is left carrying an unresolved Vigil
    thread underneath an approving Vigil review, indefinitely — a merge blocker
    attached to a review that approved the PR, under any "resolve all threads
    before merge" ruleset (issue #61).

    Scope is ALL of Vigil's own unresolved threads on the PR, deliberately NOT
    only the current session's. `session_id` is per-SPECIALIST-RUN, not
    per-review-round (models.py: `PersonaVerdict.session_id`), so threads left
    over from earlier rounds necessarily carry different session IDs. A
    current-session-only implementation would therefore resolve nothing in
    exactly the reported scenario — it would pass its own tests and not fix the
    reported behavior.

    Vigil's own threads are identified the way the rest of this module
    identifies them: the `VGL-` marker in the thread body
    (`VIGIL_SESSION_PATTERN`). That gate is what guarantees human-authored
    threads are never touched.

    Callers MUST have put a genuine accepted approval on record first; see the
    guards at the call site in cli.py (issue #61).

    Returns count of resolved threads.
    """
    threads = fetch_review_threads(owner, repo, pr_number, token)

    to_resolve: list[str] = []
    for t in threads:
        if t["isResolved"]:
            continue
        # The VGL gate is the human-thread guard. Never widen it.
        if not VIGIL_SESSION_PATTERN.search(t.get("body", "")):
            continue
        to_resolve.append(t["id"])

    if not to_resolve:
        return 0

    resolved = resolve_threads_batch(to_resolve, token)
    for tid in resolved:
        log.info("Resolved Vigil thread %s on approval", tid)
    return len(resolved)


def _is_resolution_reply(body: str) -> bool:
    """Check if a reply body indicates resolution (keyword, issue link, or combo)."""
    body = body.strip()
    if not body:
        return False
    # Pure keyword match
    if _RESOLUTION_KEYWORDS.search(body):
        return True
    # Issue link (full URL or short ref like #45)
    if _TRACKING_LINK_PATTERN.search(body) or _SHORT_ISSUE_REF.search(body):
        return True
    return False


def _extract_issue_refs(body: str) -> list[tuple[str, str, int]]:
    """Extract (owner, repo, issue_number) tuples from issue references.

    Handles both full URLs (https://github.com/org/repo/issues/123)
    and short refs (#123). Short refs without owner/repo context return
    empty strings for owner/repo (caller must fill in from PR context).
    """
    results: list[tuple[str, str, int]] = []

    # Full URL matches — track their spans so we don't double-count short refs inside them
    full_url_spans: list[tuple[int, int]] = []
    for match in _TRACKING_LINK_PATTERN.finditer(body):
        owner, repo, num = match.group(1), match.group(2), int(match.group(3))
        results.append((owner, repo, num))
        full_url_spans.append((match.start(), match.end()))

    # Short refs — skip if they fall inside a full URL
    for match in _SHORT_ISSUE_REF.finditer(body):
        pos = match.start()
        inside_url = any(start <= pos < end for start, end in full_url_spans)
        if not inside_url:
            results.append(("", "", int(match.group(1))))

    return results


def _fetch_issue(owner: str, repo: str, issue_number: int, token: str) -> dict | None:
    """Fetch a GitHub issue by number. Returns None on failure."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
    try:
        resp = httpx.get(url, headers=_github_headers(token), timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.warning("Failed to fetch issue %s/%s#%d: %s", owner, repo, issue_number, e)
        return None


def _issue_covers_finding(issue: dict, finding_body: str) -> bool:
    """Check if an issue's content is relevant to a Vigil finding.

    Uses keyword overlap: extracts meaningful words from the finding body,
    checks what fraction appear in the issue title + body.
    """
    stop_words = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "shall", "can", "need", "must", "ought",
        "this", "that", "these", "those", "it", "its", "not", "no", "nor",
        "but", "and", "or", "so", "if", "then", "than", "too", "very",
        "for", "with", "about", "against", "between", "through", "during",
        "before", "after", "above", "below", "from", "up", "down", "in",
        "out", "on", "off", "over", "under", "again", "further", "once",
        "here", "there", "when", "where", "why", "how", "all", "each",
        "every", "both", "few", "more", "most", "other", "some", "such",
        "only", "own", "same", "also", "just", "use", "used", "using",
        "file", "line", "code", "null", "none", "true", "false",
    }

    finding_text = _extract_message_content(finding_body)
    issue_text = (issue.get("title", "") + " " + (issue.get("body") or "")).lower()

    finding_words = [w for w in re.findall(r"[a-z]{3,}", finding_text) if w not in stop_words]
    if not finding_words:
        return True  # If no meaningful words, give benefit of doubt

    matches = sum(1 for w in finding_words if w in issue_text)
    return (matches / len(finding_words)) >= _ISSUE_RELEVANCE_THRESHOLD


def _parse_finding_from_comment(body: str, path: str | None, line: int | None) -> "Finding | None":
    """Try to reconstruct a Finding from a Vigil inline comment body.

    Extracts severity, category, and message from the formatted comment text.
    Returns a Finding object or None if parsing fails.
    Hardened against ReDoS with input length limits and bounded quantifiers.
    """
    from .models import Finding, Severity

    # Limit input to prevent ReDoS attacks
    max_body_length = 10000
    if len(body) > max_body_length:
        body = body[:max_body_length]

    # Extract severity from tags like **[CRITICAL]**, **[HIGH]**, etc.
    sev_match = re.search(r"\*\*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\*\*", body)
    if not sev_match:
        return None
    sev_str = sev_match.group(1).lower()
    sev_map = {"critical": Severity.critical, "high": Severity.high,
               "medium": Severity.medium, "low": Severity.low}
    severity = sev_map.get(sev_str, Severity.medium)

    # Extract category from [CategoryName] tags
    # Use bounded quantifier {1,100} to prevent ReDoS
    # Restrict character class to be more specific (word chars, space, slash, hyphen)
    cat_match = re.search(r"\[([\w\s/\-]{1,100})\]", body[sev_match.end():])
    category = cat_match.group(1).strip() if cat_match else "unknown"

    # Extract message: everything after the header line(s), before suggestion
    message = _extract_message_content(body)
    if not message:
        return None

    return Finding(
        file=path or "unknown",
        line=line,
        severity=severity,
        category=category,
        message=message,
    )


def resolve_dismissed_threads(
    owner: str, repo: str, pr_number: int, token: str,
) -> int:
    """Resolve Vigil threads that received a 'resolved' reply.

    Scans all PR review comments. For each Vigil inline comment thread,
    checks if any reply contains 'resolved' (case-insensitive).
    If so, resolves the thread via GraphQL and logs the decision.

    Returns count of resolved threads.
    """
    all_comments = fetch_all_pr_comments(owner, repo, pr_number, token)

    # Build lookup: comment_id -> comment
    by_id: dict[int, dict] = {c["id"]: c for c in all_comments}

    # Find Vigil root comments and their reply chains
    vigil_roots: set[int] = set()
    replies_to: dict[int, list[dict]] = {}  # root_id -> [reply comments]

    for c in all_comments:
        if VIGIL_SESSION_PATTERN.search(c.get("body", "")) and not c.get("in_reply_to_id"):
            vigil_roots.add(c["id"])

    for c in all_comments:
        parent_id = c.get("in_reply_to_id")
        if parent_id and parent_id in vigil_roots:
            replies_to.setdefault(parent_id, []).append(c)

    # Check which Vigil root comments have resolution replies
    # Track by (path, line, session_id) for robust matching to GraphQL threads
    roots_to_resolve: list[dict] = []  # root comment dicts
    resolution_info: dict[int, dict] = {}  # root_id -> {reason, decided_by}
    for root_id in vigil_roots:
        replies = replies_to.get(root_id, [])
        for reply in replies:
            reply_body = reply.get("body", "").strip()
            if not _is_resolution_reply(reply_body):
                continue

            # Check if reply contains issue links that need verification
            issue_refs = _extract_issue_refs(reply_body)
            if issue_refs:
                # Verify at least one linked issue covers the finding
                root_body = by_id[root_id].get("body", "")
                verified = False
                for ref_owner, ref_repo, ref_num in issue_refs:
                    # Fill in owner/repo from PR context for short refs
                    ref_owner = ref_owner or owner
                    ref_repo = ref_repo or repo
                    issue = _fetch_issue(ref_owner, ref_repo, ref_num, token)
                    if issue and _issue_covers_finding(issue, root_body):
                        verified = True
                        break
                if not verified:
                    log.info(
                        "Issue link(s) in reply to comment %d don't cover the finding — skipping",
                        root_id,
                    )
                    continue

            # Capture resolution metadata for decision logging
            resolution_info[root_id] = {
                "reason": reply_body,
                "decided_by": reply.get("user", {}).get("login", ""),
            }
            roots_to_resolve.append(by_id[root_id])
            break

    if not roots_to_resolve:
        return 0

    # Log decisions for resolved findings
    repo_key = f"{owner}/{repo}"
    pr_url = f"https://github.com/{owner}/{repo}/pull/{pr_number}"
    for root in roots_to_resolve:
        root_id = root["id"]
        info = resolution_info.get(root_id, {})
        root_body = root.get("body", "")
        root_path = root.get("path")
        root_line = root.get("line") or root.get("original_line")

        finding = _parse_finding_from_comment(root_body, root_path, root_line)
        if finding:
            try:
                from .decision_log import log_decision
                # Infer decision type from the reply text
                reason = info.get("reason", "")
                reason_lower = reason.lower()
                if (
                    "false positive" in reason_lower
                    or "false_positive" in reason_lower
                    or "overruled" in reason_lower
                    or "over ruled" in reason_lower
                    or "overridden" in reason_lower
                ):
                    decision_type = "false_positive"
                elif "wontfix" in reason_lower or "won't fix" in reason_lower or "acceptable" in reason_lower:
                    decision_type = "wontfix"
                else:
                    decision_type = "accepted"

                log_decision(
                    repo=repo_key,
                    finding=finding,
                    decision=decision_type,
                    reason=reason,
                    decided_by=info.get("decided_by", ""),
                    pr_url=pr_url,
                )
                log.info("Logged decision for %s:%s [%s] -> %s",
                         finding.file, finding.line, finding.category, decision_type)
            except Exception as e:
                log.warning("Failed to log decision: %s", e)

    # Fetch threads and match by (path, line, session_id) for robust identification
    threads = fetch_review_threads(owner, repo, pr_number, token)

    # Build a lookup key for each root that needs resolution
    def _match_key(path: str | None, line: int | None, body: str) -> tuple[str | None, int | None, str]:
        """Extract (path, line, session_id) as a matching key."""
        match = VIGIL_SESSION_PATTERN.search(body)
        sid = match.group(0) if match else ""
        return (path, line, sid)

    root_keys: set[tuple] = set()
    for root in roots_to_resolve:
        key = _match_key(root.get("path"), root.get("line") or root.get("original_line"), root.get("body", ""))
        root_keys.add(key)

    # Match threads to roots by the same key
    to_resolve: list[str] = []
    for t in threads:
        if t["isResolved"]:
            continue
        if not VIGIL_SESSION_PATTERN.search(t.get("body", "")):
            continue
        key = _match_key(t.get("path"), t.get("line"), t.get("body", ""))
        if key in root_keys:
            to_resolve.append(t["id"])

    if not to_resolve:
        return 0

    resolved = resolve_threads_batch(to_resolve, token)
    for tid in resolved:
        log.info("Resolved dismissed thread %s", tid)
    return len(resolved)


def fetch_all_vigil_comments(
    owner: str, repo: str, pr_number: int, token: str,
) -> list[dict]:
    """Fetch all Vigil comments including from resolved threads.

    Combines REST API comments (active) with GraphQL thread comments (resolved)
    to provide comprehensive dedup coverage. Prevents Vigil from reposting
    findings when threads are resolved without the underlying code changing.
    """
    # Active comments via REST
    active = fetch_vigil_comments(owner, repo, pr_number, token)
    active_bodies = {c.get("body", "") for c in active}

    # Resolved thread comments via GraphQL
    threads = fetch_review_threads(owner, repo, pr_number, token)
    resolved_comments: list[dict] = []
    for t in threads:
        if not t["isResolved"]:
            continue
        body = t.get("body", "")
        if not VIGIL_SESSION_PATTERN.search(body):
            continue
        if body in active_bodies:
            continue  # already included from REST
        resolved_comments.append({
            "path": t.get("path"),
            "line": t.get("line"),
            "body": body,
        })

    return active + resolved_comments


def _extract_message_content(body: str) -> str:
    """Strip formatting to get core message text for dedup comparison.

    Delegates to utils.extract_message_content. This alias is kept for
    backward compatibility with existing imports.
    """
    return extract_message_content(body)


def _content_fingerprint(text: str) -> str:
    """Generate a short hash fingerprint of normalized text for fast pre-filtering.

    Delegates to utils.content_fingerprint. This alias is kept for
    backward compatibility with existing imports.
    """
    return content_fingerprint(text)


def is_duplicate_finding(
    new_comment: dict,
    existing_comments: list[dict],
    similarity_threshold: float = 0.85,
) -> bool:
    """Check if a new inline comment duplicates an existing Vigil comment.

    Structured comments first match by a stable semantic finding key that is
    independent of category, line, and presentation anchor. Legacy comments
    retain the old path/line/text fallback.
    """
    new_path = new_comment.get("path", "")
    new_line = new_comment.get("line", 0)
    new_text = _extract_message_content(new_comment.get("body", ""))

    if not new_text:
        return False

    from .context_manager import extract_finding_from_comment, stable_finding_key

    new_finding = extract_finding_from_comment(
        new_comment.get("body", ""), new_path, new_line,
    )
    new_key = stable_finding_key(new_finding) if new_finding else ""

    for existing in existing_comments:
        existing_line = existing.get("line") or existing.get("original_line") or 0
        existing_finding = extract_finding_from_comment(
            existing.get("body", ""), existing.get("path"), existing_line,
        )
        if new_key and existing_finding and new_key == stable_finding_key(existing_finding):
            return True
        if existing.get("path") != new_path:
            continue
        if abs(existing_line - new_line) > 3:
            continue
        existing_text = _extract_message_content(existing.get("body", ""))
        if not existing_text:
            continue
        # Exact match via fingerprint (fast path)
        if _content_fingerprint(new_text) == _content_fingerprint(existing_text):
            return True
        # Fuzzy match via SequenceMatcher (slow path)
        ratio = difflib.SequenceMatcher(None, new_text, existing_text).ratio()
        if ratio >= similarity_threshold:
            return True
    return False


def deduplicate_comments(
    new_comments: list[dict],
    existing_comments: list[dict],
    threshold: float = 0.85,
) -> list[dict]:
    """Filter out new comments that are duplicates of existing Vigil comments.

    Pre-indexes existing comments by file path for O(N+M) performance.

    Args:
        new_comments: New comments to filter
        existing_comments: Existing comments from previous rounds
        threshold: Similarity threshold (default 0.85) for fuzzy matching

    Returns:
        Filtered list of new comments, excluding duplicates
    """
    if not existing_comments:
        return list(new_comments)

    result = []
    for c in new_comments:
        if not is_duplicate_finding(c, existing_comments, threshold):
            result.append(c)
    return result


