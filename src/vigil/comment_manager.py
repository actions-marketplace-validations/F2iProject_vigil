"""Manage Vigil review comment lifecycle: fetch, resolve, deduplicate."""

import difflib
import logging
import re

import httpx

log = logging.getLogger(__name__)

VIGIL_SIGNATURE = "Reviewed by [Vigil]"
VIGIL_SESSION_PATTERN = re.compile(r"VGL-[0-9a-f]{6}")

# Pattern to strip formatting for dedup comparison
_STRIP_PATTERNS = [
    re.compile(r"[\U0001f534\U0001f7e0\U0001f7e1\U0001f535]"),  # severity emoji
    re.compile(r"\*\*\[(?:CRITICAL|HIGH|MEDIUM|LOW)\]\*\*"),  # severity tags
    re.compile(r"\[[\w\s]+\]"),  # category tags
    re.compile(r"\*\*[\w\s]+\*\*"),  # bold persona names
    re.compile(r"`VGL-[0-9a-f]{6}`"),  # session IDs
    re.compile(r"\*\*Suggestion:\*\*.*", re.DOTALL),  # suggestion blocks
    re.compile(r"\*Originally for.*?\*\n*"),  # relocation notes
]


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }


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


def get_last_reviewed_sha(owner: str, repo: str, pr_number: int, token: str) -> str | None:
    """Find the most recent Vigil review and return its commit SHA."""
    reviews = fetch_vigil_reviews(owner, repo, pr_number, token)
    if not reviews:
        return None
    latest = sorted(reviews, key=lambda r: r.get("submitted_at", ""), reverse=True)[0]
    return latest.get("commit_id")


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

    Returns list of dicts: {id, isResolved, path, line, body}
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
              comments(first: 1) {
                nodes {
                  body
                  path
                  line
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
            first_comment = (node.get("comments", {}).get("nodes") or [{}])[0]
            threads.append({
                "id": node["id"],
                "isResolved": node["isResolved"],
                "path": first_comment.get("path"),
                "line": first_comment.get("line"),
                "body": first_comment.get("body", ""),
            })
        page_info = thread_data.get("pageInfo", {})
        if page_info.get("hasNextPage"):
            cursor = page_info["endCursor"]
        else:
            break
    return threads


def resolve_thread_by_node_id(node_id: str, token: str) -> bool:
    """Resolve a review thread using the GraphQL resolveReviewThread mutation."""
    mutation = """
    mutation($threadId: ID!) {
      resolveReviewThread(input: {threadId: $threadId}) {
        thread { isResolved }
      }
    }
    """
    try:
        data = _graphql(mutation, {"threadId": node_id}, token)
        resolved = (
            data.get("data", {})
            .get("resolveReviewThread", {})
            .get("thread", {})
            .get("isResolved", False)
        )
        return resolved
    except Exception as e:
        log.warning("Failed to resolve thread %s: %s", node_id, e)
        return False


def resolve_addressed_threads(
    owner: str, repo: str, pr_number: int, token: str,
    changed_files: dict[str, set[int]],
) -> int:
    """Resolve Vigil comment threads where the underlying code has changed.

    A thread is considered 'addressed' if:
      - It's a Vigil thread (body contains VGL session ID)
      - It's not already resolved
      - Its file is in changed_files AND its line is in the changed lines set

    Returns count of resolved threads.
    """
    threads = fetch_review_threads(owner, repo, pr_number, token)
    resolved_count = 0
    for t in threads:
        if t["isResolved"]:
            continue
        if not VIGIL_SESSION_PATTERN.search(t.get("body", "")):
            continue
        path = t.get("path")
        line = t.get("line")
        if path and path in changed_files:
            # If specific line changed, or file was broadly modified
            file_lines = changed_files[path]
            if line is None or line in file_lines:
                if resolve_thread_by_node_id(t["id"], token):
                    resolved_count += 1
                    log.info("Resolved addressed thread at %s:%s", path, line)
    return resolved_count


def resolve_dismissed_threads(
    owner: str, repo: str, pr_number: int, token: str,
) -> int:
    """Resolve Vigil threads that received a 'resolved' reply.

    Scans all PR review comments. For each Vigil inline comment thread,
    checks if any reply contains 'resolved' (case-insensitive).
    If so, resolves the thread via GraphQL.

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

    # Check which Vigil threads have "resolved" replies
    threads_to_resolve: set[str] = set()  # node_ids
    for root_id in vigil_roots:
        replies = replies_to.get(root_id, [])
        for reply in replies:
            body = reply.get("body", "").strip().lower()
            if body == "resolved" or body == "resolve":
                root = by_id[root_id]
                node_id = root.get("node_id")
                if node_id:
                    threads_to_resolve.add(node_id)
                break

    # Need thread IDs (not comment node IDs) for resolution
    # Fetch threads and match by comment body/path
    if not threads_to_resolve:
        return 0

    threads = fetch_review_threads(owner, repo, pr_number, token)
    resolved_count = 0
    for t in threads:
        if t["isResolved"]:
            continue
        if not VIGIL_SESSION_PATTERN.search(t.get("body", "")):
            continue
        # Match thread to a root comment that needs resolution
        # We match by body content since thread ID != comment node_id
        for root_id in vigil_roots:
            root = by_id[root_id]
            if root.get("node_id") in threads_to_resolve:
                # Match by path + body prefix
                if (
                    t.get("path") == root.get("path")
                    and t.get("body", "")[:100] == root.get("body", "")[:100]
                ):
                    if resolve_thread_by_node_id(t["id"], token):
                        resolved_count += 1
                        log.info("Resolved dismissed thread at %s:%s", t.get("path"), t.get("line"))
                    break

    return resolved_count


def _extract_message_content(body: str) -> str:
    """Strip formatting to get core message text for dedup comparison."""
    text = body
    for pattern in _STRIP_PATTERNS:
        text = pattern.sub("", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def is_duplicate_finding(
    new_comment: dict,
    existing_comments: list[dict],
    similarity_threshold: float = 0.85,
) -> bool:
    """Check if a new inline comment duplicates an existing Vigil comment.

    Match criteria (ALL must be true):
    1. Same file path
    2. Same line (or within 3 lines)
    3. Message similarity >= threshold
    """
    new_path = new_comment.get("path", "")
    new_line = new_comment.get("line", 0)
    new_text = _extract_message_content(new_comment.get("body", ""))

    if not new_text:
        return False

    for existing in existing_comments:
        if existing.get("path") != new_path:
            continue
        existing_line = existing.get("line") or existing.get("original_line") or 0
        if abs(existing_line - new_line) > 3:
            continue
        existing_text = _extract_message_content(existing.get("body", ""))
        if not existing_text:
            continue
        ratio = difflib.SequenceMatcher(None, new_text, existing_text).ratio()
        if ratio >= similarity_threshold:
            return True
    return False


def deduplicate_comments(
    new_comments: list[dict],
    existing_comments: list[dict],
    threshold: float = 0.85,
) -> list[dict]:
    """Filter out new comments that are duplicates of existing Vigil comments."""
    return [
        c for c in new_comments
        if not is_duplicate_finding(c, existing_comments, threshold)
    ]
