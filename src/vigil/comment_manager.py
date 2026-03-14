"""Manage Vigil review comment lifecycle: fetch, resolve, deduplicate."""

import difflib
import hashlib
import logging
import re
from collections import defaultdict

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

# Max thread IDs per batch mutation (GitHub GraphQL has a ~500KB payload limit)
_BATCH_SIZE = 50


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
            if line is None or line in file_lines:
                to_resolve.append(t["id"])

    if not to_resolve:
        return 0

    resolved = resolve_threads_batch(to_resolve, token)
    for tid in resolved:
        log.info("Resolved addressed thread %s", tid)
    return len(resolved)


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

    # Check which Vigil root comments have "resolved" replies
    # Track by (path, line, session_id) for robust matching to GraphQL threads
    roots_to_resolve: list[dict] = []  # root comment dicts
    for root_id in vigil_roots:
        replies = replies_to.get(root_id, [])
        for reply in replies:
            body = reply.get("body", "").strip().lower()
            if body == "resolved" or body == "resolve":
                roots_to_resolve.append(by_id[root_id])
                break

    if not roots_to_resolve:
        return 0

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


def _extract_message_content(body: str) -> str:
    """Strip formatting to get core message text for dedup comparison."""
    text = body
    for pattern in _STRIP_PATTERNS:
        text = pattern.sub("", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _content_fingerprint(text: str) -> str:
    """Generate a short hash fingerprint of normalized text for fast pre-filtering."""
    return hashlib.md5(text.encode()).hexdigest()[:12]


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

    Pre-indexes existing comments by file path to avoid O(N*M) full scans.
    """
    if not existing_comments:
        return list(new_comments)

    # Index existing comments by path for O(1) lookup
    by_path: dict[str, list[dict]] = defaultdict(list)
    for c in existing_comments:
        path = c.get("path", "")
        if path:
            by_path[path].append(c)

    result = []
    for c in new_comments:
        path = c.get("path", "")
        candidates = by_path.get(path, [])
        if not candidates or not is_duplicate_finding(c, candidates, threshold):
            result.append(c)
    return result
