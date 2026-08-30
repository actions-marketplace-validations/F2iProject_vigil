"""GitHub API integration for fetching PR data."""

import re
from urllib.parse import quote

import httpx


def parse_pr_url(url: str) -> tuple[str, str, int]:
    """Extract owner, repo, pr_number from a GitHub PR URL."""
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)", url)
    if not match:
        raise ValueError(f"Invalid PR URL: {url}")
    return match.group(1), match.group(2), int(match.group(3))


def get_pr_data(owner: str, repo: str, pr_number: int, token: str) -> dict:
    """Fetch PR metadata and diff from GitHub API."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    base_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"

    with httpx.Client() as client:
        # PR metadata
        meta_resp = client.get(base_url, headers=headers)
        meta_resp.raise_for_status()
        meta = meta_resp.json()

        # PR diff
        diff_headers = {**headers, "Accept": "application/vnd.github.v3.diff"}
        diff_resp = client.get(base_url, headers=diff_headers)
        diff_resp.raise_for_status()

    return {
        "title": meta["title"],
        "body": meta.get("body") or "",
        "author": meta["user"]["login"],
        "base": meta["base"]["ref"],
        "head": meta["head"]["ref"],
        "head_sha": meta["head"]["sha"],
        "diff": diff_resp.text,
        "url": meta["html_url"],
        "commits": meta["commits"],
        "changed_files": meta["changed_files"],
        "additions": meta["additions"],
        "deletions": meta["deletions"],
    }


def get_diff_between_commits(
    owner: str, repo: str, base_sha: str, head_sha: str, token: str,
) -> str:
    """Fetch the diff between two commits."""
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}"
    with httpx.Client() as client:
        resp = client.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.text


def get_changed_files_between_commits(
    owner: str, repo: str, base_sha: str, head_sha: str, token: str,
) -> list[str]:
    """Get list of file paths changed between two commits.

    NOTE: this answers "what differs between these two trees", which is NOT
    the same question as "what was pushed since the last review" once the
    branch has been rebased. ``compare`` silently falls back to the merge
    base for an orphaned-but-still-reachable base SHA, so the answer becomes
    the whole PR rather than the increment, without erroring. Callers that
    depend on the incremental meaning must check ``is_ancestor_commit`` first
    (F2iLLC/vigil#74).
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}"
    with httpx.Client() as client:
        resp = client.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return [f["filename"] for f in data.get("files", [])]


def compare_commits(
    owner: str, repo: str, base_sha: str, head_sha: str, token: str,
) -> dict:
    """Fetch the raw comparison payload between two commits.

    Deliberately separate from ``get_diff_between_commits`` and
    ``get_changed_files_between_commits``: those two project the response down
    to a diff or a file list and throw away ``status`` and
    ``merge_base_commit``, which are the only fields that reveal a rebase.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}"
    with httpx.Client() as client:
        resp = client.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()


def shas_equal(left: str, right: str) -> bool:
    """Compare two commit SHAs, tolerating a legitimately abbreviated one.

    GitHub returns full 40-character SHAs, but a SHA that reached Vigil from
    a workflow input or a comment may be abbreviated. Prefix matching is
    accepted only from 7 characters up, which is git's own minimum for an
    unambiguous short SHA — below that this reports "not equal", which on
    every current caller is the conservative answer.
    """
    a, b = (left or "").strip().lower(), (right or "").strip().lower()
    if not a or not b:
        return False
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    if len(shorter) < 7:
        return False
    return longer.startswith(shorter)


def is_ancestor_commit(
    owner: str, repo: str, ancestor_sha: str, head_sha: str, token: str,
) -> bool:
    """Return True when ``ancestor_sha`` is still reachable from ``head_sha``.

    A force-push does not orphan the old commit in a way ``compare`` reports
    as an error: as long as the SHA is reachable in the repository at all
    (it still is, from the pre-rebase reflog and from GitHub's own record of
    the push), ``compare/{base}...{head}`` answers happily by computing
    against the merge base. The caller then reads a whole-PR file list as if
    it were "changed since the last review". The two fields that give the
    rebase away are ``status`` — ``"diverged"`` when the histories forked —
    and ``merge_base_commit.sha``, which equals ``ancestor_sha`` exactly when
    the old head really is an ancestor of the new one.

    Raises like every other helper here; the fail-open decision belongs to
    the caller, which is the layer that knows what degrading means.
    """
    data = compare_commits(owner, repo, ancestor_sha, head_sha, token)
    status = (data.get("status") or "").strip().lower()
    merge_base = ((data.get("merge_base_commit") or {}).get("sha") or "")
    return status != "diverged" and shas_equal(merge_base, ancestor_sha)


def get_file_content_at_commit(
    owner: str, repo: str, path: str, ref: str, token: str,
) -> str | None:
    """Fetch a file's text as it exists at an exact commit.

    Returns ``None`` — and only — when GitHub answers 404 for that path at
    that ref. Every other failure raises, so a caller can tell "this file is
    genuinely not in the tree" apart from "GitHub would not answer", which is
    the distinction the head-content guard is built on (F2iLLC/vigil#74). A
    404 can still mean "this token cannot see this repository at all", so a
    caller that acts on absence must corroborate it with
    ``commit_is_readable``.

    The raw media type is requested so the response is the file itself rather
    than base64-in-JSON.
    """
    headers = {
        "Accept": "application/vnd.github.v3.raw",
        "Authorization": f"Bearer {token}",
    }
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{quote(path, safe='/')}"
    )
    # Redirects are followed rather than raised on: httpx defaults to
    # `follow_redirects=False`, so a 301 (renamed repository, canonicalized
    # owner) reaches `raise_for_status` as an error and the head-content guard
    # reads it as "unverified" — i.e. one org rename would silently switch the
    # guard off for every finding in the review.
    with httpx.Client(follow_redirects=True) as client:
        resp = client.get(url, headers=headers, params={"ref": ref}, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text


def commit_is_readable(owner: str, repo: str, sha: str, token: str) -> bool:
    """Return True when this token can read ``sha`` in this repository.

    Corroborates a 404 from ``get_file_content_at_commit``: the contents API
    returns the same 404 for "no such path at this ref" and for "no such
    repository, as far as your credentials are concerned", and only the first
    is evidence about the file. Uses the git-database commit endpoint rather
    than ``/commits/{sha}``, which would drag the whole file list back.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/git/commits/{sha}"
    # Follows redirects for the same reason as the contents fetch above: an
    # unfollowed 301 here raises, and this probe raising means every
    # absent-file result in the review is treated as unverified.
    with httpx.Client(follow_redirects=True) as client:
        resp = client.get(url, headers=headers, timeout=30)
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True


def get_check_runs_for_commit(
    owner: str, repo: str, sha: str, token: str,
) -> list[dict]:
    """Fetch check runs attached to exactly ``sha``.

    Callers receive the raw stable fields needed to prove a current build/test
    assertion.  This helper raises on API failure so the validation layer can
    preserve its explicit fail-open/fail-loud contract instead of confusing an
    outage with an empty check set.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}/check-runs"
    with httpx.Client(follow_redirects=True) as client:
        resp = client.get(url, headers=headers, params={"per_page": 100}, timeout=30)
        resp.raise_for_status()
        return list((resp.json() or {}).get("check_runs") or [])
