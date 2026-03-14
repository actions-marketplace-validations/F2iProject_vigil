"""GitHub API integration for fetching PR data."""

import re

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
    """Get list of file paths changed between two commits."""
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
