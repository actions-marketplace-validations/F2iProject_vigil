"""FastAPI webhook server for receiving GitHub webhook events.

Starts via `vigil serve` and listens for:
  - pull_request (opened, reopened, ready_for_review)
  - issue_comment (containing `/vigil review` or resolution replies)
  - ping (GitHub health check)

Configuration:
    WEBHOOK_SECRET  — shared secret for HMAC-SHA256 signature verification
    GITHUB_TOKEN    — required for GitHub API access
"""

import hashlib
import hmac
import logging
import os
import threading
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature or not secret:
        return False
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def _extract_pr_url(event: str, payload: dict) -> Optional[str]:
    """Extract the PR URL from a webhook payload."""
    if event == "pull_request":
        pr = payload.get("pull_request", {})
        return pr.get("html_url")
    elif event == "issue_comment":
        issue = payload.get("issue", {})
        # issue_comment events on PRs have a pull_request key
        if issue.get("pull_request"):
            return issue["html_url"].replace("/issues/", "/pull/")
    return None


def _should_review(event: str, payload: dict) -> bool:
    """Decide whether a webhook event should trigger a Vigil review."""
    if event == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "reopened", "ready_for_review"):
            return False
        pr = payload.get("pull_request", {})
        if pr.get("draft"):
            return False
        user = pr.get("user", {})
        if user.get("type") == "Bot":
            return False
        return True
    elif event == "issue_comment":
        action = payload.get("action", "")
        if action != "created":
            return False
        body = payload.get("comment", {}).get("body", "").strip().lower()
        if "/vigil review" not in body:
            return False
        # Must be on a PR (issue_comment fires on both issues and PRs)
        issue = payload.get("issue", {})
        if not issue.get("pull_request"):
            return False
        return True
    return False


def _should_dismiss(event: str, payload: dict) -> bool:
    """Decide whether a webhook event should trigger dismiss-resolved."""
    if event != "issue_comment":
        return False
    if payload.get("action") != "created":
        return False
    issue = payload.get("issue", {})
    if not issue.get("pull_request"):
        return False
    body = payload.get("comment", {}).get("body", "").strip()
    # Import here to avoid circular dependency
    from .comment_manager import _is_resolution_reply
    return _is_resolution_reply(body)


def _run_review(pr_url: str, model: str, lead_model: Optional[str], profile: str):
    """Run a Vigil review in a background thread."""
    import subprocess
    cmd = ["vigil", "review", pr_url, "--model", model, "--profile", profile, "--post"]
    if lead_model:
        cmd.extend(["--lead-model", lead_model])
    log.info("Starting review: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            log.error("Review failed (exit %d): %s", result.returncode, result.stderr)
        else:
            log.info("Review completed for %s", pr_url)
    except Exception as e:
        log.error("Review error: %s", e)


def _run_dismiss(pr_url: str):
    """Run dismiss-resolved in a background thread."""
    import subprocess
    cmd = ["vigil", "dismiss-resolved", pr_url]
    log.info("Starting dismiss-resolved: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            log.error("Dismiss failed (exit %d): %s", result.returncode, result.stderr)
        else:
            log.info("Dismiss-resolved completed for %s", pr_url)
    except Exception as e:
        log.error("Dismiss error: %s", e)


def create_app(
    webhook_secret: Optional[str] = None,
    model: str = "gemini/gemini-2.5-flash",
    lead_model: Optional[str] = None,
    profile: str = "default",
) -> FastAPI:
    """Create and configure the FastAPI webhook application."""
    app = FastAPI(
        title="Vigil Webhook Server",
        description="Receives GitHub webhook events and triggers Vigil reviews.",
        version="0.1.0",
    )

    secret = webhook_secret or os.environ.get("WEBHOOK_SECRET", "")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "vigil-webhook"}

    @app.post("/webhook")
    async def webhook(request: Request):
        body = await request.body()
        event = request.headers.get("X-GitHub-Event", "")

        # Verify signature if secret is configured
        if secret:
            signature = request.headers.get("X-Hub-Signature-256", "")
            if not _verify_signature(body, signature, secret):
                return JSONResponse({"error": "Invalid signature"}, status_code=401)

        # Parse payload
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        # Handle ping
        if event == "ping":
            return {"message": "pong", "zen": payload.get("zen", "")}

        # Extract PR URL
        pr_url = _extract_pr_url(event, payload)
        if not pr_url:
            return {"message": "No PR URL found", "action": "skip"}

        # Check if we should review
        if _should_review(event, payload):
            thread = threading.Thread(
                target=_run_review,
                args=(pr_url, model, lead_model, profile),
                daemon=True,
            )
            thread.start()
            return {"message": "Review triggered", "pr": pr_url}

        # Check if we should dismiss resolved threads
        if _should_dismiss(event, payload):
            thread = threading.Thread(
                target=_run_dismiss,
                args=(pr_url,),
                daemon=True,
            )
            thread.start()
            return {"message": "Dismiss-resolved triggered", "pr": pr_url}

        return {"message": "Event received", "action": "skip"}

    return app
