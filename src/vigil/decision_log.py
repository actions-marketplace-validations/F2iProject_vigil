"""Decision log — remembers acknowledged findings so Vigil doesn't re-flag them.

Stores decisions in SQLite at ~/.vigil/decisions.db. When a user resolves or
dismisses a Vigil comment, the finding pattern is logged with a reason. On
future reviews, findings that match a logged decision are suppressed.

Users can browse, filter, and remove decisions via `vigil decisions`.
"""

import difflib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .comment_manager import _content_fingerprint, _extract_message_content
from .models import Finding

_DEFAULT_DB_DIR = Path.home() / ".vigil"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "decisions.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY,
    repo TEXT NOT NULL,
    file_path TEXT NOT NULL,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    message_preview TEXT,
    reason TEXT DEFAULT '',
    decision TEXT NOT NULL,
    decided_by TEXT DEFAULT '',
    pr_url TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(repo, file_path, category, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_decisions_repo ON decisions(repo);
CREATE INDEX IF NOT EXISTS idx_decisions_lookup ON decisions(repo, file_path, category);
"""

_SIMILARITY_THRESHOLD = 0.85


def _get_db(db_path: Path | None = None) -> sqlite3.Connection:
    """Open (or create) the decisions database."""
    path = db_path or _DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def _finding_fingerprint(finding: Finding) -> str:
    """Generate a fingerprint for a finding's message content."""
    text = _extract_message_content(finding.message)
    return _content_fingerprint(text)


def log_decision(
    repo: str,
    finding: Finding,
    decision: str = "accepted",
    reason: str = "",
    decided_by: str = "",
    pr_url: str = "",
    db_path: Path | None = None,
) -> int:
    """Record a decision about a finding pattern.

    Args:
        repo: Repository in "owner/repo" format.
        finding: The finding being decided on.
        decision: One of "accepted", "wontfix", "false_positive".
        reason: Why it was dismissed (user's reply text).
        decided_by: GitHub login of who resolved it.
        pr_url: PR where the decision was made.

    Returns the decision row ID.
    """
    fp = _finding_fingerprint(finding)
    preview = finding.message[:120]
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_db(db_path)
    try:
        cursor = conn.execute(
            """INSERT INTO decisions
               (repo, file_path, category, fingerprint, message_preview,
                reason, decision, decided_by, pr_url, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(repo, file_path, category, fingerprint)
               DO UPDATE SET
                 reason = excluded.reason,
                 decision = excluded.decision,
                 decided_by = excluded.decided_by,
                 pr_url = excluded.pr_url,
                 created_at = excluded.created_at
            """,
            (repo, finding.file, finding.category, fp, preview,
             reason, decision, decided_by, pr_url, now),
        )
        conn.commit()
        return cursor.lastrowid or 0
    finally:
        conn.close()


def is_known_decision(
    repo: str,
    finding: Finding,
    db_path: Path | None = None,
) -> dict | None:
    """Check if a finding matches a logged decision.

    Looks up by (repo, file_path, category), then fuzzy-matches the message.
    Returns the decision record as a dict, or None if no match.
    """
    conn = _get_db(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM decisions
               WHERE repo = ? AND file_path = ? AND category = ?""",
            (repo, finding.file, finding.category),
        ).fetchall()

        if not rows:
            return None

        # Check fingerprint first (fast path)
        fp = _finding_fingerprint(finding)
        for row in rows:
            if row["fingerprint"] == fp:
                return dict(row)

        # Fuzzy match (slow path)
        finding_text = _extract_message_content(finding.message)
        for row in rows:
            existing_text = _extract_message_content(row["message_preview"])
            if not existing_text:
                continue
            ratio = difflib.SequenceMatcher(None, finding_text, existing_text).ratio()
            if ratio >= _SIMILARITY_THRESHOLD:
                return dict(row)

        return None
    finally:
        conn.close()


def filter_known_findings(
    repo: str,
    findings: list[Finding],
    db_path: Path | None = None,
) -> list[Finding]:
    """Filter out findings that match logged decisions.

    Returns only findings that have no matching decision record.
    """
    if not findings:
        return findings
    return [f for f in findings if is_known_decision(repo, f, db_path) is None]


def get_decisions(
    repo: str,
    file_path: str | None = None,
    category: str | None = None,
    db_path: Path | None = None,
) -> list[dict]:
    """Query logged decisions for a repository.

    Args:
        repo: Repository in "owner/repo" format.
        file_path: Optional filter by file path.
        category: Optional filter by category.

    Returns list of decision records as dicts.
    """
    conn = _get_db(db_path)
    try:
        query = "SELECT * FROM decisions WHERE repo = ?"
        params: list = [repo]

        if file_path:
            query += " AND file_path = ?"
            params.append(file_path)
        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def remove_decision(
    repo: str,
    decision_id: int,
    db_path: Path | None = None,
) -> bool:
    """Remove a specific decision by ID. Returns True if deleted."""
    conn = _get_db(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM decisions WHERE id = ? AND repo = ?",
            (decision_id, repo),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def clear_decisions(
    repo: str,
    file_path: str | None = None,
    category: str | None = None,
    db_path: Path | None = None,
) -> int:
    """Bulk clear decisions. Returns count of deleted records."""
    conn = _get_db(db_path)
    try:
        query = "DELETE FROM decisions WHERE repo = ?"
        params: list = [repo]

        if file_path:
            query += " AND file_path = ?"
            params.append(file_path)
        if category:
            query += " AND category = ?"
            params.append(category)

        cursor = conn.execute(query, params)
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()
