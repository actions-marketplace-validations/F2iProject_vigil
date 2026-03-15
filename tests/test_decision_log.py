"""Tests for decision_log: CRUD operations, filtering, fuzzy matching."""

import sqlite3
from pathlib import Path

import pytest

from vigil.decision_log import (
    _get_db,
    clear_decisions,
    filter_known_findings,
    get_decisions,
    is_known_decision,
    log_decision,
    remove_decision,
)
from vigil.models import Finding, Severity


# ---------- Fixtures ----------

@pytest.fixture
def db_path(tmp_path):
    """Return a temporary database path."""
    return tmp_path / "decisions.db"


def _make_finding(
    file="src/app.py",
    line=10,
    sev=Severity.high,
    category="injection",
    message="SQL injection in query builder",
):
    return Finding(file=file, line=line, severity=sev, category=category, message=message)


# ---------- log_decision ----------

class TestLogDecision:

    def test_creates_record(self, db_path):
        finding = _make_finding()
        row_id = log_decision("owner/repo", finding, db_path=db_path)
        assert row_id > 0

    def test_returns_row_id(self, db_path):
        finding = _make_finding()
        row_id = log_decision("owner/repo", finding, db_path=db_path)
        assert isinstance(row_id, int)

    def test_upsert_on_conflict(self, db_path):
        finding = _make_finding()
        id1 = log_decision("owner/repo", finding, reason="first reason", db_path=db_path)
        id2 = log_decision("owner/repo", finding, reason="updated reason", db_path=db_path)
        # Should update, not duplicate
        records = get_decisions("owner/repo", db_path=db_path)
        assert len(records) == 1
        assert records[0]["reason"] == "updated reason"

    def test_stores_all_fields(self, db_path):
        finding = _make_finding()
        log_decision(
            "owner/repo", finding,
            decision="wontfix",
            reason="Acceptable risk during early dev",
            decided_by="testuser",
            pr_url="https://github.com/owner/repo/pull/42",
            db_path=db_path,
        )
        records = get_decisions("owner/repo", db_path=db_path)
        assert len(records) == 1
        r = records[0]
        assert r["repo"] == "owner/repo"
        assert r["file_path"] == "src/app.py"
        assert r["category"] == "injection"
        assert r["decision"] == "wontfix"
        assert r["reason"] == "Acceptable risk during early dev"
        assert r["decided_by"] == "testuser"
        assert r["pr_url"] == "https://github.com/owner/repo/pull/42"
        assert r["created_at"]  # ISO timestamp present

    def test_different_repos_separate(self, db_path):
        finding = _make_finding()
        log_decision("owner/repo1", finding, db_path=db_path)
        log_decision("owner/repo2", finding, db_path=db_path)
        assert len(get_decisions("owner/repo1", db_path=db_path)) == 1
        assert len(get_decisions("owner/repo2", db_path=db_path)) == 1

    def test_different_files_separate(self, db_path):
        f1 = _make_finding(file="a.py")
        f2 = _make_finding(file="b.py")
        log_decision("owner/repo", f1, db_path=db_path)
        log_decision("owner/repo", f2, db_path=db_path)
        assert len(get_decisions("owner/repo", db_path=db_path)) == 2

    def test_different_categories_separate(self, db_path):
        f1 = _make_finding(category="injection")
        f2 = _make_finding(category="xss")
        log_decision("owner/repo", f1, db_path=db_path)
        log_decision("owner/repo", f2, db_path=db_path)
        assert len(get_decisions("owner/repo", db_path=db_path)) == 2


# ---------- is_known_decision ----------

class TestIsKnownDecision:

    def test_exact_match(self, db_path):
        finding = _make_finding()
        log_decision("owner/repo", finding, db_path=db_path)
        result = is_known_decision("owner/repo", finding, db_path=db_path)
        assert result is not None
        assert result["category"] == "injection"

    def test_no_match(self, db_path):
        finding = _make_finding()
        result = is_known_decision("owner/repo", finding, db_path=db_path)
        assert result is None

    def test_different_repo_no_match(self, db_path):
        finding = _make_finding()
        log_decision("owner/repo1", finding, db_path=db_path)
        result = is_known_decision("owner/repo2", finding, db_path=db_path)
        assert result is None

    def test_fuzzy_match(self, db_path):
        """A slightly different message should still match via fuzzy matching."""
        original = _make_finding(message="SQL injection vulnerability in the login query, user input is not sanitized before use")
        log_decision("owner/repo", original, db_path=db_path)

        similar = _make_finding(message="SQL injection vulnerability in the login query, user input is not validated before use")
        result = is_known_decision("owner/repo", similar, db_path=db_path)
        assert result is not None

    def test_very_different_message_no_match(self, db_path):
        original = _make_finding(message="SQL injection vulnerability in the login query builder")
        log_decision("owner/repo", original, db_path=db_path)

        different = _make_finding(message="Buffer overflow in the image parser module")
        result = is_known_decision("owner/repo", different, db_path=db_path)
        assert result is None

    def test_different_file_no_match(self, db_path):
        original = _make_finding(file="auth.py")
        log_decision("owner/repo", original, db_path=db_path)

        same_msg_diff_file = _make_finding(file="other.py")
        result = is_known_decision("owner/repo", same_msg_diff_file, db_path=db_path)
        assert result is None

    def test_returns_decision_details(self, db_path):
        finding = _make_finding()
        log_decision(
            "owner/repo", finding,
            decision="false_positive",
            reason="This is sanitized upstream",
            db_path=db_path,
        )
        result = is_known_decision("owner/repo", finding, db_path=db_path)
        assert result is not None
        assert result["decision"] == "false_positive"
        assert result["reason"] == "This is sanitized upstream"


# ---------- filter_known_findings ----------

class TestFilterKnownFindings:

    def test_filters_known_findings(self, db_path):
        f1 = _make_finding(file="a.py", message="Known issue A")
        f2 = _make_finding(file="b.py", message="New issue B")
        log_decision("owner/repo", f1, db_path=db_path)

        result = filter_known_findings("owner/repo", [f1, f2], db_path=db_path)
        assert len(result) == 1
        assert result[0].file == "b.py"

    def test_empty_list_returns_empty(self, db_path):
        result = filter_known_findings("owner/repo", [], db_path=db_path)
        assert result == []

    def test_no_known_returns_all(self, db_path):
        findings = [_make_finding(file="a.py"), _make_finding(file="b.py")]
        result = filter_known_findings("owner/repo", findings, db_path=db_path)
        assert len(result) == 2

    def test_all_known_returns_empty(self, db_path):
        f1 = _make_finding(file="a.py", message="Issue A")
        f2 = _make_finding(file="b.py", message="Issue B")
        log_decision("owner/repo", f1, db_path=db_path)
        log_decision("owner/repo", f2, db_path=db_path)

        result = filter_known_findings("owner/repo", [f1, f2], db_path=db_path)
        assert len(result) == 0


# ---------- get_decisions ----------

class TestGetDecisions:

    def test_lists_all_for_repo(self, db_path):
        for i in range(5):
            log_decision("owner/repo", _make_finding(file=f"file_{i}.py"), db_path=db_path)
        records = get_decisions("owner/repo", db_path=db_path)
        assert len(records) == 5

    def test_filter_by_file(self, db_path):
        log_decision("owner/repo", _make_finding(file="a.py"), db_path=db_path)
        log_decision("owner/repo", _make_finding(file="b.py"), db_path=db_path)
        records = get_decisions("owner/repo", file_path="a.py", db_path=db_path)
        assert len(records) == 1
        assert records[0]["file_path"] == "a.py"

    def test_filter_by_category(self, db_path):
        log_decision("owner/repo", _make_finding(category="injection"), db_path=db_path)
        log_decision("owner/repo", _make_finding(file="b.py", category="xss"), db_path=db_path)
        records = get_decisions("owner/repo", category="xss", db_path=db_path)
        assert len(records) == 1
        assert records[0]["category"] == "xss"

    def test_empty_repo_returns_empty(self, db_path):
        records = get_decisions("owner/repo", db_path=db_path)
        assert records == []

    def test_ordered_by_date_desc(self, db_path):
        log_decision("owner/repo", _make_finding(file="a.py"), db_path=db_path)
        log_decision("owner/repo", _make_finding(file="b.py"), db_path=db_path)
        records = get_decisions("owner/repo", db_path=db_path)
        # Most recent first
        assert records[0]["file_path"] == "b.py"


# ---------- remove_decision ----------

class TestRemoveDecision:

    def test_removes_existing(self, db_path):
        finding = _make_finding()
        row_id = log_decision("owner/repo", finding, db_path=db_path)
        assert remove_decision("owner/repo", row_id, db_path=db_path) is True
        assert len(get_decisions("owner/repo", db_path=db_path)) == 0

    def test_nonexistent_returns_false(self, db_path):
        assert remove_decision("owner/repo", 999, db_path=db_path) is False

    def test_wrong_repo_returns_false(self, db_path):
        finding = _make_finding()
        row_id = log_decision("owner/repo1", finding, db_path=db_path)
        assert remove_decision("owner/repo2", row_id, db_path=db_path) is False

    def test_finding_re_flagged_after_removal(self, db_path):
        """After removing a decision, the finding should be flaggable again."""
        finding = _make_finding()
        row_id = log_decision("owner/repo", finding, db_path=db_path)
        assert is_known_decision("owner/repo", finding, db_path=db_path) is not None

        remove_decision("owner/repo", row_id, db_path=db_path)
        assert is_known_decision("owner/repo", finding, db_path=db_path) is None


# ---------- clear_decisions ----------

class TestClearDecisions:

    def test_clears_all_for_repo(self, db_path):
        for i in range(5):
            log_decision("owner/repo", _make_finding(file=f"file_{i}.py"), db_path=db_path)
        count = clear_decisions("owner/repo", db_path=db_path)
        assert count == 5
        assert len(get_decisions("owner/repo", db_path=db_path)) == 0

    def test_clears_by_file(self, db_path):
        log_decision("owner/repo", _make_finding(file="a.py"), db_path=db_path)
        log_decision("owner/repo", _make_finding(file="b.py"), db_path=db_path)
        count = clear_decisions("owner/repo", file_path="a.py", db_path=db_path)
        assert count == 1
        remaining = get_decisions("owner/repo", db_path=db_path)
        assert len(remaining) == 1
        assert remaining[0]["file_path"] == "b.py"

    def test_clears_by_category(self, db_path):
        log_decision("owner/repo", _make_finding(category="injection"), db_path=db_path)
        log_decision("owner/repo", _make_finding(file="b.py", category="xss"), db_path=db_path)
        count = clear_decisions("owner/repo", category="injection", db_path=db_path)
        assert count == 1

    def test_does_not_affect_other_repos(self, db_path):
        log_decision("owner/repo1", _make_finding(), db_path=db_path)
        log_decision("owner/repo2", _make_finding(), db_path=db_path)
        clear_decisions("owner/repo1", db_path=db_path)
        assert len(get_decisions("owner/repo2", db_path=db_path)) == 1

    def test_returns_zero_when_empty(self, db_path):
        count = clear_decisions("owner/repo", db_path=db_path)
        assert count == 0


# ---------- Database initialization ----------

class TestDbInit:

    def test_creates_db_file(self, tmp_path):
        db_path = tmp_path / "subdir" / "decisions.db"
        _get_db(db_path)
        assert db_path.exists()

    def test_creates_tables(self, tmp_path):
        db_path = tmp_path / "decisions.db"
        conn = _get_db(db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        assert "decisions" in tables

    def test_idempotent_schema(self, tmp_path):
        db_path = tmp_path / "decisions.db"
        # Open twice — should not error
        conn1 = _get_db(db_path)
        conn1.close()
        conn2 = _get_db(db_path)
        conn2.close()
