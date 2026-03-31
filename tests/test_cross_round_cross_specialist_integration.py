"""Integration tests for cross-round and cross-specialist deduplication pipelines."""

import pytest

from vigil.context_manager import (
    extract_finding_from_comment,
    fingerprint_finding,
    filter_cross_round_duplicates,
)
from vigil.cross_specialist_dedup import (
    VerdictInfo,
    format_merged_finding_comment,
    merge_specialist_findings,
    annotate_findings_with_specialist_context,
)
from vigil.models import Finding, PersonaVerdict, ReviewResult, Severity
from vigil.reviewer import review_diff
from vigil.personas import Persona, ReviewProfile


class TestCrossSpecialistMergeIntegration:
    """Test cross-specialist dedup flow through reviewer."""

    def test_merged_findings_in_review_result(self):
        """Merged findings should appear in ReviewResult.lead_findings."""
        # Create two specialists finding the same issue
        f_sql_1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )
        f_sql_2 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        v1 = PersonaVerdict(
            persona="Security",
            session_id="VGL-111111",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f_sql_1],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Logic",
            session_id="VGL-222222",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f_sql_2],
            observations=[],
        )

        # Run dedup directly
        deduped, merged_info = merge_specialist_findings([v1, v2])

        # Verify results
        assert len(deduped) == 1, "Should merge into 1 finding"
        assert len(merged_info) == 1, "Should have 1 merged group"
        assert merged_info[0].count == 2, "Both specialists should be recorded"
        assert set(merged_info[0].specialists) == {"Security", "Logic"}

    def test_partial_merge_with_unique_findings(self):
        """When some findings merge and some are unique, output should reflect both."""
        # Two specialists flag the same SQL issue
        sql_f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )
        sql_f2 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )

        # One specialist also flags a different issue
        xss_f = Finding(
            file="src/api.py",
            line=10,
            severity=Severity.medium,
            category="XSS",
            message="User input not escaped",
        )

        v1 = PersonaVerdict(
            persona="Security",
            session_id="VGL-111111",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[sql_f1],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Logic",
            session_id="VGL-222222",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[sql_f2, xss_f],
            observations=[],
        )

        deduped, merged_info = merge_specialist_findings([v1, v2])

        # Should output 2 findings: 1 merged SQL + 1 unique XSS
        assert len(deduped) == 2, "Should have 2 findings (1 merged + 1 unique)"
        assert len(merged_info) == 1, "Should have 1 merged group"

        # Verify the merged finding is present
        merged_finding = merged_info[0].finding
        assert merged_finding.file == "src/auth.py"
        assert merged_finding.category == "SQL Injection"

        # Verify the unique finding is in deduped
        unique_finding = next(
            (f for f in deduped if f.category == "XSS"), None
        )
        assert unique_finding is not None
        assert unique_finding.message == "User input not escaped"


class TestCrossRoundFilteringIntegration:
    """Test cross-round dedup flow."""

    def test_filter_cross_round_duplicates_basic(self):
        """New findings matching existing comments should be filtered out."""
        # Create a new finding
        new_finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        # Simulate an existing comment from a previous round
        existing_comment = {
            "path": "src/auth.py",
            "line": 42,
            "body": (
                "🟠 **[HIGH]** [SQL Injection]\n\n"
                "Dangerous SQL concatenation\n\n"
                "**Suggestion:** Use parameterized queries"
            ),
        }

        # Filter should remove the new finding
        result = filter_cross_round_duplicates([new_finding], [existing_comment])
        assert len(result) == 0, "Should filter out cross-round duplicate"

    def test_filter_cross_round_line_shift_tolerance(self):
        """Cross-round filter should allow line number shifts (within context)."""
        # New finding at line 42
        new_finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        # Existing comment at line 40 (close by, in context range)
        existing_comment = {
            "path": "src/auth.py",
            "line": 40,
            "body": (
                "🟠 **[HIGH]** [SQL Injection]\n\n"
                "Dangerous SQL concatenation"
            ),
        }

        # Filter should still remove it (line shift within tolerance)
        result = filter_cross_round_duplicates([new_finding], [existing_comment])
        assert len(result) == 0, "Should filter within line shift tolerance"

    def test_filter_cross_round_different_file_not_filtered(self):
        """Different file should not be filtered even with same message."""
        new_finding = Finding(
            file="src/api.py",
            line=10,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        existing_comment = {
            "path": "src/auth.py",  # Different file
            "line": 42,
            "body": (
                "🟠 **[HIGH]** [SQL Injection]\n\n"
                "Dangerous SQL concatenation"
            ),
        }

        result = filter_cross_round_duplicates([new_finding], [existing_comment])
        assert len(result) == 1, "Different file should not be filtered"

    def test_filter_cross_round_multiple_findings(self):
        """Mixed duplicates and unique findings should be handled correctly."""
        # Duplicate finding
        dup_finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        # Unique finding
        unique_finding = Finding(
            file="src/api.py",
            line=50,
            severity=Severity.medium,
            category="XSS",
            message="User input not escaped",
        )

        existing_comments = [
            {
                "path": "src/auth.py",
                "line": 42,
                "body": (
                    "🟠 **[HIGH]** [SQL Injection]\n\n"
                    "Dangerous SQL concatenation"
                ),
            }
        ]

        result = filter_cross_round_duplicates(
            [dup_finding, unique_finding], existing_comments
        )
        assert len(result) == 1, "Should filter 1 duplicate, keep 1 unique"
        assert result[0].category == "XSS"


class TestMergedFindingFormatting:
    """Test merged finding comment formatting."""

    def test_merged_finding_includes_all_specialists(self):
        """Merged finding comment should list all specialists."""
        finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )

        specialists = ["Security", "Logic", "Testing"]
        result = format_merged_finding_comment(finding, specialists)

        for specialist in specialists:
            assert specialist in result, f"Should include {specialist}"

    def test_merged_finding_includes_severity(self):
        """Merged finding comment should show severity level."""
        finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.critical,
            category="Secrets",
            message="API key exposed",
        )

        result = format_merged_finding_comment(finding, ["Security"])
        assert "[CRITICAL]" in result

    def test_merged_finding_with_session_ids(self):
        """Merged finding comment should include session IDs when provided."""
        finding = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )

        session_ids = {
            "Security": "VGL-abc123",
            "Logic": "VGL-def456",
        }

        result = format_merged_finding_comment(
            finding, ["Security", "Logic"], session_ids
        )
        assert "VGL-abc123" in result
        assert "VGL-def456" in result


class TestAnnotateWithSpecialistContext:
    """Test annotation of findings with specialist metadata."""

    def test_annotate_merged_findings(self):
        """Merged findings should be annotated with specialist list."""
        f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )
        f2 = Finding(
            file="src/api.py",
            line=10,
            severity=Severity.medium,
            category="XSS",
            message="User input not escaped",
        )

        v1 = PersonaVerdict(
            persona="Security",
            session_id="VGL-111111",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f1],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Logic",
            session_id="VGL-222222",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f1, f2],  # Shared f1 with Security
            observations=[],
        )

        deduped, merged_info = merge_specialist_findings([v1, v2])
        annotated = annotate_findings_with_specialist_context(deduped, merged_info)

        # Should have 2 annotated findings
        assert len(annotated) == 2

        # The merged one should have specialist metadata
        merged_item = next((a for a in annotated if a["is_merged"]), None)
        assert merged_item is not None
        assert merged_item["count"] == 2
        assert set(merged_item["specialists"]) == {"Security", "Logic"}

        # The unique one should be marked as not merged
        unique_item = next((a for a in annotated if not a["is_merged"]), None)
        assert unique_item is not None
        assert unique_item["count"] == 0


class TestEndToEndConsensusFlow:
    """End-to-end test of consensus table generation."""

    def test_consensus_table_end_to_end(self):
        """Test full flow: merge findings -> format with consensus table.

        Note: findings merge when they share file + category + message fingerprint.
        Specialists must use the same category for dedup to trigger.
        """
        # Simulate 3 specialists finding the same issue with same category
        f1 = Finding(
            file="src/adapter.py",
            line=15,
            severity=Severity.critical,
            category="Resource Lifecycle Management",
            message="The `PlatformAuditAdapter` uses an in-memory `deque` as its WAL buffer, "
                    "which is lost on process termination. This violates write-ahead logging guarantees.",
            suggestion="Replace the in-memory `deque` with a persistent storage mechanism.",
        )
        f2 = Finding(
            file="src/adapter.py",
            line=15,
            severity=Severity.critical,
            category="Resource Lifecycle Management",
            message="The `PlatformAuditAdapter` uses an in-memory `deque` as its WAL buffer, "
                    "which is lost on process termination. This violates write-ahead logging guarantees.",
            suggestion="Replace the in-memory `deque` with a persistent storage mechanism.",
        )
        f3 = Finding(
            file="src/adapter.py",
            line=15,
            severity=Severity.high,
            category="Resource Lifecycle Management",
            message="The `PlatformAuditAdapter` uses an in-memory `deque` as its WAL buffer, "
                    "which is lost on process termination. This violates write-ahead logging guarantees.",
            suggestion="Replace the in-memory `deque` with a persistent storage mechanism.",
        )

        v1 = PersonaVerdict(
            persona="Architecture",
            session_id="VGL-ddd629",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f1],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Testing",
            session_id="VGL-7dbc2f",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f2],
            observations=[],
        )
        v3 = PersonaVerdict(
            persona="Performance",
            session_id="VGL-62c24e",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f3],
            observations=[],
        )

        # Merge findings
        deduped, merged = merge_specialist_findings([v1, v2, v3])

        assert len(deduped) == 1, "Should merge 3 findings into 1"
        assert len(merged) == 1, "Should have 1 merged group"
        assert merged[0].count == 3, "Should show 3 specialists"

        # Format with consensus table
        result = format_merged_finding_comment(
            merged[0].finding,
            merged[0].specialists,
            verdict_info=merged[0].verdict_info,
            total_specialists=6,
        )

        # Verify consensus table is present and correct
        assert "📊 **Consensus (3/6 specialists)**" in result
        assert "Architecture" in result
        assert "Testing" in result
        assert "Performance" in result
        assert "VGL-ddd629" in result
        assert "VGL-7dbc2f" in result
        assert "VGL-62c24e" in result
        assert "Resource Lifecycle Management" in result
        assert "PlatformAuditAdapter" in result
        assert "Replace the in-memory" in result
