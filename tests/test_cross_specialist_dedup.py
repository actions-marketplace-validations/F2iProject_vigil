"""Tests for cross_specialist_dedup: merging findings from multiple specialists."""

import pytest

from vigil.cross_specialist_dedup import (
    MergedFinding,
    VerdictInfo,
    merge_specialist_findings,
    format_merged_finding_comment,
    _severity_rank,
)
from vigil.models import Finding, PersonaVerdict, Severity


class TestSeverityRank:
    """Test severity ranking."""

    def test_critical_highest(self):
        assert _severity_rank(Severity.critical) > _severity_rank(Severity.high)

    def test_high_greater_medium(self):
        assert _severity_rank(Severity.high) > _severity_rank(Severity.medium)

    def test_medium_greater_low(self):
        assert _severity_rank(Severity.medium) > _severity_rank(Severity.low)

    def test_ranking_order(self):
        ranks = [_severity_rank(s) for s in [Severity.critical, Severity.high,
                                              Severity.medium, Severity.low]]
        assert ranks == sorted(ranks, reverse=True)


class TestMergeSpecialistFindings:
    """Test merging findings across specialists."""

    def test_single_specialist_no_merge(self):
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
        v1 = PersonaVerdict(
            persona="Security",
            session_id="VGL-abc123",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f1],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1])
        assert len(deduped) == 1
        assert len(merged) == 0

    def test_two_specialists_same_finding(self):
        """Two specialists flagging identical issue should merge."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
        f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
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
            findings=[f2],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        # Should merge into 1 finding
        assert len(deduped) == 1
        assert len(merged) == 1
        assert merged[0].count == 2
        assert set(merged[0].specialists) == {"Security", "Logic"}

    def test_two_specialists_different_findings(self):
        """Two specialists with different findings should not merge."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
        f2 = Finding(file="src/auth.py", line=50, severity=Severity.high,
                    category="SQL Injection", message="Different SQL issue")
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
            findings=[f2],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        # Different findings — no merge
        assert len(deduped) == 2
        assert len(merged) == 0

    def test_highest_severity_chosen_as_representative(self):
        """When merging, highest severity should be representative."""
        f_low = Finding(file="src/auth.py", line=42, severity=Severity.low,
                       category="DX", message="Issue")
        f_high = Finding(file="src/auth.py", line=42, severity=Severity.high,
                        category="DX", message="Issue")
        v1 = PersonaVerdict(
            persona="DX",
            session_id="VGL-111111",
            decision="APPROVE",
            checks={},
            findings=[f_low],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Testing",
            session_id="VGL-222222",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f_high],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        assert len(merged) == 1
        # Representative should be the high severity one
        assert merged[0].finding.severity == Severity.high

    def test_multiple_findings_partial_merge(self):
        """Multiple findings with some merging and some unique."""
        # Two specialists find same SQL issue
        sql_f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                        category="SQL Injection", message="Dangerous SQL")
        sql_f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                        category="SQL Injection", message="Dangerous SQL")
        
        # Different finding from another specialist
        design_f = Finding(file="src/api.py", line=10, severity=Severity.medium,
                          category="Design", message="Missing validation")
        
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
            findings=[sql_f2, design_f],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        # 2 findings in result: 1 merged SQL + 1 unique Design
        assert len(deduped) == 2
        assert len(merged) == 1  # Only the SQL was merged
        assert merged[0].count == 2


class TestFormatMergedFindingComment:
    """Test formatting merged findings for inline comments."""

    def test_basic_merged_format(self):
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        result = format_merged_finding_comment(f, ["Security", "Logic"])
        assert "🟠" in result  # High severity emoji (orange circle)
        assert "[HIGH]" in result
        assert "[SQL Injection]" in result
        assert "Flagged by:" in result
        assert "Security" in result
        assert "Logic" in result

    def test_format_with_suggestion(self):
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL",
                   suggestion="Use parameterized queries")
        result = format_merged_finding_comment(f, ["Security"])
        assert "Suggestion:" in result
        assert "parameterized" in result

    def test_format_includes_session_ids(self):
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        session_ids = {"Security": "VGL-abc123", "Logic": "VGL-def456"}
        result = format_merged_finding_comment(f, ["Security", "Logic"], session_ids)
        assert "VGL-abc123" in result
        assert "VGL-def456" in result

    def test_critical_severity_icon(self):
        f = Finding(file="src/config.py", line=1, severity=Severity.critical,
                   category="Secrets", message="API key exposed")
        result = format_merged_finding_comment(f, ["Security"])
        assert "[CRITICAL]" in result

    def test_medium_severity_icon(self):
        f = Finding(file="src/db.py", line=20, severity=Severity.medium,
                   category="Performance", message="N+1 query")
        result = format_merged_finding_comment(f, ["Performance"])
        assert "[MEDIUM]" in result

    def test_low_severity_icon(self):
        f = Finding(file="src/errors.py", line=5, severity=Severity.low,
                   category="DX", message="Confusing message")
        result = format_merged_finding_comment(f, ["DX"])
        assert "[LOW]" in result


class TestMergedFindingNamedTuple:
    """Test MergedFinding data structure."""

    def test_merged_finding_creation(self):
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        f_copy = Finding(file="src/auth.py", line=42, severity=Severity.high,
                        category="SQL Injection", message="Dangerous SQL")
        mf = MergedFinding(
            finding=f,
            specialists=["Security", "Logic"],
            count=2,
            original_findings=[f, f_copy],
        )
        assert mf.finding == f
        assert mf.count == 2
        assert len(mf.specialists) == 2
        assert len(mf.original_findings) == 2


class TestConsensusFormatting:
    """Test consensus table formatting for merged findings."""

    def test_consensus_format_two_specialists(self):
        """Consensus format should show table for two specialists."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-abc123"),
            VerdictInfo(specialist="Logic", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-def456"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Logic"],
            verdict_info=verdict_info,
            total_specialists=6
        )
        assert "📊 **Consensus (2/6 specialists)**" in result
        assert "| Specialist | Verdict | Ref |" in result
        assert "| Security `VGL-abc123` | 🚫 REQUEST_CHANGES | SQL Injection |" in result
        assert "| Logic `VGL-def456` | 🚫 REQUEST_CHANGES | SQL Injection |" in result
        assert "---" in result

    def test_consensus_format_three_specialists(self):
        """Consensus format should work with three specialists."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-111"),
            VerdictInfo(specialist="Testing", verdict="REQUEST_CHANGES",
                       category="Input Validation", session_id="VGL-222"),
            VerdictInfo(specialist="Performance", verdict="APPROVE",
                       category="Performance", session_id="VGL-333"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Testing", "Performance"],
            verdict_info=verdict_info,
            total_specialists=5
        )
        assert "📊 **Consensus (3/5 specialists)**" in result
        assert "Security" in result
        assert "Testing" in result
        assert "Performance" in result
        assert "✅ APPROVE" in result

    def test_consensus_shows_correct_total_count(self):
        """Consensus should show correct N/TOTAL count."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-abc"),
            VerdictInfo(specialist="Logic", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-def"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Logic"],
            verdict_info=verdict_info,
            total_specialists=8
        )
        assert "2/8 specialists" in result

    def test_consensus_includes_verdicts(self):
        """Consensus table should show verdicts with emojis."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Reviewer1", verdict="APPROVE",
                       category="SQL Injection", session_id="VGL-111"),
            VerdictInfo(specialist="Reviewer2", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-222"),
        ]
        result = format_merged_finding_comment(
            f, ["Reviewer1", "Reviewer2"],
            verdict_info=verdict_info,
            total_specialists=3
        )
        assert "✅ APPROVE" in result
        assert "🚫 REQUEST_CHANGES" in result

    def test_consensus_includes_category_refs(self):
        """Consensus table Ref column should show each specialist's category."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="Resource Lifecycle Management", session_id="VGL-ddd629"),
            VerdictInfo(specialist="Testing", verdict="REQUEST_CHANGES",
                       category="Data Integrity / Compliance", session_id="VGL-7dbc2f"),
            VerdictInfo(specialist="Performance", verdict="REQUEST_CHANGES",
                       category="Memory Leak / Unbounded Data Structure", session_id="VGL-62c24e"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Testing", "Performance"],
            verdict_info=verdict_info,
            total_specialists=6
        )
        assert "Resource Lifecycle Management" in result
        assert "Data Integrity / Compliance" in result
        assert "Memory Leak / Unbounded Data Structure" in result

    def test_single_specialist_no_consensus_table(self):
        """Single specialist should use simple format without consensus table."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        result = format_merged_finding_comment(
            f, ["Security"],
            session_ids={"Security": "VGL-abc123"}
        )
        assert "Consensus" not in result
        assert "Flagged by:" in result
        assert "Security" in result

    def test_no_total_specialists_uses_simple_format(self):
        """Without total_specialists, should use simple format."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-abc"),
            VerdictInfo(specialist="Logic", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-def"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Logic"],
            verdict_info=verdict_info,
            total_specialists=None  # No total provided
        )
        assert "Consensus" not in result
        assert "Flagged by:" in result

    def test_consensus_includes_main_finding_content(self):
        """Consensus format should include the main finding message and suggestion."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL concatenation",
                   suggestion="Use parameterized queries")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-abc"),
            VerdictInfo(specialist="Logic", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-def"),
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Logic"],
            verdict_info=verdict_info,
            total_specialists=3
        )
        assert "Dangerous SQL concatenation" in result
        assert "Use parameterized queries" in result

    def test_verdict_info_with_empty_session_id(self):
        """VerdictInfo with empty session_id should not show backticks."""
        f = Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL")
        verdict_info = [
            VerdictInfo(specialist="Security", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id="VGL-abc123"),
            VerdictInfo(specialist="Logic", verdict="REQUEST_CHANGES",
                       category="SQL Injection", session_id=""),  # No session ID
        ]
        result = format_merged_finding_comment(
            f, ["Security", "Logic"],
            verdict_info=verdict_info,
            total_specialists=3
        )
        # Security row should have session ID in backticks
        assert "Security `VGL-abc123`" in result
        # Logic row should not have backticks
        assert "| Logic |" in result


class TestMergeWithVerdictInfo:
    """Test merge_specialist_findings populates verdict_info correctly."""

    def test_merged_finding_includes_verdict_info(self):
        """Merged finding should populate verdict_info from PersonaVerdict."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
        f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="SQL Injection", message="Dangerous SQL")
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
            findings=[f2],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        assert len(merged) == 1
        assert len(merged[0].verdict_info) == 2

        # Check verdict info contains expected data
        verdicts_by_spec = {v.specialist: v for v in merged[0].verdict_info}
        assert "Security" in verdicts_by_spec
        assert "Logic" in verdicts_by_spec
        assert verdicts_by_spec["Security"].verdict == "REQUEST_CHANGES"
        assert verdicts_by_spec["Security"].session_id == "VGL-111111"
        assert verdicts_by_spec["Logic"].session_id == "VGL-222222"

    def test_verdict_info_includes_category_from_finding(self):
        """Verdict info should capture the category from each specialist's finding.

        Note: findings must share the same category to merge (fingerprint includes category).
        The verdict_info tracks each specialist's category label for display purposes.
        """
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="Resource Management", message="Issue")
        f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                    category="Resource Management", message="Issue")
        v1 = PersonaVerdict(
            persona="Architecture",
            session_id="VGL-aaa111",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f1],
            observations=[],
        )
        v2 = PersonaVerdict(
            persona="Performance",
            session_id="VGL-bbb222",
            decision="REQUEST_CHANGES",
            checks={},
            findings=[f2],
            observations=[],
        )
        deduped, merged = merge_specialist_findings([v1, v2])
        assert len(merged) == 1

        verdicts_by_spec = {v.specialist: v for v in merged[0].verdict_info}
        assert verdicts_by_spec["Architecture"].category == "Resource Management"
        assert verdicts_by_spec["Performance"].category == "Resource Management"


class TestXssSanitization:
    """Test XSS prevention in comment formatting (issue #12)."""

    def test_sanitizes_llm_generated_message(self):
        """LLM-generated message should be sanitized to prevent XSS."""
        # Malicious message from LLM
        malicious_msg = "Check this: <script>alert('xss')</script> dangerous!"
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category="Issue", message=malicious_msg
        )
        result = format_merged_finding_comment(f, ["Security"])
        # XSS payload should be removed
        assert "<script>" not in result
        assert "alert" not in result

    def test_sanitizes_llm_generated_category(self):
        """LLM-generated category should be sanitized."""
        malicious_cat = "SQL Injection<img src=x onerror='alert(1)'>"
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category=malicious_cat, message="Issue"
        )
        result = format_merged_finding_comment(f, ["Security"])
        # HTML injection should be removed
        assert "<img" not in result
        assert "onerror" not in result

    def test_sanitizes_llm_generated_suggestion(self):
        """LLM-generated suggestion should be sanitized."""
        malicious_sugg = "Use this: <svg/onload=alert(1)>"
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category="Issue", message="Problem",
            suggestion=malicious_sugg
        )
        result = format_merged_finding_comment(f, ["Security"])
        # SVG injection should be removed
        assert "<svg" not in result
        assert "onload" not in result

    def test_validates_specialist_names(self):
        """Specialist names with special chars should be validated."""
        # Try to inject markdown/HTML via specialist name
        malicious_name = "Security<script>"
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category="Issue", message="Problem"
        )
        result = format_merged_finding_comment(f, [malicious_name])
        # Malicious chars should be stripped
        assert "<script>" not in result
        assert "Security" in result

    def test_validates_session_ids(self):
        """Invalid session IDs should be rejected."""
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category="Issue", message="Problem"
        )
        # Malicious session ID
        session_ids = {"Security": "'; drop table findings; --"}
        result = format_merged_finding_comment(f, ["Security"], session_ids)
        # Invalid session ID should not appear
        assert "drop table" not in result
        assert ";" not in result

    def test_verdict_info_sanitizes_category(self):
        """Category in verdict info should be sanitized."""
        f = Finding(
            file="src/file.py", line=42, severity=Severity.high,
            category="Issue", message="Problem"
        )
        malicious_cat = "Category<img src=x onerror='alert(1)'>"
        verdict_info = [
            VerdictInfo(
                specialist="Security",
                verdict="REQUEST_CHANGES",
                category=malicious_cat,
                session_id="VGL-abc123"
            )
        ]
        result = format_merged_finding_comment(
            f, ["Security"],
            verdict_info=verdict_info,
            total_specialists=1
        )
        # HTML injection should be removed from verdict info
        assert "<img" not in result
        assert "onerror" not in result
