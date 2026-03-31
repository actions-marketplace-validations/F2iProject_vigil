"""Tests for context_manager: fingerprinting, cross-round matching, cross-specialist dedup."""

import pytest

from vigil.context_manager import (
    FindingFingerprint,
    extract_finding_from_comment,
    filter_cross_round_duplicates,
    fingerprint_finding,
    fingerprints_match,
    _normalize_line_range,
    _line_ranges_overlap,
    _extract_finding_from_json_metadata,
    _extract_finding_from_regex,
)
from vigil.models import Finding, Severity


class TestNormalizeLineRange:
    """Test line range normalization for fuzzy matching."""

    def test_none_line_returns_zero_range(self):
        result = _normalize_line_range(None)
        assert result == (0, 0)

    def test_zero_line_returns_zero_range(self):
        result = _normalize_line_range(0)
        assert result == (0, 0)

    def test_positive_line_creates_range(self):
        result = _normalize_line_range(50, context_lines=2)
        assert result == (48, 52)

    def test_small_lines_bounded_at_zero(self):
        result = _normalize_line_range(1, context_lines=5)
        assert result == (0, 6)  # Max(0, -4) = 0


class TestLineRangesOverlap:
    """Test line range overlap detection."""

    def test_unlocated_range_overlaps_any(self):
        assert _line_ranges_overlap((0, 0), (10, 20))
        assert _line_ranges_overlap((10, 20), (0, 0))

    def test_overlapping_ranges(self):
        assert _line_ranges_overlap((10, 20), (15, 25))
        assert _line_ranges_overlap((15, 25), (10, 20))

    def test_touching_ranges_overlap(self):
        assert _line_ranges_overlap((10, 20), (20, 30))

    def test_non_overlapping_ranges(self):
        assert not _line_ranges_overlap((10, 15), (20, 25))
        assert not _line_ranges_overlap((20, 25), (10, 15))


class TestFingerprintFinding:
    """Test finding fingerprint generation."""

    def test_same_finding_same_fingerprint(self):
        f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )
        f2 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )
        assert fingerprint_finding(f1) == fingerprint_finding(f2)

    def test_different_file_different_fingerprint(self):
        f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )
        f2 = Finding(
            file="src/other.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL concatenation",
        )
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_different_category_different_fingerprint(self):
        f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )
        f2 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="XSS",
            message="Dangerous SQL",
        )
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_line_range_includes_context(self):
        f1 = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="Issue",
            message="Test",
        )
        fp1 = fingerprint_finding(f1)
        # Line range should include context
        assert fp1.line_range == (40, 44)  # 42 +/- 2


class TestFingerprintsMatch:
    """Test fingerprint matching logic."""

    def test_identical_fingerprints_match(self):
        f = Finding(
            file="src/auth.py",
            line=42,
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous SQL",
        )
        fp = fingerprint_finding(f)
        assert fingerprints_match(fp, fp)

    def test_different_files_dont_match(self):
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Test")
        f2 = Finding(file="src/other.py", line=42, severity=Severity.high,
                     category="Issue", message="Test")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        assert not fingerprints_match(fp1, fp2)

    def test_different_categories_dont_match(self):
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="SQL Injection", message="Test")
        f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="XSS", message="Test")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        assert not fingerprints_match(fp1, fp2)

    def test_different_message_hash_dont_match(self):
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Problem A")
        f2 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Problem B")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        assert not fingerprints_match(fp1, fp2)

    def test_slightly_shifted_lines_match_fuzzy(self):
        """Lines that are close together should match (fuzzy mode)."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Test problem")
        f2 = Finding(file="src/auth.py", line=44, severity=Severity.high,
                     category="Issue", message="Test problem")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        # 42 +/- 2 = [40, 44], 44 +/- 2 = [42, 46] — they overlap
        assert fingerprints_match(fp1, fp2, exact_line=False)

    def test_far_apart_lines_dont_match_fuzzy(self):
        """Lines far apart shouldn't match even in fuzzy mode."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Test problem")
        f2 = Finding(file="src/auth.py", line=100, severity=Severity.high,
                     category="Issue", message="Test problem")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        assert not fingerprints_match(fp1, fp2, exact_line=False)

    def test_exact_line_mode_requires_same_range(self):
        """Exact line mode requires ranges to be identical."""
        f1 = Finding(file="src/auth.py", line=42, severity=Severity.high,
                     category="Issue", message="Test")
        f2 = Finding(file="src/auth.py", line=44, severity=Severity.high,
                     category="Issue", message="Test")
        fp1, fp2 = fingerprint_finding(f1), fingerprint_finding(f2)
        assert not fingerprints_match(fp1, fp2, exact_line=True)


class TestExtractFindingFromComment:
    """Test extracting findings from Vigil comment bodies."""

    def test_extract_basic_finding(self):
        body = (
            "🔴 **[HIGH]** [SQL Injection] **Security** `VGL-abc123`\n\n"
            "Dangerous SQL concatenation in query\n\n"
            "**Suggestion:** Use parameterized queries"
        )
        result = extract_finding_from_comment(body, "src/auth.py", 42)
        assert result is not None
        assert result.file == "src/auth.py"
        assert result.line == 42
        assert result.severity == Severity.high
        assert result.category == "SQL Injection"
        assert "concatenation" in result.message

    def test_extract_critical_finding(self):
        body = "🔴 **[CRITICAL]** [Secrets Leak] Hardcoded API key"
        result = extract_finding_from_comment(body, "src/config.py", 10)
        assert result is not None
        assert result.severity == Severity.critical

    def test_extract_medium_finding(self):
        body = "🟡 **[MEDIUM]** [Design] Missing validation"
        result = extract_finding_from_comment(body, "src/handlers.py", 20)
        assert result is not None
        assert result.severity == Severity.medium

    def test_extract_low_finding(self):
        body = "🔵 **[LOW]** [DX] Confusing error message"
        result = extract_finding_from_comment(body, "src/errors.py", 5)
        assert result is not None
        assert result.severity == Severity.low

    def test_extract_with_file_path_fallback(self):
        """If file_path is None, should use 'unknown'."""
        body = "🔴 **[HIGH]** [Issue] Problem here"
        result = extract_finding_from_comment(body, None, 42)
        assert result is not None
        assert result.file == "unknown"

    def test_extract_invalid_severity_returns_none(self):
        """If severity tag not found, extraction should fail."""
        body = "Some comment without severity tag"
        result = extract_finding_from_comment(body, "src/file.py", 42)
        assert result is None

    def test_extract_category_from_bracket(self):
        body = "🔴 **[HIGH]** [My Custom Category] Some issue"
        result = extract_finding_from_comment(body, "src/file.py", 42)
        assert result is not None
        assert result.category == "My Custom Category"


class TestFilterCrossRoundDuplicates:
    """Test filtering findings against existing comments."""

    def test_empty_existing_returns_all_findings(self):
        findings = [
            Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL"),
            Finding(file="src/api.py", line=10, severity=Severity.medium,
                   category="Design", message="Missing validation"),
        ]
        result = filter_cross_round_duplicates(findings, [])
        assert result == findings

    def test_filters_exact_match(self):
        findings = [
            Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="Dangerous SQL"),
        ]
        existing = [
            {
                "path": "src/auth.py",
                "line": 42,
                "body": "🔴 **[HIGH]** [SQL Injection] Dangerous SQL",
            }
        ]
        result = filter_cross_round_duplicates(findings, existing)
        assert len(result) == 0

    def test_keeps_different_findings(self):
        findings = [
            Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="New issue"),
        ]
        existing = [
            {
                "path": "src/auth.py",
                "line": 42,
                "body": "🔴 **[HIGH]** [SQL Injection] Old issue",
            }
        ]
        result = filter_cross_round_duplicates(findings, existing)
        # Different message hash — should be kept
        assert len(result) == 1

    def test_filters_by_category_and_file(self):
        findings = [
            Finding(file="src/auth.py", line=42, severity=Severity.high,
                   category="SQL Injection", message="SQL problem"),
        ]
        existing = [
            {
                "path": "src/other.py",
                "line": 42,
                "body": "🔴 **[HIGH]** [SQL Injection] SQL problem",
            }
        ]
        result = filter_cross_round_duplicates(findings, existing)
        # Different file — should be kept
        assert len(result) == 1

    def test_filters_unlocated_finding(self):
        """Finding with line=None should match if file and category match."""
        findings = [
            Finding(file="src/auth.py", line=None, severity=Severity.high,
                   category="SQL Injection", message="SQL problem"),
        ]
        existing = [
            {
                "path": "src/auth.py",
                "line": None,
                "body": "🔴 **[HIGH]** [SQL Injection] SQL problem",
            }
        ]
        result = filter_cross_round_duplicates(findings, existing)
        assert len(result) == 0


class TestExtractFindingFromJsonMetadata:
    """Test JSON metadata extraction (issue #13)."""

    def test_extracts_from_json_metadata(self):
        """Should extract Finding from embedded JSON metadata."""
        body = (
            "<!-- vigil-meta: "
            '{"severity":"high","category":"SQL Injection","message":"Dangerous SQL"} '
            "-->\n\nMarkdown content here"
        )
        result = _extract_finding_from_json_metadata(body, "src/auth.py", 42)
        assert result is not None
        assert result.severity == Severity.high
        assert result.category == "SQL Injection"
        assert result.message == "Dangerous SQL"
        assert result.file == "src/auth.py"
        assert result.line == 42

    def test_extracts_with_suggestion(self):
        """JSON metadata can include optional suggestion field."""
        body = (
            "<!-- vigil-meta: "
            '{"severity":"high","category":"Issue","message":"Problem",'
            '"suggestion":"Use parameterized queries"} '
            "-->"
        )
        result = _extract_finding_from_json_metadata(body, "src/file.py", 10)
        assert result is not None
        assert result.suggestion == "Use parameterized queries"

    def test_returns_none_if_no_metadata(self):
        """Should return None if no JSON metadata block found."""
        body = "Regular comment without metadata"
        result = _extract_finding_from_json_metadata(body, "src/file.py", 42)
        assert result is None

    def test_handles_malformed_json(self):
        """Should gracefully handle malformed JSON."""
        body = '<!-- vigil-meta: {invalid json} -->'
        result = _extract_finding_from_json_metadata(body, "src/file.py", 42)
        assert result is None

    def test_requires_severity(self):
        """Missing severity field should fail."""
        body = '<!-- vigil-meta: {"category":"Issue","message":"Test"} -->'
        result = _extract_finding_from_json_metadata(body, "src/file.py", 42)
        assert result is None

    def test_requires_message(self):
        """Missing message field should fail."""
        body = '<!-- vigil-meta: {"severity":"high","category":"Issue"} -->'
        result = _extract_finding_from_json_metadata(body, "src/file.py", 42)
        assert result is None

    def test_handles_values_with_closing_brace(self):
        """JSON values containing '}' should be parsed correctly (non-greedy regex)."""
        body = (
            '<!-- vigil-meta: '
            '{"severity":"high","category":"Logic","message":"Missing } in template"} '
            '-->'
        )
        result = _extract_finding_from_json_metadata(body, "src/file.py", 10)
        assert result is not None
        assert result.message == "Missing } in template"

    def test_handles_nested_json_objects(self):
        """Nested JSON objects should not break extraction."""
        # While current metadata schema is flat, the regex should not choke
        # on values that happen to contain braces
        body = (
            '<!-- vigil-meta: '
            '{"severity":"medium","category":"Format","message":"Check {braces} usage"} '
            '-->'
        )
        result = _extract_finding_from_json_metadata(body, "src/file.py", 5)
        assert result is not None
        assert "{braces}" in result.message


class TestExtractFindingFromRegex:
    """Test regex-based extraction with ReDoS protection (issue #11)."""

    def test_extracts_via_regex(self):
        """Should extract Finding using regex patterns."""
        body = "🔴 **[HIGH]** [SQL Injection] Dangerous SQL concatenation"
        result = _extract_finding_from_regex(body, "src/auth.py", 42)
        assert result is not None
        assert result.severity == Severity.high
        assert result.category == "SQL Injection"

    def test_bounded_regex_quantifier(self):
        """Category regex should use bounded quantifier to prevent ReDoS."""
        # Create a comment with a very long category name (but still within bounds)
        category = "A" * 50  # Within 100 char limit
        body = f"🔴 **[HIGH]** [{category}] Issue"
        result = _extract_finding_from_regex(body, "src/file.py", 42)
        assert result is not None
        assert len(result.category) == 50

    def test_rejects_overly_long_category(self):
        """Categories longer than 100 chars should be truncated."""
        category = "A" * 150  # Exceeds 100 char limit
        body = f"🔴 **[HIGH]** [{category}] Issue"
        result = _extract_finding_from_regex(body, "src/file.py", 42)
        # Regex shouldn't match (bounded to 100 chars)
        # It will extract whatever it can, or fail gracefully
        if result:
            assert len(result.category) <= 100

    def test_restricted_category_chars(self):
        """Category regex should only allow word chars, space, slash, hyphen."""
        # Valid: word chars, spaces, slashes, hyphens
        body1 = "🔴 **[HIGH]** [SQL-Injection/Prevention] Issue"
        result1 = _extract_finding_from_regex(body1, "src/file.py", 42)
        assert result1 is not None

    def test_handles_input_length_limit(self):
        """Comments longer than 10000 chars should be truncated."""
        # Create a very long comment
        long_body = "🔴 **[HIGH]** [Issue] " + "A" * 15000
        # Should not crash, should truncate internally
        result = _extract_finding_from_regex(long_body, "src/file.py", 42)
        # Result depends on internal handling, but should not raise
        assert result is None or isinstance(result, Finding)

    def test_extracts_all_severity_levels(self):
        """Should extract all severity levels."""
        for severity_tag in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            body = f"🔴 **[{severity_tag}]** [Issue] Problem"
            result = _extract_finding_from_regex(body, "src/file.py", 42)
            assert result is not None
            assert result.severity.value.lower() == severity_tag.lower()


class TestJsonMetadataFallback:
    """Test that extraction tries JSON first, then falls back to regex."""

    def test_prefers_json_metadata_over_regex(self):
        """If both JSON and regex data exist, JSON should be used."""
        # This comment has BOTH JSON metadata and regex-parseable content
        body = (
            "<!-- vigil-meta: "
            '{"severity":"critical","category":"Secrets","message":"API key exposed"} '
            "-->\n\n"
            "🔴 **[MEDIUM]** [Design] This is the regex version"
        )
        result = extract_finding_from_comment(body, "src/file.py", 10)
        assert result is not None
        # Should use JSON data (critical, Secrets, API key exposed)
        # not regex data (medium, Design)
        assert result.severity == Severity.critical
        assert result.category == "Secrets"
        assert "API key" in result.message

    def test_falls_back_to_regex_if_no_json(self):
        """If no JSON metadata, should fall back to regex parsing."""
        body = "🔴 **[HIGH]** [SQL Injection] Dangerous SQL"
        result = extract_finding_from_comment(body, "src/file.py", 42)
        assert result is not None
        assert result.severity == Severity.high
        assert result.category == "SQL Injection"

    def test_returns_none_if_neither_works(self):
        """If neither JSON nor regex works, should return None."""
        body = "Just a regular comment with no structured data"
        result = extract_finding_from_comment(body, "src/file.py", 42)
        assert result is None


class TestSpatialLookup:
    """Test spatial line range lookup optimization for large candidate lists."""

    def test_find_overlapping_with_exact_match(self):
        """Test finding overlapping fingerprints with exact line match."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="abc123def456",
            line_range=(40, 44),
        )

        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="abc123def456",
                line_range=(40, 44),  # Exact match
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="different_hash",
                line_range=(40, 44),
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        assert len(result) == 1
        assert result[0].message_hash == "abc123def456"

    def test_find_overlapping_with_shifted_lines(self):
        """Test finding overlapping fingerprints when lines are shifted."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="abc123def456",
            line_range=(40, 44),
        )

        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="abc123def456",
                line_range=(42, 46),  # Overlaps with target
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="abc123def456",
                line_range=(50, 55),  # No overlap
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        assert len(result) == 1
        assert result[0].line_range == (42, 46)

    def test_find_overlapping_with_unlocated(self):
        """Test that unlocated findings match everything."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="abc123def456",
            line_range=(0, 0),  # Unlocated
        )

        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="abc123def456",
                line_range=(10, 20),
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="abc123def456",
                line_range=(100, 200),
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        assert len(result) == 2, "Unlocated target should match all candidates"

    def test_find_overlapping_filters_by_message_hash(self):
        """Test that message_hash is still used for filtering."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="target_hash",
            line_range=(40, 44),
        )

        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="target_hash",
                line_range=(40, 44),  # Matches
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="different_hash",
                line_range=(40, 44),  # Same line but different hash
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        assert len(result) == 1
        assert result[0].message_hash == "target_hash"

    def test_find_overlapping_with_many_candidates(self):
        """Test spatial lookup with many candidates."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="target_hash",
            line_range=(50, 55),
        )

        # Create 100 candidates at various line ranges
        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="target_hash",
                line_range=(i, i + 4),
            )
            for i in range(0, 200, 2)
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        # Should find only those that overlap with (50, 55)
        # Overlapping ranges: those where end >= 50 and start <= 55
        assert len(result) > 0
        for fp in result:
            start, end = fp.line_range
            # Verify overlap: not (end < 50 or start > 55)
            assert not (end < 50 or start > 55)

    def test_filter_with_spatial_lookup_threshold(self):
        """Test that filter_cross_round_duplicates uses spatial lookup for large lists."""
        # Create many existing findings
        existing_comments = []
        for i in range(20):
            existing_comments.append({
                "path": "src/queries.py",
                "line": i * 10,
                "body": "🟠 **[HIGH]** [SQL Injection]\n\nDangerous query",
            })

        # New finding that matches one of them (by line range overlap)
        new_finding = Finding(
            file="src/queries.py",
            line=25,  # Should match the finding at line 20 (within context)
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous query",
        )

        # With spatial_lookup_threshold=10, should use binary search
        result = filter_cross_round_duplicates(
            [new_finding],
            existing_comments,
            spatial_lookup_threshold=10,
        )

        assert len(result) == 0, "Should filter duplicate found via spatial lookup"

    def test_filter_fallback_to_linear_scan(self):
        """Test that small candidate lists use linear scan (below threshold)."""
        # Create just 5 existing findings
        existing_comments = [
            {
                "path": "src/auth.py",
                "line": 10,
                "body": "🟠 **[HIGH]** [SQL Injection]\n\nDangerous query",
            },
            {
                "path": "src/auth.py",
                "line": 20,
                "body": "🟠 **[HIGH]** [SQL Injection]\n\nDangerous query",
            },
            {
                "path": "src/auth.py",
                "line": 30,
                "body": "🟠 **[HIGH]** [SQL Injection]\n\nDangerous query",
            },
        ]

        new_finding = Finding(
            file="src/auth.py",
            line=28,  # Close to line 30
            severity=Severity.high,
            category="SQL Injection",
            message="Dangerous query",
        )

        # With threshold=10, 3 candidates should use linear scan
        result = filter_cross_round_duplicates(
            [new_finding],
            existing_comments,
            spatial_lookup_threshold=10,
        )

        assert len(result) == 0, "Should filter using linear scan"

    def test_spatial_lookup_non_overlapping_ranges(self):
        """Test that non-overlapping ranges are correctly excluded."""
        from vigil.context_manager import _find_overlapping_fingerprints

        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="target_hash",
            line_range=(100, 105),
        )

        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="target_hash",
                line_range=(10, 20),  # Too low
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="target_hash",
                line_range=(200, 210),  # Too high
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="target_hash",
                line_range=(100, 105),  # Exact match
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        assert len(result) == 1
        assert result[0].line_range == (100, 105)

    def test_no_duplicates_when_candidates_share_start_line(self):
        """Test that multiple candidates at same start line are returned once each."""
        from vigil.context_manager import _find_overlapping_fingerprints

        # Target at line 15 with range (13, 17)
        target = FindingFingerprint(
            file="src/auth.py",
            category="SQL Injection",
            message_hash="shared_hash",
            line_range=(13, 17),
        )

        # Three candidates all starting at line 10, all with matching message_hash
        candidates = [
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="shared_hash",
                line_range=(10, 20),  # Overlaps with target
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="shared_hash",
                line_range=(10, 25),  # Overlaps with target
            ),
            FindingFingerprint(
                file="src/auth.py",
                category="SQL Injection",
                message_hash="shared_hash",
                line_range=(10, 30),  # Overlaps with target
            ),
        ]

        result = _find_overlapping_fingerprints(target, candidates)
        # All three should be returned (they all overlap)
        assert len(result) == 3
        # Each should appear exactly once (no duplicates)
        assert result[0].line_range == (10, 20)
        assert result[1].line_range == (10, 25)
        assert result[2].line_range == (10, 30)
