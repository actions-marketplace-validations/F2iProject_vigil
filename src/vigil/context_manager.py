"""Cross-round context management — fingerprint findings and skip already-posted ones.

Vigil tracks findings across multiple review rounds by generating fingerprints
for each finding. Before posting new findings, we check against all existing
Vigil comments (including resolved threads) to avoid re-flagging the same issues.

Finding fingerprint = hash(file + line_range + category + normalized_message)
This enables finding matching even when:
- The exact line number shifts slightly (same logical location)
- The message is paraphrased but conveys the same concern
- The thread is marked as resolved (we still skip to respect prior feedback)
"""

import bisect
import hashlib
import json
import logging
import re
from typing import NamedTuple

from .models import Finding
from .utils import content_fingerprint, extract_message_content

log = logging.getLogger(__name__)

# Pre-compiled regex for extracting JSON metadata from Vigil HTML comments.
# Uses non-greedy .*? to handle nested objects and values containing '}'.
_VIGIL_META_PATTERN = re.compile(r"<!--\s*vigil-meta:\s*(\{.*?\})\s*-->")


class FindingFingerprint(NamedTuple):
    """Unique identifier for a finding pattern."""
    file: str
    category: str
    message_hash: str
    line_range: tuple[int, int]  # (line_start, line_end) — accounts for multi-line findings


def _normalize_line_range(line: int | None, context_lines: int = 2) -> tuple[int, int]:
    """Convert a single line number to a line range for fuzzy matching.

    When the same finding appears a few lines away (due to code changes),
    we still want to recognize it as the same finding. This builds a range
    that accounts for slight line shifts.

    Args:
        line: The exact line number (0 means unknown/unlocated)
        context_lines: Lines to expand the range by on each side

    Returns:
        (line_start, line_end) tuple for range-based matching
    """
    if line is None or line <= 0:
        # Unlocated findings: match by (file, category, message) only
        return (0, 0)
    start = max(0, line - context_lines)
    end = line + context_lines
    return (start, end)


def _line_ranges_overlap(
    range1: tuple[int, int], range2: tuple[int, int]
) -> bool:
    """Check if two line ranges overlap (for fuzzy line matching)."""
    # Unlocated findings (0, 0) match any range
    if range1 == (0, 0) or range2 == (0, 0):
        return True
    start1, end1 = range1
    start2, end2 = range2
    return not (end1 < start2 or end2 < start1)


def fingerprint_finding(finding: Finding) -> FindingFingerprint:
    """Generate a fingerprint for a finding to enable cross-round matching.

    Two findings match if they have the same fingerprint, even if:
    - Posted in different review rounds
    - The line number shifted slightly
    - The exact wording changed (but semantic content is similar)

    Args:
        finding: The Finding object to fingerprint

    Returns:
        FindingFingerprint with file, category, message_hash, and line_range
    """
    # Extract core message for hashing
    message_text = extract_message_content(finding.message)
    message_hash = content_fingerprint(message_text)

    # Line range accounts for small line shifts
    line_range = _normalize_line_range(finding.line)

    return FindingFingerprint(
        file=finding.file,
        category=finding.category,
        message_hash=message_hash,
        line_range=line_range,
    )


def fingerprints_match(
    fp1: FindingFingerprint,
    fp2: FindingFingerprint,
    exact_line: bool = False,
) -> bool:
    """Check if two finding fingerprints match (same issue, possibly different round).

    Args:
        fp1: First fingerprint
        fp2: Second fingerprint
        exact_line: If True, require exact line match (used for same-round dedup)

    Returns:
        True if the fingerprints represent the same finding
    """
    # Different file or category — definitely different
    if fp1.file != fp2.file or fp1.category != fp2.category:
        return False

    # Different message hash — likely different issues
    if fp1.message_hash != fp2.message_hash:
        return False

    # Line matching
    if exact_line:
        # Same-round dedup: require exact match
        return fp1.line_range == fp2.line_range
    else:
        # Cross-round dedup: allow slight line shifts
        return _line_ranges_overlap(fp1.line_range, fp2.line_range)


def extract_finding_from_comment(
    comment_body: str,
    file_path: str | None,
    line: int | None,
) -> Finding | None:
    """Parse a Vigil comment body back into a Finding object for cross-round matching.

    Extracts severity, category, and message from the formatted comment.
    This allows us to reconstruct findings from existing comments to compare
    with newly generated findings.

    Tries JSON metadata first (future-proof), then falls back to regex parsing (backward-compatible).
    Regex parsing is hardened against ReDoS with input length limits and bounded quantifiers.

    Args:
        comment_body: The full Vigil comment body (markdown)
        file_path: The file path from GitHub comment metadata
        line: The line number from GitHub comment metadata

    Returns:
        Reconstructed Finding, or None if parsing fails
    """
    from .models import Severity

    # Limit input to prevent ReDoS attacks
    max_comment_length = 10000
    if len(comment_body) > max_comment_length:
        log.warning(
            "Comment body exceeds max length (%d > %d), truncating for parsing",
            len(comment_body),
            max_comment_length,
        )
        comment_body = comment_body[:max_comment_length]

    # Try JSON metadata extraction first (issue #13)
    finding = _extract_finding_from_json_metadata(comment_body, file_path, line)
    if finding:
        return finding

    # Fall back to regex parsing (backward-compatible)
    return _extract_finding_from_regex(comment_body, file_path, line)


def _extract_finding_from_json_metadata(
    comment_body: str,
    file_path: str | None,
    line: int | None,
) -> "Finding | None":
    """Try to extract Finding from embedded JSON metadata.

    Looks for HTML comment with structure:
    <!-- vigil-meta: {"severity":"high","category":"SQL Injection",...} -->

    Args:
        comment_body: The full comment body
        file_path: File path from GitHub metadata
        line: Line number from GitHub metadata

    Returns:
        Reconstructed Finding, or None if metadata not found
    """
    from .models import Severity

    # Use pre-compiled module-level pattern for JSON metadata extraction.
    # Non-greedy .*? correctly handles nested JSON and values containing '}'.
    match = _VIGIL_META_PATTERN.search(comment_body)
    if not match:
        return None

    try:
        metadata = json.loads(match.group(1))

        # Extract required fields
        severity_str = metadata.get("severity", "").lower()
        category = metadata.get("category", "unknown")
        message = metadata.get("message", "")

        if not severity_str or not message:
            return None

        # Map severity
        sev_map = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
        }
        severity = sev_map.get(severity_str)
        if not severity:
            return None

        return Finding(
            file=file_path or "unknown",
            line=line,
            severity=severity,
            category=category,
            message=message,
            suggestion=metadata.get("suggestion"),
        )
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        log.debug("Failed to parse JSON metadata: %s", e)
        return None


def _extract_finding_from_regex(
    comment_body: str,
    file_path: str | None,
    line: int | None,
) -> "Finding | None":
    """Extract Finding from regex-based markdown parsing (backward-compatible).

    Hardened against ReDoS with bounded quantifiers and input validation.

    Args:
        comment_body: The full comment body
        file_path: File path from GitHub metadata
        line: Line number from GitHub metadata

    Returns:
        Reconstructed Finding, or None if parsing fails
    """
    from .models import Severity

    # Extract severity from tags like **[CRITICAL]**, **[HIGH]**, etc.
    sev_match = re.search(r"\*\*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\*\*", comment_body)
    if not sev_match:
        return None

    sev_str = sev_match.group(1).lower()
    sev_map = {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
    }
    severity = sev_map.get(sev_str, Severity.medium)

    # Extract category from [CategoryName] tags
    # Use bounded quantifier {1,100} to prevent ReDoS
    # Restrict character class to be more specific (word chars, space, slash, hyphen)
    cat_match = re.search(
        r"\[([\w\s/\-]{1,100})\]", comment_body[sev_match.end() :]
    )
    category = cat_match.group(1).strip() if cat_match else "unknown"

    # Extract message: everything after the header, before suggestion
    message = extract_message_content(comment_body)
    if not message:
        return None

    return Finding(
        file=file_path or "unknown",
        line=line,
        severity=severity,
        category=category,
        message=message,
    )


def _find_overlapping_fingerprints(
    target: FindingFingerprint,
    candidates: list[FindingFingerprint],
) -> list[FindingFingerprint]:
    """Find fingerprints with overlapping line ranges using binary search.

    **Precondition**: ``candidates`` must be sorted by ``line_range[0]`` in
    ascending order. ``filter_cross_round_duplicates`` guarantees this by
    pre-sorting each candidate group once before invoking this function.

    Time complexity: O(log N + R) where N = len(candidates) and R is the number
    of candidates whose ``line_range[0] <= target_end`` (the scan window).
    ``bisect.bisect_right`` with a ``key`` function (Python ≥ 3.10) locates the
    window boundary in O(log N) with no intermediate list; only the R candidates
    in the window are inspected afterward, with no extra list allocation.
    R ≤ N; in the common case R ≈ k (the number of results returned).

    Unlocated findings (line_range = (0, 0)) match any target.

    Args:
        target: The target fingerprint to match against.
        candidates: List of candidate fingerprints, pre-sorted by line_range[0].

    Returns:
        List of candidate fingerprints whose line ranges overlap with the target
        and whose message_hash matches.
    """
    if target.line_range == (0, 0):
        # Unlocated target matches everything with same message hash
        return [fp for fp in candidates if fp.message_hash == target.message_hash]

    target_start, target_end = target.line_range

    # Binary search: find the rightmost index where line_range[0] <= target_end.
    # bisect.bisect_right with key= avoids building an intermediate list — O(log N).
    # Requires Python >= 3.10 (key parameter added in 3.10); pyproject.toml
    # specifies python_requires >= "3.11" so this is always available.
    right_idx = bisect.bisect_right(
        candidates, target_end, key=lambda fp: fp.line_range[0]
    )  # O(log N)

    # Iterate only the window [0, right_idx) by index — O(R), no list allocation.
    # Use a seen set with id() for O(1) deduplication without requiring hashability.
    seen: set[int] = set()
    result: list[FindingFingerprint] = []
    for i in range(right_idx):
        fp = candidates[i]
        fp_start, fp_end = fp.line_range
        # Overlap condition: fp_end >= target_start (fp_start <= target_end is
        # already guaranteed by the binary search boundary above).
        # Also accept unlocated findings (0, 0).
        if (
            (fp.line_range == (0, 0) or fp_end >= target_start)
            and fp.message_hash == target.message_hash
        ):
            fp_id = id(fp)
            if fp_id not in seen:
                seen.add(fp_id)
                result.append(fp)

    return result


def filter_cross_round_duplicates(
    new_findings: list[Finding],
    existing_comments: list[dict],
    spatial_lookup_threshold: int = 10,
) -> list[Finding]:
    """Filter out findings that match findings from previous rounds.

    Before posting new findings, check if any of them match findings that
    have already been posted (even in resolved threads). This prevents
    the "finding fatigue" where Vigil keeps re-flagging the same issues
    round after round.

    Uses fingerprint grouping by (file, category) for O(1) lookup and optional
    spatial lookup optimization for large candidate lists.

    Args:
        new_findings: Findings from the current review round
        existing_comments: Comments from previous rounds (fetched from GitHub,
                          includes resolved threads via fetch_all_vigil_comments)
        spatial_lookup_threshold: When candidate list exceeds this size, use
                                 binary search spatial lookup. Default 10.

    Returns:
        List of new findings, excluding those that match existing comments
    """
    if not existing_comments:
        return list(new_findings)

    # Pre-build set of existing fingerprints for O(1) lookup
    # Group by file+category for faster initial filtering
    existing_fingerprints_by_file_cat: dict[tuple[str, str], list[FindingFingerprint]] = {}
    for comment in existing_comments:
        existing_finding = extract_finding_from_comment(
            comment.get("body", ""),
            comment.get("path"),
            comment.get("line") or comment.get("original_line"),
        )
        if existing_finding:
            fp = fingerprint_finding(existing_finding)
            key = (fp.file, fp.category)
            if key not in existing_fingerprints_by_file_cat:
                existing_fingerprints_by_file_cat[key] = []
            existing_fingerprints_by_file_cat[key].append(fp)

    # Pre-sort each candidate list by line_range[0] for O(log N + k) spatial lookup
    for key in existing_fingerprints_by_file_cat:
        existing_fingerprints_by_file_cat[key].sort(key=lambda fp: fp.line_range[0])

    # Filter: keep only findings that don't match existing ones
    result = []
    for new_finding in new_findings:
        new_fp = fingerprint_finding(new_finding)
        key = (new_fp.file, new_fp.category)

        # Quick pre-filter: if file+category not in existing, keep the finding
        if key not in existing_fingerprints_by_file_cat:
            result.append(new_finding)
            continue

        # Check if this finding matches any existing one (cross-round match)
        candidates = existing_fingerprints_by_file_cat[key]

        # Use spatial lookup if candidate list is large
        if len(candidates) > spatial_lookup_threshold:
            overlapping = _find_overlapping_fingerprints(new_fp, candidates)
            is_duplicate = len(overlapping) > 0
        else:
            # Linear scan for small lists
            is_duplicate = any(
                fingerprints_match(new_fp, existing_fp, exact_line=False)
                for existing_fp in candidates
            )

        if is_duplicate:
            log.debug(
                "Skipping cross-round duplicate: %s:%s [%s] (already posted)",
                new_finding.file,
                new_finding.line,
                new_finding.category,
            )
        else:
            result.append(new_finding)

    if len(result) < len(new_findings):
        skipped = len(new_findings) - len(result)
        log.info(
            "Filtered %d cross-round duplicate(s) from %d finding(s)",
            skipped,
            len(new_findings),
        )

    return result


def build_finding_fingerprint_map(
    findings_list: list[Finding],
) -> dict[FindingFingerprint, int]:
    """Build a map of fingerprints to count of findings with that fingerprint.

    Used for detecting cross-specialist duplicates within the same round.

    Args:
        findings_list: List of findings to fingerprint

    Returns:
        dict mapping each unique fingerprint to count of findings with that fingerprint
    """
    fp_map: dict[FindingFingerprint, int] = {}
    for finding in findings_list:
        fp = fingerprint_finding(finding)
        fp_map[fp] = fp_map.get(fp, 0) + 1
    return fp_map


def find_cross_specialist_duplicates(
    specialist_findings: list[tuple[str, Finding]],
) -> dict[FindingFingerprint, list[tuple[str, Finding]]]:
    """Group findings by fingerprint to identify cross-specialist duplicates.

    When multiple specialists flag the same issue at the same location,
    this groups them together so they can be merged into a single comment.

    Args:
        specialist_findings: List of (specialist_name, finding) tuples from
                            a single review round

    Returns:
        dict mapping each fingerprint to list of (specialist, finding) that
        share that fingerprint. Entries with >1 finding are cross-specialist
        duplicates.
    """
    groups: dict[FindingFingerprint, list[tuple[str, Finding]]] = {}
    for specialist, finding in specialist_findings:
        fp = fingerprint_finding(finding)
        if fp not in groups:
            groups[fp] = []
        groups[fp].append((specialist, finding))
    return groups
