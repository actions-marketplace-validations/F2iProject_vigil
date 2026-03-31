"""Cross-specialist finding deduplication — merge overlapping findings in same round.

When multiple specialists flag the same code issue at the same location,
Vigil merges them into a single comment showing which specialists flagged it.
This prevents review spam while showing consensus.
"""

import logging
from dataclasses import dataclass
from typing import NamedTuple

from .context_manager import (
    FindingFingerprint,
    find_cross_specialist_duplicates,
    fingerprint_finding,
)
from .models import Finding, PersonaVerdict, Severity
from .utils import severity_emoji

log = logging.getLogger(__name__)


@dataclass
class VerdictInfo:
    """Verdict info for a specialist on a merged finding."""

    specialist: str
    verdict: str  # APPROVE | REQUEST_CHANGES
    category: str  # The category label this specialist used for the finding
    session_id: str = ""


class MergedFinding(NamedTuple):
    """A finding that was flagged by multiple specialists, now merged."""

    finding: Finding  # Representative finding (highest severity)
    specialists: list[str]  # List of specialist names who flagged it
    count: int  # Number of specialists who flagged it (len(specialists))
    original_findings: list[Finding]  # All original findings before merge
    verdict_info: list[VerdictInfo] = []  # Verdict details for each specialist


def merge_specialist_findings(
    verdicts: list[PersonaVerdict],
) -> tuple[list[Finding], list[MergedFinding]]:
    """Merge findings from multiple specialists, grouping overlapping issues.

    When specialists flag the same issue (same file, line, category, message),
    they're merged into a single Finding with specialist attribution.

    Args:
        verdicts: List of PersonaVerdict objects from specialists

    Returns:
        (deduped_findings, merged_info) tuple:
        - deduped_findings: List of findings with cross-specialist duplicates merged
        - merged_info: List of MergedFinding info for each merged group
    """
    # Collect all specialist findings with attribution and verdict details
    specialist_findings: list[tuple[str, Finding, PersonaVerdict]] = []
    for v in verdicts:
        for f in v.findings:
            specialist_findings.append((v.persona, f, v))

    if not specialist_findings:
        return [], []

    # Group by fingerprint
    groups = find_cross_specialist_duplicates(
        [(name, finding) for name, finding, _ in specialist_findings]
    )

    deduped_findings: list[Finding] = []
    merged_info: list[MergedFinding] = []

    # Build a lookup from (persona, finding_id) to verdict info
    verdict_lookup: dict[tuple[str, int], tuple[PersonaVerdict, Finding]] = {}
    for name, finding, verdict in specialist_findings:
        verdict_lookup[(name, id(finding))] = (verdict, finding)

    for fp, group in groups.items():
        if len(group) == 1:
            # Single specialist — keep as-is
            _, finding = group[0]
            deduped_findings.append(finding)
        else:
            # Multiple specialists — merge
            specialists = [name for name, _ in group]
            findings = [f for _, f in group]

            # Representative finding: pick highest severity
            rep_finding = max(findings, key=lambda f: _severity_rank(f.severity))

            # Build verdict info for each specialist
            verdict_infos: list[VerdictInfo] = []
            for spec_name, spec_finding in group:
                if (spec_name, id(spec_finding)) in verdict_lookup:
                    verdict, _ = verdict_lookup[(spec_name, id(spec_finding))]
                    verdict_infos.append(
                        VerdictInfo(
                            specialist=spec_name,
                            verdict=verdict.decision,
                            category=spec_finding.category,
                            session_id=verdict.session_id,
                        )
                    )

            # Preserve the representative but track the merge
            deduped_findings.append(rep_finding)
            merged_info.append(
                MergedFinding(
                    finding=rep_finding,
                    specialists=specialists,
                    count=len(specialists),
                    original_findings=findings,
                    verdict_info=verdict_infos,
                )
            )

            log.info(
                "Merged %d specialist findings: %s:%s [%s] — %s",
                len(specialists),
                rep_finding.file,
                rep_finding.line,
                rep_finding.category,
                ", ".join(specialists),
            )

    return deduped_findings, merged_info


def _severity_rank(severity: Severity) -> int:
    """Map severity to a numeric rank for comparison. Higher = more severe."""
    rank_map = {
        Severity.critical: 4,
        Severity.high: 3,
        Severity.medium: 2,
        Severity.low: 1,
    }
    return rank_map.get(severity, 0)


def format_merged_finding_comment(
    finding: Finding,
    specialists: list[str],
    session_ids: dict[str, str] | None = None,
    verdict_info: list[VerdictInfo] | None = None,
    total_specialists: int | None = None,
) -> str:
    """Format a merged finding for inline comment display.

    Shows which specialists flagged the issue with consensus table for multiple flaggers.
    Sanitizes LLM-generated content (message, suggestion, category) to prevent XSS.

    Args:
        finding: The representative Finding
        specialists: List of specialist names who flagged it
        session_ids: Optional dict mapping specialist name -> session_id (deprecated, use verdict_info)
        verdict_info: List of VerdictInfo objects with verdict details (replaces session_ids approach)
        total_specialists: Total number of specialists in the review (for consensus count)

    Returns:
        Formatted markdown for the merged finding
    """
    icon = severity_emoji(finding.severity)
    session_ids = session_ids or {}
    verdict_info = verdict_info or []

    # Sanitize LLM-generated content to prevent XSS
    sanitized_message = sanitize_markdown(finding.message)
    sanitized_suggestion = (
        sanitize_markdown(finding.suggestion) if finding.suggestion else None
    )
    sanitized_category = sanitize_markdown(finding.category)

    # Build the main finding section
    suggestion = (
        f"\n\n**Suggestion:** {sanitized_suggestion}"
        if sanitized_suggestion
        else ""
    )

    main_body = (
        f"{icon} **[{finding.severity.value.upper()}]** [{sanitized_category}]\n\n"
        f"{sanitized_message}{suggestion}"
    )

    # If only one specialist or no consensus table requested, use simple format
    if len(specialists) <= 1 or total_specialists is None:
        # Fall back to simple format with validated specialist names and session IDs
        specialist_lines = []
        for spec in specialists:
            # Validate specialist name for safe embedding
            safe_name = validate_specialist_name(spec)

            sid = session_ids.get(spec)
            # Validate session ID
            safe_sid = validate_session_id(sid) if sid else ""

            if safe_sid:
                specialist_lines.append(f"**{safe_name}** `{safe_sid}`")
            else:
                specialist_lines.append(f"**{safe_name}**")
        specialist_text = ", ".join(specialist_lines)
        return (
            f"{icon} **[{finding.severity.value.upper()}]** [{sanitized_category}]\n"
            f"🔍 Flagged by: {specialist_text}\n\n"
            f"{sanitized_message}{suggestion}"
        )

    # Build consensus table for multiple specialists
    lines = [main_body]
    lines.append("\n---\n")
    lines.append(f"📊 **Consensus ({len(specialists)}/{total_specialists} specialists)**")
    lines.append("")

    # Build table header and separator
    lines.append("| Specialist | Verdict | Ref |")
    lines.append("|------------|---------|-----|")

    # Build table rows from verdict_info if available, otherwise from specialists
    if verdict_info:
        for info in verdict_info:
            # Validate specialist name and session ID
            safe_name = validate_specialist_name(info.specialist)
            safe_sid = validate_session_id(info.session_id)

            verdict_emoji = "✅" if info.verdict == "APPROVE" else "🚫"
            session_id_str = f" `{safe_sid}`" if safe_sid else ""
            # Sanitize category field in verdict info
            safe_category = sanitize_markdown(info.category)
            lines.append(
                f"| {safe_name}{session_id_str} | {verdict_emoji} {info.verdict} | {safe_category} |"
            )
    else:
        # Fallback: use specialists list without verdict details
        for spec in specialists:
            safe_name = validate_specialist_name(spec)
            sid = session_ids.get(spec)
            safe_sid = validate_session_id(sid) if sid else ""
            session_id_str = f" `{safe_sid}`" if safe_sid else ""
            lines.append(
                f"| {safe_name}{session_id_str} | — | {sanitized_category} |"
            )

    return "\n".join(lines)


def annotate_findings_with_specialist_context(
    findings: list[Finding],
    merged_info: list[MergedFinding],
) -> list[dict]:
    """Annotate findings with specialist context for later formatting.

    Attaches metadata about which specialists flagged each finding,
    enabling formatted output to show consensus.

    Args:
        findings: The deduped findings list
        merged_info: List of MergedFinding objects

    Returns:
        List of dicts with finding + specialist metadata
    """
    # Build a lookup from finding ID to merged info
    merged_lookup: dict[int, MergedFinding] = {
        id(info.finding): info for info in merged_info
    }

    result = []
    for f in findings:
        if id(f) in merged_lookup:
            info = merged_lookup[id(f)]
            result.append({
                "finding": f,
                "is_merged": True,
                "specialists": info.specialists,
                "count": info.count,
            })
        else:
            result.append({
                "finding": f,
                "is_merged": False,
                "specialists": [],
                "count": 0,
            })
    return result
