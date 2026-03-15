"""Data models for review findings and results."""

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Finding(BaseModel):
    file: str
    line: int | None = None
    severity: Severity
    category: str
    message: str
    suggestion: str | None = None


class PersonaVerdict(BaseModel):
    """One specialist reviewer's structured verdict."""

    persona: str
    session_id: str = ""  # e.g. "VGL-a3f8b2" — unique per specialist run
    decision: str  # APPROVE | REQUEST_CHANGES
    checks: dict[str, str]  # e.g. {"input_validation": "PASS", "injection_prevention": "CONCERN"}
    findings: list[Finding]
    observations: list[Finding]  # non-blocking notes (should become issues per CR-002)


class ReviewResult(BaseModel):
    """Aggregated result from all reviewers + lead."""

    decision: str  # APPROVE | REQUEST_CHANGES | BLOCK
    summary: str
    commit_sha: str = ""  # HEAD commit SHA at time of review
    pr_url: str = ""  # GitHub PR URL
    model: str = ""  # LLM model used for specialists
    specialist_verdicts: list[PersonaVerdict]
    lead_findings: list[Finding]  # lead reviewer's own findings (scope, conventions, etc.)
    observations: list[Finding]  # all non-blocking observations aggregated
    observation_sources: list[tuple[str, Finding]] = []  # (persona_name, finding) for issue creation
