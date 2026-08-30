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
    # Machine-readable review evidence.  These fields are optional for
    # backwards compatibility with older model responses and persisted
    # comments, but new prompts require them.  They let deterministic review
    # stages distinguish a current-head assertion from a claim copied out of
    # historical PR discussion.
    component: str = ""
    predicate: str = ""
    evidence_source: str = "unknown"
    evidence_commit: str = ""


# Machine-stable values for PersonaVerdict.skip_reason (F2iLLC/vigil#66).
# These are contract, not prose: they are matched on, not read, so they must
# stay stable even if the words Vigil renders around them change.
SKIP_NO_FILES_IN_SCOPE = "no_files_in_scope"
SKIP_REVIEWER_UNAVAILABLE = "reviewer_unavailable"
# A specialist that can only review against material from outside the PR (a
# governing spec, plan, or requirement set) and did not receive any. It must
# skip rather than review: with no spec to check against, the only honest
# output is "unexamined". Answering anyway would mean judging conformance
# against the PR's own description, which is what having no spec looks like.
SKIP_NO_EXTERNAL_CONTEXT = "no_external_context"


# ---------- Aggregate review decisions ----------

# The verdicts that actually block a merge. Lives here rather than in
# github_review so the review engine and the posting layer read one definition
# (F2iLLC/vigil#79); ``github_review`` re-exports the name it has always
# exported.
BLOCKING_DECISIONS = frozenset({"REQUEST_CHANGES", "BLOCK"})

# The aggregate decision for a review in which NO specialist ran (#79).
#
# It is deliberately neither APPROVE nor a blocking verdict. A review where
# every specialist was skipped is not an approval — it is the absence of one —
# and emitting APPROVE there satisfied the org ruleset's required-approval rule,
# so a PR touching only unscoped files merged with zero review
# (F2iLLC/LunaOS#5028). It is equally not REQUEST_CHANGES: nothing was examined,
# so there is nothing to object to, and blocking would fail closed on every
# diff no persona happens to scope.
#
# It maps to a GitHub COMMENT event, which is the exact semantics wanted:
# the review still posts and still says everything it has to say, but it does
# not count as an approval toward a required-approval rule. This closes the
# whole class — including the next file extension nobody thought to add.
DECISION_NOT_REVIEWED = "NOT_REVIEWED"


class PersonaVerdict(BaseModel):
    """One specialist reviewer's structured verdict.

    ``reviewed`` records whether a model was actually asked. Vigil
    synthesizes an APPROVE verdict for a specialist that never ran — no
    files matched its patterns, or its model call failed transiently — and
    every consumer downstream rendered those exactly like a specialist that
    read the diff and found nothing. A verdict table implies verdicts were
    reached (F2iLLC/vigil#66): a table of green rows was taken by two
    automated readers as evidence of a review that had made zero model
    calls. The flag exists so the *reporting* layer can tell the two apart.

    It is deliberately not consulted by any gating logic. ``decision``
    remains the only input to ``is_blocking_decision()`` and to the lead's
    aggregation, so a synthesized APPROVE still does not block a merge —
    this changes what Vigil says, never what it does.

    ``reviewed`` defaults to True so verdicts parsed from model JSON (the
    only ones that did run) are unaffected and every existing construction
    site keeps its meaning. ``skip_reason`` carries one of the SKIP_*
    constants above whenever ``reviewed`` is False.
    """

    persona: str
    session_id: str = ""  # e.g. "VGL-a3f8b2" — unique per specialist run
    decision: str  # APPROVE | REQUEST_CHANGES
    checks: dict[str, str]  # e.g. {"input_validation": "PASS", "injection_prevention": "CONCERN"}
    findings: list[Finding]
    observations: list[Finding]  # non-blocking notes (should become issues per CR-002)
    reviewed: bool = True  # False => no model call was made for this specialist
    skip_reason: str = ""  # one of the SKIP_* constants when reviewed is False


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
