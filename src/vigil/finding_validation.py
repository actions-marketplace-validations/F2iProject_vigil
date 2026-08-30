"""Validate findings against the content of the commit they cite (#74).

Every finding Vigil posts is stamped with the PR's head SHA, and that SHA is
written to GitHub as the review's ``commit_id``. Nothing checked that the file
and line it cites actually support the claim *at that SHA*. On
F2iLLC/LunaOS#4528 the gap produced seven CRITICAL "Cannot find namespace JSX"
findings across three pushes, each stamped with that push's correct head,
against files that already carried ``import type { JSX } from "react"`` at
every one of those commits — repo-wide CI typecheck passed the whole time. The
finding text described pre-rebase content; only the SHA was current, which is
the worst possible combination because the SHA is what makes it look verified.

This module is the guard. Its bias is asymmetric and deliberate for legacy
findings, while new structured findings add positive provenance and exact-head
check evidence:

  * A finding is suppressed ONLY on positive evidence of staleness or a
    structured current-status claim with no corroborating failed check.
  * Anything ambiguous keeps the finding — an unresolvable line, a mis-cited
    path, a message with no citable remedy, an unreadable blob, and *any* API
    failure at all.

Note what the evidence is *not*. ``suggestion`` is free-form text
(``personas.py`` asks for a ``"string or null"``), not a machine-readable
patch, so the code spans in it are a mix of the remedy and the code being
complained about. Treating all of them as the remedy inverts the guard —
the offending code is in the file precisely when the fix was *not* applied.
``_remedy_snippets`` is where that mix is narrowed down, and every filter in
it is chosen to fail toward keeping the finding. Likewise a 404 for a cited
path is not by itself proof the file is gone: it is also what a mis-typed
path looks like, which is why absence must corroborate against the diff's own
file list before it counts.

The two error directions are not comparable, so they are not weighed equally.
A finding kept in error costs a reviewer one wrong comment, visible and
arguable. A finding suppressed in error lets a real defect through a merge
gate five repositories depend on, silently, leaving nothing behind to audit.
So this fails open on every path, and it never touches
``ReviewResult.decision``: a REQUEST_CHANGES that loses every one of its
findings still posts as REQUEST_CHANGES. Suppression changes what a review
*says*, never what it does — the same line #66 draws.
"""

import logging
import re
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable

from .github import commit_is_readable, get_check_runs_for_commit, get_file_content_at_commit
from .models import Finding

log = logging.getLogger(__name__)

# Machine-stable suppression reasons. These are matched on and rendered, not
# read as prose, so they must stay stable even if the wording around them
# changes (same contract as the SKIP_* constants in models.py).
STALE_FILE_ABSENT = "file_absent_at_head"
STALE_FIX_ALREADY_PRESENT = "suggested_fix_already_present"
STALE_HISTORICAL_EVIDENCE = "historical_evidence_not_attributable_to_head"
STALE_EVIDENCE_COMMIT = "evidence_commit_does_not_match_head"
UNSUPPORTED_CURRENT_STATUS = "current_status_not_supported_by_failed_check"

_REASON_TEXT: dict[str, str] = {
    STALE_FILE_ABSENT: "the cited file does not exist at the reviewed commit",
    STALE_FIX_ALREADY_PRESENT: (
        "the change this finding asks for is already present in the file at "
        "the reviewed commit"
    ),
    STALE_HISTORICAL_EVIDENCE: (
        "the finding relies on historical conversation rather than current-head evidence"
    ),
    STALE_EVIDENCE_COMMIT: (
        "the finding's supporting commit is not the reviewed commit"
    ),
    UNSUPPORTED_CURRENT_STATUS: (
        "no completed failed check at the reviewed commit supports this status claim"
    ),
}

# A remedy snippet shorter than this, or one with no code punctuation in it,
# is prose ("use parameterized queries") rather than the literal text a fixed
# file would contain. Searching for prose in source would either never match
# or match by accident, and only the accident is dangerous — so both are
# rejected before the search happens.
_MIN_SNIPPET_CHARS = 12

# ...but a character floor alone is far too weak, because the dangerous
# snippets are short *and* punctuated. ``httpx.get(url)`` is 14 characters and
# passes the code-shape test, yet it is the code being complained about, not a
# remedy; ``requirements.txt`` clears the shape test on its lone ``.``. Both
# are present at head precisely when the finding is live, so matching on them
# suppresses exactly the findings that must survive.
#
# So a snippet must also carry enough *named* structure to be a line of code
# rather than a reference to one: at least this many DISTINCT word tokens
# (identifiers, keywords, numeric literals). Four is the smallest floor that
# separates the two populations seen in real suggestions:
#
#   rejected  ``httpx.get(url)``            → httpx, get, url                (3)
#   rejected  ``requirements.txt``          → requirements, txt              (2)
#   rejected  ``x = 1;``                    → x, 1                           (2)
#   accepted  ``import type { JSX } from "react";``
#                                → import, type, JSX, from, react            (5)
#
# The #74 shape — the JSX import — is the case this guard exists for, so the
# floor is set below it and no higher. Raising it would reopen #74; lowering
# it re-admits the bare-call and bare-filename shapes above. Both floors
# apply: a long snippet of two repeated names is no more specific than a
# short one.
_MIN_SNIPPET_TOKENS = 4

_FENCED_CODE = re.compile(r"```[\w+.-]*\r?\n(.*?)```", re.DOTALL)
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_CODE_SHAPE = re.compile(r"[=(){}\[\];:<>.]")
_WORD_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|\d+")
_WHITESPACE = re.compile(r"\s+")
_PATH_SEPARATORS = re.compile(r"[\\/]+")

# Sentinel for "this blob could not be read", kept distinct from ``None``,
# which this module reads as the much stronger claim "GitHub says there is no
# such file at this commit".
_UNREADABLE = object()
_STATUS_WORDS = re.compile(
    r"\b(?:build|compile|compiler|typecheck|tests?|ci)\b.{0,80}"
    r"\b(?:cannot|error|fail|failed|failing|failure|unresolved)\b|"
    r"\b(?:cannot|error|fail|failed|failing|failure|unresolved)\b.{0,80}"
    r"\b(?:build|compile|compiler|typecheck|tests?|ci)\b",
    re.IGNORECASE,
)
_DIAGNOSTIC = re.compile(r"\b(?:TS|CS|E|ERR_)[-_]?\d{3,}\b", re.IGNORECASE)
_FAILED_CONCLUSIONS = frozenset({
    "action_required", "cancelled", "failure", "startup_failure", "timed_out",
})


def _same_commit(left: str, right: str) -> bool:
    """Compare full or safely abbreviated commit IDs without guessing."""
    a, b = left.strip().lower(), right.strip().lower()
    if not a or not b:
        return False
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    return len(shorter) >= 7 and longer.startswith(shorter)


def _provenance_contradicts_head(finding: Finding, head_sha: str) -> str:
    """Return a suppression reason for positively stale evidence provenance.

    Legacy findings carry ``unknown`` and continue through the existing
    fail-open path.  Factual-accuracy findings are allowed to cite historical
    conversation because their predicate is a contradiction *in that
    conversation*, not an assertion that an old failure is still current.
    """
    source = finding.evidence_source.strip().lower()
    category = finding.category.strip().lower().replace("_", "-")
    if source == "historical_conversation" and category != "factual-accuracy":
        return STALE_HISTORICAL_EVIDENCE
    if (
        source in {"current_diff", "current_check"}
        and finding.evidence_commit.strip()
        and not _same_commit(finding.evidence_commit, head_sha)
    ):
        return STALE_EVIDENCE_COMMIT
    return ""


def _is_status_assertion(finding: Finding) -> bool:
    """True for claims that a compiler, build, CI, or test currently fails."""
    text = " ".join((finding.category, finding.message, finding.predicate))
    return bool(_DIAGNOSTIC.search(text) or _STATUS_WORDS.search(text))


def _failed_check_supports(finding: Finding, checks: list[dict]) -> bool:
    """Require exact failed-check output to corroborate the claimed symptom."""
    finding_text = " ".join((finding.message, finding.predicate, finding.component))
    claimed_codes = {code.upper().replace("-", "_") for code in _DIAGNOSTIC.findall(finding_text)}
    component = finding.component.strip().lower()
    component_leaf = component.replace("\\", "/").rstrip("/").split("/")[-1]

    for check in checks:
        if (check.get("status") or "").lower() != "completed":
            continue
        if (check.get("conclusion") or "").lower() not in _FAILED_CONCLUSIONS:
            continue
        output = check.get("output") or {}
        evidence = " ".join((
            str(check.get("name") or ""),
            str(output.get("title") or ""),
            str(output.get("summary") or ""),
            str(output.get("text") or ""),
        )).lower()
        evidence_codes = {
            code.upper().replace("-", "_") for code in _DIAGNOSTIC.findall(evidence)
        }
        if claimed_codes and claimed_codes.intersection(evidence_codes):
            return True
        if not claimed_codes and component_leaf and component_leaf in evidence:
            return True
    return False


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding withheld from the review, with the evidence that withheld it.

    Carried out of ``validate_findings_against_head`` rather than logged and
    forgotten: a guard that silently deletes findings from a merge gate is
    indistinguishable from the bug it fixes. Every instance of this is
    rendered into the posted review body and logged.
    """

    finding: Finding
    reason: str
    evidence: str = ""

    @property
    def reason_text(self) -> str:
        """Human-readable reason, degrading to the raw constant if unknown."""
        return _REASON_TEXT.get(self.reason, self.reason)


def _normalize(text: str) -> str:
    """Collapse all whitespace runs to single spaces, for content matching.

    Both sides of every comparison go through this, so indentation, line
    breaks and trailing whitespace cannot make a present line look absent.
    """
    return _WHITESPACE.sub(" ", text).strip()


def _distinct_word_tokens(snippet: str) -> int:
    """How many distinct identifiers/keywords/literals a snippet names."""
    return len(set(_WORD_TOKEN.findall(snippet)))


def _is_code_like(snippet: str) -> bool:
    """True when a snippet is specific enough to search source for.

    Three independent floors, all of which must hold: long enough, punctuated
    like code, and carrying at least ``_MIN_SNIPPET_TOKENS`` distinct named
    tokens. See that constant for why a character count alone is not enough.
    """
    return (
        len(snippet) >= _MIN_SNIPPET_CHARS
        and bool(_CODE_SHAPE.search(snippet))
        and _distinct_word_tokens(snippet) >= _MIN_SNIPPET_TOKENS
    )


def _remedy_snippets(finding: Finding) -> list[str]:
    """The code this finding asks for, best-effort, from ``suggestion``.

    ``suggestion`` is **not** a remedy field by construction — ``personas.py``
    asks the model for a free-form ``"string or null"``, and models routinely
    quote the current code beside the fix ("replace ``a`` with ``b``",
    "Current: … / Change to: …"). Extracting every code span from it and
    testing for presence at head therefore inverts on exactly those shapes:
    the offending code is found in the file *because the fix was never
    applied*, and a live finding is suppressed. Three filters narrow the raw
    spans down to something that can only be a remedy:

    1. **Fences: the last block only.** When a suggestion carries several
       fenced blocks the convention — in the prompt's own examples and in
       model output generally — is before-then-after, so only the final block
       can be the desired state. Earlier blocks are the code complained about.
    2. **Nothing that also appears in ``finding.message``.** A span quoted in
       both is the defect being described, not the fix for it. The message is
       already never mined directly, for the same reason; this closes the
       route by which it gets mined indirectly.
    3. **Enough code to be a line, not a reference to one** — see
       ``_is_code_like`` and ``_MIN_SNIPPET_TOKENS``.

    Every one of these can only *reduce* the snippet set, i.e. only ever keep
    a finding that would otherwise have been suppressed. That is the safe
    direction, and it is the only direction this function is allowed to move.
    """
    text = finding.suggestion or ""
    if not text.strip():
        return []

    fenced = _FENCED_CODE.findall(text)
    # (1) The remedy is the last block; anything before it is context.
    fenced = fenced[-1:]
    inline = _INLINE_CODE.findall(_FENCED_CODE.sub(" ", text))

    # (2) Same normalization on both sides, so whitespace cannot smuggle a
    # complained-about span past the comparison.
    complained_about = _normalize(finding.message or "")

    snippets: list[str] = []
    for raw in (*fenced, *inline):
        snippet = _normalize(raw)
        if not _is_code_like(snippet):
            continue
        if complained_about and snippet in complained_about:
            continue
        snippets.append(snippet)
    return snippets


def _already_applied_snippet(finding: Finding, content: str) -> str:
    """Return the remedy snippet already present at head, or "".

    Whole-file rather than near-the-cited-line, because the #74 shape is
    exactly a fix that lands somewhere other than where the finding points:
    the import goes at the top of the file, the finding cites the usage two
    hundred lines down.

    Residual false-suppression risk, stated rather than hidden: a finding that
    asks for the same change at several call sites is suppressed once any one
    of them has it. The filters in ``_remedy_snippets`` keep that to snippets
    specific enough to be meaningful, and the suppression is reported in the
    review body, so it is visible rather than silent.
    """
    haystack = _normalize(content)
    for snippet in _remedy_snippets(finding):
        if snippet in haystack:
            return snippet
    return ""


def _canonical_path(path: str) -> str:
    """Collapse the ways a model writes the same path into one form.

    Leading slashes, ``./`` prefixes and backslash separators are all shapes
    Vigil sees from models. A leading slash in particular is not cosmetic:
    ``quote(path, safe='/')`` in ``github.py`` turns ``/src/a.py`` into a
    ``contents//src/a.py`` URL, which 404s for a file that is plainly there.
    """
    collapsed = _PATH_SEPARATORS.sub("/", path.strip()).lstrip("/")
    while collapsed.startswith("./"):
        collapsed = collapsed[2:]
    return collapsed


def _path_resolves_in_diff(path: str, diff_files: Collection[str]) -> bool:
    """True when ``path`` plausibly names a file the diff actually touches.

    Deliberately the same family of matches ``diff_parser`` already uses to
    relocate a mis-cited finding (exact, suffix, basename) — and deliberately
    *not* its final "fall back to the first file in the diff" branch, which
    always succeeds and would disable absence-suppression altogether.
    """
    cited = _canonical_path(path)
    if not cited:
        return False
    cited_name = PurePosixPath(cited).name
    for known in diff_files:
        candidate = _canonical_path(known)
        if not candidate:
            continue
        if candidate == cited:
            return True
        # Wrong-prefix citations run both ways: `app.py` for `src/pkg/app.py`,
        # and `repo/src/app.py` for `src/app.py`.
        if candidate.endswith("/" + cited) or cited.endswith("/" + candidate):
            return True
        if PurePosixPath(candidate).name == cited_name:
            return True
    return False


def validate_findings_against_head(
    findings: list[Finding],
    owner: str,
    repo: str,
    head_sha: str,
    token: str,
    fetch_content: Callable[[str, str, str, str, str], str | None] | None = None,
    commit_readable: Callable[[str, str, str, str], bool] | None = None,
    diff_files: Collection[str] | None = None,
    fetch_checks: Callable[[str, str, str, str], list[dict]] | None = None,
) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Split ``findings`` into (supported, suppressed) against head tree content.

    Five things count as positive evidence that a structured finding cannot be
    posted as current, and nothing else does:

    1. ``STALE_FILE_ABSENT`` — GitHub reports no such path at ``head_sha``,
       *and* a probe confirms the commit itself is readable with this token
       (the contents API returns the same 404 for a missing path and for a
       repository the credentials cannot see), *and* the cited path cannot be
       matched to any file in ``diff_files``. All three are required: models
       mis-cite paths constantly (a missing directory prefix, a leading
       slash), and a mis-cited path on a live defect 404s exactly like a
       hallucinated one. Vigil already repairs that shape downstream —
       ``diff_parser.find_best_file_for_finding`` relocates the comment — so
       suppressing here would be dropping a real finding over a typo, and
       would do it before the repair ever ran.
    2. ``STALE_FIX_ALREADY_PRESENT`` — a code span from the finding's own
       ``suggestion`` that can only be the remedy (see ``_remedy_snippets``
       for how narrowly that is drawn, and why it has to be) is already in
       the file at ``head_sha``.

    3. ``STALE_HISTORICAL_EVIDENCE`` - a structured finding says its only
       source is historical conversation (except factual-accuracy findings,
       whose subject is the conversation itself).
    4. ``STALE_EVIDENCE_COMMIT`` - structured current evidence names a commit
       other than the reviewed head.
    5. ``UNSUPPORTED_CURRENT_STATUS`` - a structured build/test/status claim
       has no completed failed exact-head check whose output supports its
       diagnostic or affected component.

    Everything else keeps the finding, including several things that look like
    evidence and are not. A cited line past end-of-file is **not** grounds for
    suppression: it says the citation is misplaced, which Vigil already
    tolerates and repairs (``_place_finding_inline`` relocates findings to the
    nearest commentable line), and says nothing about whether the defect
    exists somewhere else in the file. Suppressing on it would drop real
    findings over an off-by-N line number, which models produce constantly.

    Args:
        findings: The findings about to be posted. Not mutated.
        owner: Repository owner.
        repo: Repository name.
        head_sha: The exact commit the findings are stamped with. An empty
            SHA disables validation entirely — there is nothing to check
            against, and guessing a ref would defeat the point.
        token: GitHub API token.
        fetch_content: Seam for the blob fetch, defaulting to
            ``github.get_file_content_at_commit``. Returns the file's text, or
            None when GitHub reports the path absent at that ref.
        commit_readable: Seam for the corroborating probe, defaulting to
            ``github.commit_is_readable``.
        diff_files: The paths this PR's diff actually touches, as
            ``commentable_lines`` reports them. Optional, and its absence is
            never read as evidence: with no file set (or an empty one) there
            is nothing to distinguish a mis-cited path from a hallucinated
            one, so no finding is suppressed for file-absence at all.
        fetch_checks: Seam for exact-head check runs. An API exception keeps
            status findings unvalidated (fail open); an available empty or
            pending set positively cannot support a current failure claim.

    Returns:
        ``(supported, suppressed)``. ``supported`` preserves input order and
        contains the same objects (identity is what the caller rebuilds
        verdicts by). ``suppressed`` carries each withheld finding with the
        reason and the evidence for it.
    """
    if not findings or not head_sha:
        return list(findings), []

    fetch = fetch_content or get_file_content_at_commit
    readable = commit_readable or commit_is_readable
    check_fetcher = fetch_checks or get_check_runs_for_commit

    # Materialized once: the caller may hand over a view (``dict.keys()``)
    # that is cheap to iterate but is walked once per absent file.
    known_files: tuple[str, ...] = tuple(diff_files or ())

    # Per (path, sha), so a review with a dozen findings in one file costs one
    # blob fetch. Deliberately call-scoped, not module-level: a cache that
    # outlived the call would serve one PR's head content to another run.
    cache: dict[tuple[str, str], object] = {}
    head_readable: bool | None = None
    head_checks: list[dict] | object = _UNREADABLE
    checks_loaded = False

    supported: list[Finding] = []
    suppressed: list[SuppressedFinding] = []

    for finding in findings:
        provenance_reason = _provenance_contradicts_head(finding, head_sha)
        if provenance_reason:
            suppressed.append(
                SuppressedFinding(
                    finding,
                    provenance_reason,
                    finding.evidence_commit or finding.evidence_source,
                )
            )
            continue
        if _is_status_assertion(finding) and finding.evidence_source in {
            "current_diff", "current_check",
        }:
            if not checks_loaded:
                checks_loaded = True
                try:
                    head_checks = check_fetcher(owner, repo, head_sha, token)
                except Exception as e:  # noqa: BLE001 - validation API failures fail open
                    log.warning(
                        "Could not read checks at %s (%s: %s) - keeping status "
                        "findings unvalidated",
                        head_sha[:7], type(e).__name__, e,
                    )
                    head_checks = _UNREADABLE
            if head_checks is not _UNREADABLE and not _failed_check_supports(
                finding, head_checks,
            ):
                suppressed.append(SuppressedFinding(
                    finding, UNSUPPORTED_CURRENT_STATUS, head_sha,
                ))
                continue
        key = (finding.file, head_sha)
        if key not in cache:
            try:
                cache[key] = fetch(owner, repo, finding.file, head_sha, token)
            except Exception as e:  # noqa: BLE001 — never fail a review over validation
                # Network failure, 403, rate limit, revoked token: all of them
                # mean "unverified", and unverified keeps the finding. The
                # cache holds the failure too, so an outage costs one call per
                # file rather than one per finding.
                log.warning(
                    "Could not read %s at %s (%s: %s) — keeping the finding "
                    "unvalidated",
                    finding.file, head_sha[:7], type(e).__name__, e,
                )
                cache[key] = _UNREADABLE

        content = cache[key]

        if content is _UNREADABLE:
            supported.append(finding)
            continue

        if content is None:
            # A 404 on the literal cited path is not on its own evidence that
            # the file is gone — it is equally the signature of a path the
            # model got slightly wrong. Only a path with no counterpart
            # anywhere in the diff is evidence of anything.
            if not known_files or _path_resolves_in_diff(finding.file, known_files):
                supported.append(finding)
                continue
            if head_readable is None:
                try:
                    head_readable = readable(owner, repo, head_sha, token)
                except Exception as e:  # noqa: BLE001 — same fail-open contract
                    log.warning(
                        "Could not confirm %s is readable (%s: %s) — treating "
                        "every absent-file result as unverified",
                        head_sha[:7], type(e).__name__, e,
                    )
                    head_readable = False
            if not head_readable:
                supported.append(finding)
                continue
            suppressed.append(
                SuppressedFinding(finding, STALE_FILE_ABSENT, finding.file)
            )
            continue

        if not isinstance(content, str) or "\x00" in content:
            # A binary blob is not something a line-and-content claim can be
            # checked against. Unverified, so kept.
            supported.append(finding)
            continue

        snippet = _already_applied_snippet(finding, content)
        if snippet:
            suppressed.append(
                SuppressedFinding(finding, STALE_FIX_ALREADY_PRESENT, snippet)
            )
            continue

        supported.append(finding)

    for item in suppressed:
        log.info(
            "Suppressed finding at %s:%s [%s] — %s (evidence: %s)",
            item.finding.file, item.finding.line, item.finding.category,
            item.reason, item.evidence,
        )

    return supported, suppressed
