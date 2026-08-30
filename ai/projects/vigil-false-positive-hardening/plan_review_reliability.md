# VFP-01: Review reliability corrective action

## Problem

LunaOS pull request #4761 accumulated 37 Vigil review threads across seven heads. Thirty threads repeated the same writing-style/TypeScript symptom after the underlying configuration was fixed. Stale conversation text, parallel specialist output, full-diff re-review, location-sensitive deduplication, and fallback comment relocation combined into a false-positive feedback loop.

The complete evidence, root-cause analysis, and corrective-action hierarchy are recorded in [F2iLLC/vigil#77](https://github.com/F2iLLC/vigil/issues/77).

## Scope

Implement one coherent control path that:

1. distinguishes historical conversation evidence from current-head source evidence;
2. rejects or downgrades findings whose factual predicate is contradicted by the current head;
3. semantically deduplicates equivalent findings across specialists and review rounds;
4. refuses to relocate an unplaceable finding to an unrelated file;
5. prevents duplicate observation issues for the same underlying problem; and
6. proves the behavior with a deterministic replay derived from LunaOS #4761.

## Expected implementation areas

- `src/vigil/context_manager.py` and `src/vigil/reviewer.py` for provenance and current-head review context.
- `src/vigil/finding_validation.py` for evidence validation.
- `src/vigil/cross_specialist_dedup.py` and `src/vigil/comment_manager.py` for semantic deduplication and safe placement.
- `src/vigil/issue_manager.py` for observation-issue identity.
- Focused tests under `tests/`, including a deterministic #4761 replay fixture.

The implementer may choose a smaller or different file set when repository evidence supports it, but must document that decision in the completion report.

## Acceptance criteria

- The replay models seven successive heads and the historical build-failure comment from LunaOS #4761.
- The initial real defect may produce one actionable finding; equivalent specialist findings collapse to one canonical finding.
- Once the fixing head is present, the historical failure text cannot create a new blocking finding.
- Re-running the same head produces no new review thread or observation issue.
- Findings without a valid changed-file location are summarized without an unrelated inline anchor.
- Equivalent wording across different specialists, line numbers, and rounds is treated as the same finding when its normalized predicate and affected component match.
- Distinct actionable findings are not collapsed merely because they share a category.
- Existing current-head commit validation from #75 remains effective.
- Infrastructure/API failures retain explicit fail-loud behavior.
- Focused and full automated test suites pass.
- The completion report records changed files, commands, results, residual risks, and follow-up effectiveness checks.

## Verification

Run the narrow replay/deduplication/current-head tests first, then the repository's full documented test suite. No acceptance evidence may depend on a live GitHub mutation or an LLM response.

## Effectiveness checks after merge

- On three multi-round PRs, no fixed predicate reappears as a new blocking finding after a green fixing head.
- Duplicate-thread rate is at most one canonical thread per normalized predicate/component.
- No inline comment is posted on a file unrelated to its source evidence.
- Genuine seeded findings continue to block exactly once.
