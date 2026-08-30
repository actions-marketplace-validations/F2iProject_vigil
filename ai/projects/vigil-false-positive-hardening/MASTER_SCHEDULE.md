# Vigil false-positive hardening master schedule

Tracking issue: [F2iLLC/vigil#77](https://github.com/F2iLLC/vigil/issues/77)

## Delivery sequence

| Milestone | Objective | Dependencies | Status | Exit gate |
| --- | --- | --- | --- | --- |
| VFP-01 | Stop stale evidence amplification, deduplicate equivalent findings, and prevent unrelated inline relocation | Vigil `main` including #75 | Completed | Deterministic LunaOS #4761 replay and focused regression suite pass |

Completion evidence: implementation `e1e2cb7`; report `c4f6b69`; 379 focused tests and 819 non-Bash tests passed. The 33 remaining full-suite failures require a usable Bash/WSL and `python3` runtime and are unchanged release/guard tests.

## Integration constraints

- Keep review findings attributable to the current pull-request head.
- Preserve fail-loud behavior for genuine actionable findings and infrastructure failures.
- Never attach a missing or non-inlineable finding to an unrelated file merely to make it commentable.
- Use deterministic fixtures for the LunaOS #4761 replay; the acceptance test must not call an LLM or GitHub.
- Do not mark issue #77 resolved until the implementation is merged and effectiveness evidence is available.

## Rollback trigger

Revert the implementation if it suppresses a current-head actionable finding, changes blocking behavior without an explicit verdict, or emits a comment on a file unrelated to the finding.
