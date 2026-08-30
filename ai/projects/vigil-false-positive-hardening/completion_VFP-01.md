# VFP-01 completion report

## Outcome

Implemented the review-reliability corrective action tracked by
[F2iLLC/vigil#77](https://github.com/F2iLLC/vigil/issues/77). Structured
current-head provenance, exact-head check evidence, stable semantic finding
identity, safe inline placement, and deterministic replay coverage now form one
control path.

Implementation commit: `e1e2cb7`

## Changed files

- `src/vigil/models.py` and `src/vigil/personas.py`: added optional structured
  component, predicate, evidence source, and evidence commit fields while
  retaining compatibility with old model output.
- `src/vigil/comment_manager.py`, `src/vigil/cli.py`, and
  `src/vigil/reviewer.py`: label conversation items with source/commit/current
  head attribution and carry the authoritative head policy into every prompt.
- `src/vigil/github.py` and `src/vigil/finding_validation.py`: fetch exact-head
  check runs; reject historical/mismatched evidence and current build/test
  claims that an available completed failed check does not support. API failure
  continues to keep the finding and log the validation failure.
- `src/vigil/context_manager.py` and
  `src/vigil/cross_specialist_dedup.py`: define one component + predicate key
  used across personas, categories, wording, locations, and rounds. Legacy
  comments keep the former conservative fingerprint fallback.
- `src/vigil/github_review.py`: embed the semantic key in comment metadata,
  submit stale-only blocking verdicts as nonblocking `COMMENT`, and allow only
  exact/same-file or unique suffix/basename path repair. Unplaceable findings
  stay in the review body.
- `src/vigil/issue_manager.py`: persist and reuse the same semantic key for
  observation issues, including duplicates encountered in one run.
- `tests/test_false_positive_replay.py`: deterministic seven-head LunaOS #4761
  replay with no live GitHub or LLM calls.

## Design decisions

1. Provenance fields are optional. Findings created before this change remain
   fail-open; new structured findings receive deterministic validation.
2. A current build/test/compiler failure requires a completed failed check on
   the exact reviewed SHA whose output names the diagnostic or affected
   component. Pending, green, or empty available check sets cannot support the
   claim.
3. A check API failure is not interpreted as an empty check set. The finding is
   retained and the outage is logged, preserving fail-loud behavior.
4. Stable identity is based on affected component plus defect predicate, not
   persona, category, message wording, line number, or inline anchor. Diagnostic
   codes provide a compatibility identity for older findings.
5. Only new provenance/status suppression reasons can turn a stale-only
   `REQUEST_CHANGES` into `COMMENT`. Existing #75 file/remedy suppression keeps
   its established decision behavior.
6. Comment placement repairs only an unambiguous spelling/prefix mismatch. It
   never falls back to an unrelated changed file.

## Verification

Focused replay and affected regressions:

```text
python -c "... pytest.main([tests/test_false_positive_replay.py, tests/test_context_manager.py,
tests/test_cross_specialist_dedup.py, tests/test_comment_manager.py,
tests/test_issue_manager.py, tests/test_finding_validation.py,
tests/test_nonblocking_no_inline_threads.py, tests/test_reviewer.py, -q])"
379 passed in 3.33s
```

All Python tests not dependent on a local Bash runtime:

```text
pytest -q --ignore=tests/test_fail_loudly_guard.py --ignore=tests/test_release_tooling.py
819 passed in 5.77s
```

Complete repository invocation:

```text
pytest -q
826 passed, 33 failed in 24.16s
```

All 33 failures are confined to unchanged shell/release tests. On this Windows
host, `bash` resolves to a nonfunctional WSL launcher (`/bin/bash` missing) and
`python3` resolves to the Microsoft Store alias. The focused suite and every
test not requiring those unavailable executables pass. `compileall` and
`git diff --check` also pass.

## Acceptance-criteria mapping

- Seven heads plus the historical TS2591 comment: `HEADS` and provenance test.
- One initial real defect and one canonical specialist finding: initial-head
  validation plus six-specialist merge test.
- No later historical blocker: six later heads are withheld before any blob or
  network lookup; stale-only review event is `COMMENT`.
- Same-head rerun idempotency: stable metadata deduplicates across changed
  anchors; issue identity reuses one URL within and across rounds.
- No unrelated inline anchor: unplaceable replay finding returns `None` and is
  routed to the review body.
- Equivalent wording/category/line/round identity: stable component + predicate
  tests.
- Distinct findings stay distinct: Node-type and Docker-context predicates have
  different keys.
- Current-head #75 behavior: existing finding-validation regression suite passes.
- Pending CI cannot be called failed; completed failed exact-head evidence can
  support one defect; check API failure keeps the defect fail-loud.

## Residual risks

- Structured provenance is produced by the model. Deterministic validation
  catches explicit historical/mismatched claims, but legacy or malformed output
  intentionally remains fail-open.
- Generic findings without a structured predicate use a conservative lexical
  compatibility key and may deduplicate less aggressively than new findings.
- Check-run output can be sparse. A real current compiler failure with no
  diagnostic/component in the check output will be reported as withheld rather
  than blocking; the review body records the reason for operator inspection.
- Shell-only repository tests require a Linux/Git-Bash CI runner for complete
  execution evidence.

## Post-merge effectiveness checks

1. Replay LunaOS #4761 and confirm one TS2591 defect at the first affected head,
   zero TS2591 blockers after the overlay, one Docker-context predicate, and no
   blockers on the green heads.
2. Observe three multi-round PRs and require at most one thread and one issue per
   component/predicate key.
3. Audit inline comments for unrelated source paths; the expected count is zero.
4. Seed one genuine exact-head failed-check finding and confirm it blocks once.
5. Run the complete suite on Linux/GitHub Actions to close the local shell-runtime
   evidence gap.
