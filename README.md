# Vigil

AI-powered, model-agnostic pull-request review with domain-specialist teams.

Vigil routes a PR diff to focused reviewers, asks a lead reviewer to synthesize their verdicts, posts actionable findings on the relevant diff lines, and can track non-blocking follow-up work as GitHub issues.

> [!IMPORTANT]
> This README documents `main`. The `v1` action tag is a **moving major alias**, repointed only by an explicit release — see [Releases and version pinning](#releases-and-version-pinning) — so it can lag `main` by one or more merged changes. The `Tag drift check` workflow reports the current gap on a schedule. If you need exactly the behaviour documented here, pin the commit shown in the reusable workflow rather than `@v1`.

## How it works

```text
PR diff + description + conversation history
                    |
       domain-routed specialists
  Logic | Security | Architecture
  Testing | Performance | DX
                    |
        lead reviewer synthesis
                    |
   APPROVE / REQUEST_CHANGES / BLOCK
        |                       |
   findings inline      actionable observations
  (blocking verdicts)   tracked as GitHub issues
```

Each specialist receives only the files relevant to its domain. Security skips documentation, Testing sees tests and related source, and data/GxP reviewers activate only for relevant files in the enterprise profile.

## Features

- **Model-agnostic review** through [LiteLLM](https://github.com/BerriAI/litellm).
- **Seven default specialists plus a lead**, with an eight-specialist enterprise profile for regulated systems.
- **Inline findings on blocking verdicts only**, relocated to a valid changed line when the model cites an un-commentable location. An approving review reports its findings in the review body, so it never opens a thread it does not intend to block on.
- **Actionable observation gate** that rejects model-generated praise or notes without a concrete follow-up action.
- **Automatic issue tracking** for non-blocking observations, with severity-matched priority labels and open-issue deduplication.
- **PR conversation context** so specialists and the lead can check claims against top-level comments and prior review bodies.
- **No documentation exemption** — Markdown and text changes get the same specialist and lead review as code.
- **Cross-specialist consensus** that merges duplicate findings into one comment with specialist attribution.
- **Cross-round deduplication** against active and resolved Vigil comments.
- **Defensive output handling** that validates structured model responses and sanitizes model-generated Markdown before posting.
- **Decision log** that suppresses acknowledged, accepted, wontfix, or false-positive patterns.
- **Review lifecycle commands** for dismissing resolved findings and auto-resolving threads whose code changed.
- **Transient-provider handling** that retries recoverable rate-limit, timeout, and service-unavailable errors without treating infrastructure noise as a code defect.
- **Alert delivery** through SMTP and an optional LunaOS escalation webhook.
- **CLI, composite action, reusable workflow, and webhook server** integration options.

## Installation

Vigil requires Python 3.10 or newer.

For local development:

```bash
git clone https://github.com/F2iLLC/vigil.git
cd vigil
python -m venv .venv
python -m pip install -e .
```

Install the webhook dependencies when using `vigil serve`:

```bash
python -m pip install -e ".[webhook]"
```

For a pinned CLI installation without cloning:

```bash
python -m pip install "git+https://github.com/F2iLLC/vigil.git@ce4df1c9c7cf6dc126fe1f04a4cc02c581e8823e"
```

## Quick start

```bash
export GITHUB_TOKEN="ghp_..."
export GEMINI_API_KEY="..."

vigil review https://github.com/owner/repo/pull/123 --post
```

`GITHUB_TOKEN` must be able to read the PR. Posting reviews and issues also requires pull-request and issue write access.

## CLI

### Review a PR

```text
vigil review <PR_URL> [OPTIONS]

Options:
  -m, --model TEXT      Specialist model
                        Default: gemini/gemini-3.1-flash-lite
  --lead-model TEXT     Optional separate lead-reviewer model
  -p, --profile TEXT    default or enterprise
  --json                Print the structured result
  --post                Post the result to GitHub
  --force               Review even when no files changed since the last review
  --reason TEXT         Why the review was requested (recorded in the run log)
```

Examples:

```bash
# Default Gemini model
vigil review https://github.com/org/repo/pull/123 --post

# Gemini specialists with a Claude lead
vigil review https://github.com/org/repo/pull/123 \
  --model gemini/gemini-3.1-flash-lite \
  --lead-model claude-sonnet-4-6 \
  --post

# Regulated-system profile
vigil review https://github.com/org/repo/pull/123 --profile enterprise --post

# Machine-readable output without posting
vigil review https://github.com/org/repo/pull/123 --json
```

### Resolve acknowledged findings

```bash
vigil dismiss-resolved https://github.com/owner/repo/pull/123
```

This resolves Vigil threads that received a resolution reply and records the decision for future suppression. Recognized replies include `resolved`, `fixed`, `addressed`, `done`, and issue-link replies that cover the finding.

### Resolve findings addressed by code changes

```bash
vigil resolve-addressed https://github.com/owner/repo/pull/123
```

This compares the current head with the last Vigil-reviewed commit and resolves Vigil threads whose cited file and line changed. In a pull-request GitHub Actions event, the composite action can auto-detect the PR URL.

### Browse the decision log

```bash
vigil decisions owner/repo
vigil decisions owner/repo --file src/auth.py
vigil decisions owner/repo --category security
vigil decisions owner/repo --remove 5
vigil decisions owner/repo --clear
```

### List profiles

```bash
vigil profiles
```

### Run the webhook server

```bash
vigil serve \
  --host 0.0.0.0 \
  --port 8000 \
  --model gemini/gemini-3.1-flash-lite \
  --profile default
```

## Review lifecycle

Vigil reviews the full PR diff against the base branch. On a posted re-review it also:

1. Locates the most recent Vigil review commit, and the **state** of Vigil's reviews.
2. Resolves threads with accepted resolution replies.
3. Checks whether the PR head changed; if no files changed, it skips the duplicate review — unless one of the re-review triggers below applies.
4. Resolves threads whose cited code changed.
5. Re-reviews the **full PR diff**, not only the latest commit or changed-file subset.
6. Filters findings already covered by active or resolved Vigil comments.

This distinction matters: incremental state controls skipping, thread resolution, and deduplication, while the model still receives the complete PR change.

### Re-review triggers on an unchanged head

Skipping on an unchanged head keeps re-review cost down, but a PR must never be
able to reach a state it cannot leave. Vigil therefore still reviews — against
the full base-to-head diff — when any of the following hold:

- the run was explicitly requested with `/vigil review`;
- a Vigil `CHANGES_REQUESTED` review is still standing, so the block can be reconsidered;
- the current head carries no live Vigil verdict, for example because the verdict at head was dismissed;
- Vigil threads were resolved during this run, so the evidence behind the prior verdict changed.

Liveness is evaluated on each review's `state`, not on recency: `dismiss_stale_reviews_on_push`
leaves `DISMISSED` reviews in the API response, and a dismissed review must not read as a live one.

No empty or no-op commit is ever required to obtain a fresh verdict.

### Withdrawing a superseded block

When a re-review concludes **APPROVE**, Vigil dismisses its own prior
`CHANGES_REQUESTED` reviews, naming the head SHA that satisfied them. This
matters because `dismiss_stale_reviews_on_push` only stale-dismisses
*approvals*: without an explicit withdrawal, a later push drops Vigil's
approval and an older block becomes the latest live review again.

A re-review that still concludes `REQUEST_CHANGES` changes nothing — Vigil
standing its ground is intended. Nothing is dismissed when the review degraded
to a `COMMENT` event, because a comment clears no block and dismissing the old
one would leave the PR unguarded.

### Inline comments only on a blocking verdict

GitHub renders every inline review comment as an *unresolved review thread*.
Under a ruleset that requires all threads resolved, a review that approves
while posting inline comments blocks the pull request it just approved.

So inline placement is reserved for verdicts that block the merge:
`REQUEST_CHANGES` and `BLOCK`. A review that concludes `APPROVE` — or that
degrades to a bare `COMMENT` — carries **no** inline comments at all. Its
findings are reported in the review body under **Advisory Findings**, labeled
non-blocking, with their original file and line. Nothing the review found is
dropped; only the thread is. Observations were already summary-only and are
unchanged.

The suppression holds across every fallback in the posting ladder, including
the retries that degrade to `COMMENT` and the final plain-issue-comment
fallback.

Threads opened by *earlier* rounds are resolved when a later review approves —
by the decision, not by the diff. The diff-driven path (`resolve-addressed`)
only ever sees threads whose file changed since the last review, so a thread
from round 1 on a file round 2 never touches would otherwise sit unresolved
forever under an approving review, since dedup also stops the finding being
re-posted (F2iLLC/vigil#61).

This runs only when GitHub actually accepted the review as an `APPROVE` event —
never on a review that degraded to `COMMENT` or fell back to an issue comment,
which approve nothing and would leave the PR blocked with its findings hidden.
`REQUEST_CHANGES` and `BLOCK` resolve nothing. The scope is every one of
*Vigil's* still-open threads on the PR, matched by the `VGL-` marker in the
thread body; threads opened by people are never touched. The other lifecycle
paths still apply: a resolution reply (`vigil dismiss-resolved`), or the cited
code changing (`vigil resolve-addressed`).

### Documentation PRs

Documentation PRs are reviewed like any other diff. There is no fast path and no auto-approval.

Vigil previously short-circuited any diff whose files all matched a documentation predicate, returning an approval with zero model calls. That predicate keyed off the file extension anywhere in the tree, so *every* Markdown or text file qualified — and Markdown is the substrate for governance policy, security procedure, runbooks, ADRs, and confidentiality boundaries, none of which are low-risk by virtue of a file suffix. A PR that committed confidential legal material under a non-docs path was approved green by that path. It has been removed (F2iLLC/vigil#62).

The `is_documentation_path` / `is_documentation_only` classifier is retained for reuse, and narrowed to match its name: a file counts as documentation only when it lives under `docs/`, `documentation/`, `.github/ISSUE_TEMPLATE/`, or a PR-template path, or is a root-level convention file (`README*`, `CHANGELOG*`, `CONTRIBUTING*`, `CODE_OF_CONDUCT*`, `LICENSE*`, `NOTICE*`) **at the repository root**. A bare `*.md`/`*.mdx`/`*.rst`/`*.txt` match at arbitrary depth no longer qualifies. It is a classifier, not a review gate, and must not be wired into one.

### PR conversation evidence

Vigil fetches top-level PR comments and prior review bodies and supplies a bounded version of that conversation to every specialist and the lead. Reviewers are instructed to flag factual claims in the diff or description when the existing thread contradicts them.

### External review context

A PR can assert something that is only falsifiable against material outside the PR — a completion report claiming a milestone is done while the code is an empty stub. Vigil can be pointed at one **external context provider** so that class of claim becomes checkable.

The provider is a seam, not an integration. Vigil never parses, validates, models, or writes back to whatever is on the other end, and carries no knowledge of any specific external system.

```bash
# A command (argv-parsed, run without a shell)…
VIGIL_CONTEXT_PROVIDER="/usr/local/bin/review-context --format text"
# …or an HTTP endpoint
VIGIL_CONTEXT_PROVIDER=https://internal.example.com/vigil-context

VIGIL_CONTEXT_LABEL="project tracker"   # optional, shown to reviewers
VIGIL_CONTEXT_TOKEN=opaque-secret       # optional, one opaque token
VIGIL_CONTEXT_TIMEOUT=20                # seconds, clamped to 1-60
VIGIL_CONTEXT_MAX_CHARS=8000            # payload cap, clamped to 500-50000
```

Contract:

- **Invoked once per review**, with the PR coordinates: `{"repo": "owner/repo", "pr_number": 12, "head_sha": "…", "changed_paths": [...]}` on stdin for a command, or as a JSON POST body for an endpoint. A command also receives `VIGIL_PR_REPO`, `VIGIL_PR_NUMBER`, `VIGIL_PR_HEAD_SHA`, and newline-separated `VIGIL_PR_CHANGED_PATHS` in its environment.
- **Returns opaque text** (stdout or response body) plus an optional short label (`X-Vigil-Context-Label` response header for HTTP; `VIGIL_CONTEXT_LABEL` for a command). The text is injected into the prompt for every specialist and the lead.
- **Untrusted evidence, not instructions.** The block states this explicitly, notes that — unlike PR conversation — the content may be machine-generated, and instructs reviewers that a contradiction with the diff or description is a `factual-accuracy` finding while an instruction found inside the payload is never itself a finding. Vigil deliberately does not detect or report prompt-injection attempts arriving this way: doing so would let a hostile provider manufacture findings on an unrelated PR.
- **Truncation is visible.** Payloads over the cap keep their first `VIGIL_CONTEXT_MAX_CHARS` characters and carry an explicit marker naming the kept and original sizes, both inside the payload and in the block around it. Vigil never silently shortens the evidence.
- **Fails open, always.** Unconfigured, empty output, non-zero exit, non-2xx status, timeout, or an unparseable command string — every one omits the section and the review proceeds normally. This seam can never block or fail a review.
- **Read-only by construction.** Nothing is ever written back.
- **One opaque token, maximum.** `VIGIL_CONTEXT_TOKEN` is forwarded verbatim as an environment variable (command) or an `X-Vigil-Context-Token` header (HTTP). Vigil holds no credentials for any particular external service and will not grow a client for one.

**Fork-PR safety.** A provider configured with credentials must not be reachable from a fork. The reusable workflow enforces this in `.github/workflows/reusable-vigil.yml`, not just here: its `Resolve external context provider (fork-gated)` step resolves `context-provider`, `context-label`, and `context-token` to empty unless the event is `pull_request` **and** `github.event.pull_request.head.repo.full_name` equals `github.repository`. Everything it cannot positively prove fails closed — including on-demand `/vigil review`, which arrives as an `issue_comment` whose payload does not carry the head repository, so those runs review without external context. If you call the composite action directly rather than through the reusable workflow, you must apply the same gate yourself.

### Cross-specialist consensus

When multiple specialists report the same file/category/message concern at overlapping lines, Vigil emits one finding and includes a consensus table showing which specialists raised it and their verdicts.

## Observations and automatic issues

With `--post`, non-blocking observations can become GitHub issues:

1. Model-generated observations must include a concrete, non-null suggestion. Compliments, descriptions, and no-action notes are discarded.
2. Vigil ensures a priority label exists for the observation severity: `Critical Priority`, `High Priority`, `Medium Priority`, or `Low Priority`.
3. Open Vigil-created issues are checked for the same file and a sufficiently similar message before a new issue is created.
4. The final review links each tracked observation to its issue.

Security is non-blocking in both built-in profiles. Its findings become observations and do not change the overall review decision, but they can still be tracked and alerted.

## Decision log

Vigil stores acknowledged finding patterns in `~/.vigil/decisions.db`.

- Matching uses repository, file, category, and fuzzy message similarity.
- Resolution replies record the reply author and reason.
- Replies containing `false positive` are recorded as `false_positive`.
- Replies containing `wontfix` or `acceptable` are recorded as `wontfix`.
- Other accepted resolution replies are recorded as `accepted`.
- `--remove` re-enables one pattern; `--clear` removes all stored decisions for a repository.

## GitHub Actions

### Approval credential

The workflow token and the review identity are separate concerns:

- `github.token` can read the PR and usually post comments.
- GitHub may reject `APPROVE` or `REQUEST_CHANGES` events from `github.token`, depending on repository/organization settings and identity rules.
- When that happens, Vigil falls back to a `COMMENT` review. The content is preserved, but it cannot satisfy a required-approval branch rule.
- Configure `VIGIL_REVIEW_TOKEN` as a repository or organization secret when Vigil must submit a real review decision. Use a fine-grained PAT or GitHub App token for a dedicated reviewer identity with **Pull requests: Read and write** access to the target repositories.

The reusable workflow emits a visible warning when `VIGIL_REVIEW_TOKEN` is absent.

### Central reusable workflow

Do not symlink workflow files across repositories. A Git symlink to a path outside the repository breaks on GitHub runners and on other clones.

Use the reusable workflow instead. Each repository keeps this small caller:

```yaml
# .github/workflows/vigil.yml
name: Vigil PR Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  pull_request_review_comment:
    types: [created]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  vigil:
    uses: F2iLLC/vigil/.github/workflows/reusable-vigil.yml@main
    with:
      # Omit this input to use ubuntu-latest.
      runner-json: '["self-hosted","linux","x64","ci-light"]'
    secrets: inherit
```

The caller follows `main` so reviewed workflow fixes propagate to every consumer without copying the full YAML. If immutable workflow provenance is more important than automatic propagation, replace `@main` with a full commit SHA and update that pin intentionally.

The centralized workflow provides:

- reviews on PR open, synchronize, reopen, and ready-for-review;
- `/vigil review` on-demand reviews;
- resolution-reply handling;
- `resolve-addressed` on new commits;
- per-PR concurrency cancellation;
- `SKIP_VIGIL=true`, `skip-vigil`, and `[skip vigil]` controls;
- model-aware provider-key checks;
- approval-token warnings;
- an optional, fork-gated [external context provider](#external-review-context) (`context-provider`, `context-label`, and the `VIGIL_CONTEXT_TOKEN` secret);
- an advisory mode that keeps provider or infrastructure outages from turning into red CI by default (see [Advisory mode and loud failure](#advisory-mode-and-loud-failure)); and
- a loud-failure guard so an install/run failure is never silently reported as a passing review, even while advisory mode keeps it non-blocking.

Set these repository or organization secrets:

| Secret | Required when | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Using `gemini/*` | Specialist and lead model calls |
| `ANTHROPIC_API_KEY` | Using `claude-*` or `anthropic/*` | Specialist or lead model calls |
| `OPENAI_API_KEY` | Using OpenAI models | Specialist or lead model calls |
| `VIGIL_REVIEW_TOKEN` | Real approval events are required | Submit APPROVE/REQUEST_CHANGES as the reviewer identity |
| `VIGIL_CONTEXT_TOKEN` | An [external context provider](#external-review-context) needs a credential | One opaque token forwarded to the provider; withheld on fork pull requests |

Repository secrets are not exposed to untrusted fork pull requests under the normal `pull_request` event. Choose a fork-review policy deliberately; do not switch to `pull_request_target` without reviewing the security implications.

### Direct composite-action use

If the centralized lifecycle is unnecessary, call the composite action directly:

```yaml
- uses: F2iLLC/vigil@ce4df1c9c7cf6dc126fe1f04a4cc02c581e8823e
  with:
    model: gemini/gemini-3.1-flash-lite
    profile: default
    gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
    github-token: ${{ secrets.VIGIL_REVIEW_TOKEN || github.token }}
```

Available inputs:

| Input | Default | Notes |
| --- | --- | --- |
| `pr-url` | Event PR URL | Required for comment-triggered workflows |
| `command` | `review` | `review`, `dismiss-resolved`, or `resolve-addressed` |
| `model` | `gemini/gemini-3.1-flash-lite` | LiteLLM model identifier |
| `lead-model` | Same as `model` | Optional separate lead model |
| `profile` | `default` | `default` or `enterprise` |
| `force` | `false` | Review even when no files changed since the last review; the reusable workflow sets this for on-demand `/vigil review` |
| `reason` | Empty | Why the review was requested; recorded in the run log |
| `context-provider` | Empty | Command or `http(s)` endpoint supplying [external review context](#external-review-context). Never pass this on a fork pull request; the reusable workflow gates it off automatically, a direct caller must gate it itself |
| `context-label` | Empty | Short label naming the external context source, shown to reviewers |
| `context-token` | Empty | One opaque token for the external context provider (`VIGIL_CONTEXT_TOKEN` env for a command, `X-Vigil-Context-Token` header for HTTP). Fork-gated the same way |
| `github-token` | `github.token` | Use `VIGIL_REVIEW_TOKEN` for real approval events |
| `gemini-api-key` | Empty | Gemini provider credential |
| `anthropic-api-key` | Empty | Anthropic provider credential |
| `openai-api-key` | Empty | OpenAI provider credential |

Outputs:

| Output | Values | Notes |
| --- | --- | --- |
| `review-ran` | `true` / `false` | `false` when the venv install or the Run Vigil step did not complete successfully, meaning the requested command (review, dismiss-resolved, or resolve-addressed) never actually executed. A caller can check this explicitly to gate on a real completed review rather than on the job's (possibly advisory-wrapped) conclusion. |

The action uses a suitable system Python 3.10+ when available and falls back to `actions/setup-python`. It installs Vigil into an isolated virtual environment under the runner temporary directory.

### Advisory mode and loud failure

`advisory` (an input on the reusable workflow, default `true`) wraps the composite-action step in `continue-on-error`, so a provider-key gap or an install/run failure does not turn into red, merge-blocking CI by default. This is deliberately not the default the composite action itself would give you if called directly — direct callers get whatever `continue-on-error` they set (or none).

Advisory mode only affects merge gating. It does not affect what gets reported, and it does not affect Vigil's own review verdict when Vigil does run. A final `Verify Vigil actually ran` step in `action.yml` runs with `if: always()` — even after an earlier step in the same composite action failed — and checks whether the install step and the Run Vigil step both actually succeeded. When either did not:

- it fails itself, so the run's step list shows a red step even when the job's overall conclusion stays green under advisory mode;
- it emits an `::error::` workflow annotation naming the failure plainly;
- it appends the same statement to the job's `$GITHUB_STEP_SUMMARY`; and
- it sets the `review-ran` output to `false`.

The `review` command additionally gets a best-effort PR comment (a plain `curl` call to the GitHub REST API, since the failure can mean Vigil's own venv/package never got installed), posted only when a PR number can be resolved and skipped if a prior comment on the same PR already carries the `<!-- vigil-did-not-run -->` marker (a single, unpaginated lookup — best-effort, so a failed or unrecognized lookup falls through to posting rather than going silent). `dismiss-resolved` and `resolve-addressed` get the annotation, summary, and `review-ran` output but never the comment: neither posts a review in any outcome, so neither creates the false attestation this guard exists to catch, and `resolve-addressed` in particular runs on every `synchronize` event — commenting there too would mean a new comment on every open PR on every push for as long as an outage lasts.

Real incident: F2iLLC/relara run 30927732554 (root cause tracked fleet-wide as F2iLLC/LunaOS#3775) — the install step failed on a runner whose `python3` lacked `ensurepip`, `Run Vigil` was skipped, and the job still reported success with no review ever posted. F2iLLC/vigil#51 tracks the fix in two parts: `Detect Python` now probes the venv before deciding whether to skip `actions/setup-python`, and this loud-failure guard — so a failure of that kind is now unmissable in the run itself even though it stays non-blocking by default.

If your repository's branch protection should actually block a merge when Vigil could not run, do not flip the shared `advisory` default — that is a fleet-wide policy change reserved for the workflow's operator, since every F2iLLC repo calls the same reusable workflow. Instead, check the `review-ran` output (or the `::error::` annotation) from your own branch protection or a follow-up job.

## Releases and version pinning

Consumers pin the action at `F2iLLC/vigil@v1`. That alias does **not** follow `main` —
merging a fix here ships nothing until the alias is repointed. Two workflows
cover that gap, and they are deliberately separate:

| Workflow | Trigger | Effect |
|---|---|---|
| `Tag drift check` | push to `main`, daily, manual | **Reports only.** Fails when `v1` lags `main`, or when an in-repo `F2iLLC/vigil@<sha>` self-pin is stale. Never changes a tag. |
| `Release (move major alias tag)` | push of a `vX.Y.Z` tag, or manual dispatch | Moves the major alias (`v1`) to the released commit, behind the `release` environment gate. |

### Cutting a release

```bash
git switch main && git pull
git tag -a v1.2.0 -m "Vigil v1.2.0" && git push origin v1.2.0
```

Pushing the semver tag is the whole release. The workflow resolves `v1` from
the tag's major component, runs the full test suite, checks `action.yml`
inputs for consumer-breaking changes, waits for approval on the `release`
environment, then force-moves and pushes the annotated `v1`.

`workflow_dispatch` is the escape hatch for moving the alias without cutting a
number. It defaults to **dry run**; untick it to actually publish.

### Guards

The release refuses to proceed when any of these fail:

- the full `pytest` suite does not pass;
- an `action.yml` input was removed, or became required (either silently
  breaks consumer workflows — GitHub *ignores* an undeclared input rather than
  failing on it, so the consumer's setting just stops taking effect);
- the target commit is not contained in `main`;
- the alias would move **backwards**, un-shipping fixes from every consumer at
  once (override with `--allow-rollback` only if that is genuinely intended).

> [!WARNING]
> The `release` environment must be created with **required reviewers**.
> GitHub silently auto-creates an unprotected environment on first use, so
> without that configuration the approval step provides no protection.

### `v1` is an annotated tag

`git rev-parse v1` returns the **tag object**, not the commit — so comparing it
against a branch head reports drift that is not there. Always peel it:

```bash
git rev-parse 'v1^{commit}'          # correct
.github/scripts/tagctl.sh resolve v1 # same thing, and the only form used in CI
```

`tagctl.sh` centralises that peel precisely so the mistake cannot recur; it
also exposes `drift`, `pins`, `plan-move` and `move` (local tag only — it never
pushes).

## Webhook server

Configure a GitHub webhook to send events to:

```text
https://your-host.example/webhook
```

The server handles:

- `pull_request` opened, reopened, and ready-for-review events;
- `/vigil review` top-level PR comments; and
- top-level PR resolution comments.

It skips drafts and bot-authored PRs. The standalone webhook server does not implement the GitHub Actions `synchronize`/`resolve-addressed` lifecycle.

Set `WEBHOOK_SECRET` to verify `X-Hub-Signature-256` signatures. A health endpoint is available at `/health`.

## Alerts

Alert-enabled personas can send the same non-blocking findings through email and the optional LunaOS escalation endpoint.

```bash
# Email
VIGIL_ALERT_EMAIL=dev-team@example.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=vigil@example.com
SMTP_PASSWORD=app-specific-password

# Optional LunaOS escalation delivery
LUNAOS_ESCALATION_URL=https://hetzner-api.lunaos.io/api/escalations
ESCALATION_INGEST_TOKEN=shared-secret-token
```

Both delivery paths are best-effort and additive. Leave their configuration unset to disable them.

## Profiles

### `default`

| Specialist | Focus | Blocking |
| --- | --- | --- |
| Logic | Correctness, edge cases, concurrency | Yes |
| Security | Validation, injection, secrets, auth | No |
| Architecture | Boundaries, coupling, API design | Yes |
| Testing | Coverage, assertions, error paths | Yes |
| Performance | Queries, memory, rendering, bundle cost | Yes |
| DX | API contracts, documentation, errors, migrations | Yes |

### `enterprise`

The enterprise profile is a separate eight-specialist team, not the default team plus appended reviewers:

| Specialist | Focus | Blocking |
| --- | --- | --- |
| Architecture | Boundaries, lifecycle, observability, configuration | Yes |
| Security | Validation, auth, secrets, tenant isolation | No |
| Test Strategy | Coverage architecture and assertion quality | Yes |
| Data Architecture | Schemas, migrations, indexes, ownership | Yes |
| Performance | Queries, memory, rendering, bounded work | Yes |
| DX | Public contracts, migrations, documentation | Yes |
| GxP Compliance | Audit trails, ALCOA+, Part 11, immutability | Yes |

## Review decisions

- **APPROVE**: no blocking specialist or lead finding remains. Any finding the review still carries is reported in the body as a non-blocking advisory note, never as an inline review thread.
- **REQUEST_CHANGES**: a specialist or lead found a critical/high issue.
- **BLOCK**: the lead found a fundamental scope, architecture, or coherence problem. GitHub receives this as `REQUEST_CHANGES` because GitHub has no `BLOCK` review event.

Specialists operate under domain sovereignty: they state the constraint in their domain and leave cross-domain implementation choices to the lead reviewer.

## Supported models

Use any provider supported by LiteLLM and set the corresponding environment variable.

```bash
# Google
vigil review "$PR" --model gemini/gemini-3.1-flash-lite
vigil review "$PR" --model gemini/gemini-3.1-pro

# Anthropic
vigil review "$PR" --model claude-sonnet-4-6

# OpenAI
vigil review "$PR" --model gpt-4o
vigil review "$PR" --model o3-mini

# Local
vigil review "$PR" --model ollama/llama3
```

## Architecture

```text
src/vigil/
|-- cli.py                     Typer CLI and review orchestration
|-- reviewer.py                Specialist dispatch and lead synthesis
|-- personas.py                Profiles, prompts, and routing patterns
|-- models.py                  Pydantic review models
|-- diff_parser.py             Diff parsing and docs-only classification
|-- github.py                  PR data and GitHub API access
|-- github_review.py           Review and inline-comment posting
|-- comment_manager.py         Conversation, thread, and resolution lifecycle
|-- context_manager.py         Cross-round fingerprints and filtering
|-- external_context.py       Pluggable external review-context provider
|-- cross_specialist_dedup.py  Consensus merging and formatting
|-- issue_manager.py           Observation issue creation and deduplication
|-- decision_log.py            SQLite-backed decision memory
|-- alerts.py                  SMTP and LunaOS escalation delivery
|-- webhook.py                 FastAPI webhook server
|-- audit.py                   SQLite review audit trail
`-- utils.py                   Sanitization and shared helpers
```

The current pipeline:

1. Fetch PR metadata, full diff, top-level comments, and prior reviews.
2. Locate previous Vigil state for posted re-reviews.
3. Resolve acknowledged or code-addressed threads.
4. Parse the full diff into per-file hunks and resolve external review context once.
5. Route relevant hunks to each specialist sequentially.
6. Filter known decisions and send optional specialist alerts.
7. Run the lead reviewer with specialist results and conversation evidence.
8. Merge duplicate cross-specialist findings into consensus findings.
9. Create deduplicated issues for non-blocking observations.
10. Filter cross-round duplicates and post the review: findings inline on a blocking verdict, in the body as advisory notes otherwise, with fallbacks.

See [CROSS_ROUND_CONTEXT.md](CROSS_ROUND_CONTEXT.md) for fingerprinting and consensus details.

## License

[MIT](LICENSE)
