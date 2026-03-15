# Vigil

AI-powered, model-agnostic PR review with multi-persona specialist teams.

Vigil dispatches your pull request to a team of specialist reviewers — each focused on a single domain (security, logic, performance, etc.) — then a lead reviewer aggregates their verdicts into a final decision. Findings land as **inline PR comments** on the exact lines that need attention. Non-blocking observations are automatically opened as **GitHub issues** and linked in the review.

## How it works

```
PR Diff
  │
  ├─► Logic ──────────► findings
  ├─► Security ───────► observations (non-blocking)
  ├─► Architecture ───► findings
  ├─► Testing ────────► findings
  ├─► Performance ────► findings
  └─► DX ─────────────► findings
                            │
                    Lead Reviewer
                            │
                  ┌─────────┴─────────┐
                  │  APPROVE / BLOCK  │
                  │  + inline comments│
                  │  + issue links    │
                  └───────────────────┘
```

Each specialist only sees the files relevant to their domain (Security skips `.md` files, Testing focuses on test files + source, etc.). This keeps prompts focused and reduces token waste.

## Features

- **Model-agnostic** — runs on any LLM via [litellm](https://github.com/BerriAI/litellm) (Gemini, Claude, GPT, Mistral, local models, etc.)
- **Multi-persona review** — 6 specialist reviewers + lead, each with domain-scoped expertise
- **Inline PR comments** — findings posted directly on the diff lines, not buried in a wall of text
- **Auto-issue creation** — non-blocking observations are opened as GitHub issues with a `vigil` label and cited as links in the review
- **Decision log** — remembers acknowledged findings so Vigil stops re-flagging them; browse and manage via `vigil decisions`
- **Non-blocking personas** — Security runs as non-blocking by default (findings become observations, never block the PR)
- **Email alerts** — alert-enabled personas can send email notifications for findings via SMTP
- **Webhook server** — deploy as a GitHub webhook to auto-review PRs on open/reopen
- **Incremental review** — only reviews files changed since the last Vigil review
- **Smart deduplication** — won't repost findings already on the PR (even in resolved threads)
- **File-level routing** — each specialist only reviews files matching their domain patterns
- **Session IDs** — every specialist verdict is tagged with a unique ID (`VGL-a3f8b2`) for traceability
- **Structured output** — JSON mode with typed findings (severity, category, file, line, suggestion)
- **Built-in profiles** — `default` for general-purpose, `enterprise` for regulated/medtech (adds GxP, Data Architecture, tenant isolation)
- **GitHub Action** — drop into any repo's CI with 4 lines of YAML

## Quick start

```bash
pip install -e .
```

```bash
export GITHUB_TOKEN="ghp_..."
export GEMINI_API_KEY="..."  # or ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.

vigil review https://github.com/owner/repo/pull/123 --post
```

That's it. Vigil fetches the PR, runs all specialists, and posts a review with inline comments. Observations are auto-opened as GitHub issues and linked in the review body.

### CLI commands

```
vigil review <PR_URL> [OPTIONS]

Options:
  -m, --model TEXT        LLM model (default: gemini/gemini-2.5-flash)
  --lead-model TEXT       Different model for the lead reviewer
  -p, --profile TEXT      Review profile: default, enterprise
  --json                  Output raw JSON instead of pretty-printing
  --post                  Post review as GitHub PR review with inline comments
```

```
vigil dismiss-resolved <PR_URL>
```
Resolve Vigil comment threads that received a "resolved" reply. Also logs the decision so the finding pattern is suppressed in future reviews.

```
vigil decisions <owner/repo> [OPTIONS]

Options:
  -f, --file TEXT         Filter by file path
  -c, --category TEXT     Filter by category
  --remove INT            Remove a specific decision by ID (re-enables that pattern)
  --clear                 Clear all decisions for the repo
```
Browse, filter, and manage the decision log. See what Vigil is suppressing, why each finding was dismissed, and selectively re-enable patterns as the repo matures.

```
vigil serve [OPTIONS]

Options:
  -p, --port INT          Port to listen on (default: 8000)
  --host TEXT             Host to bind to (default: 0.0.0.0)
  -m, --model TEXT        LLM model for reviews
  --lead-model TEXT       LLM model for lead reviewer
  --profile TEXT          Review profile
```
Start the webhook server to auto-review PRs when they are opened, reopened, or marked ready for review.

```
vigil profiles
```
List available review profiles and their specialists.

### Examples

```bash
# Use Gemini Flash (fast + cheap)
vigil review https://github.com/org/repo/pull/42 -m gemini/gemini-2.5-flash --post

# Use Claude for lead, Gemini for specialists
vigil review https://github.com/org/repo/pull/42 -m gemini/gemini-2.5-flash --lead-model claude-sonnet-4-6 --post

# Enterprise profile (adds GxP, Data Architecture, tenant isolation reviewers)
vigil review https://github.com/org/repo/pull/42 -p enterprise --post

# JSON output for piping into other tools
vigil review https://github.com/org/repo/pull/42 --json

# Browse decision log
vigil decisions F2iProject/vigil
vigil decisions F2iProject/vigil --file src/auth.py
vigil decisions F2iProject/vigil --remove 5

# Start webhook server on port 9000
vigil serve --port 9000 -m gemini/gemini-2.5-flash
```

## Auto-Issue Creation

When `--post` is used, Vigil automatically creates GitHub issues for non-blocking observations:

1. Each observation becomes an issue labeled `vigil` with severity, file location, message, and suggestion
2. Existing open `vigil` issues are checked first to avoid duplicates (file path + message similarity matching)
3. The review body shows compact issue links instead of raw text:

```
### Observations (3 non-blocking → tracked as issues)
- 🟡 [MEDIUM] `src/auth.py:42` — Missing input validation → #12
- 🔵 [LOW] `src/db.py:18` — Connection not pooled → #13
- 🟡 [MEDIUM] `src/api.py:5` — Error leaks stack trace → already tracked in #8
```

## Decision Log

Vigil remembers findings you've already acknowledged so it doesn't keep flagging the same patterns:

**How decisions get logged:**
- Reply "resolved", "fixed", "addressed", or "done" to a Vigil inline comment
- Vigil captures the reply text as the reason and the author as `decided_by`
- Decision type is inferred: "false positive" → `false_positive`, "wontfix"/"acceptable" → `wontfix`, everything else → `accepted`

**How decisions suppress findings:**
- Before each review, findings are checked against the decision log by (repo, file, category) + fuzzy message matching (≥85% similarity)
- Matching findings are silently suppressed

**Managing decisions:**
```bash
# See what's suppressed and why
vigil decisions owner/repo

# Re-enable a pattern (repo has matured, time to catch these again)
vigil decisions owner/repo --remove 5

# Nuclear option: clear everything
vigil decisions owner/repo --clear
```

## Webhook Server

Deploy Vigil as a webhook to auto-review PRs:

```bash
vigil serve --port 8000 -m gemini/gemini-2.5-flash
```

The server listens for GitHub webhook events:
- **PR opened/reopened/ready_for_review** → triggers a review
- **`/vigil review` comment** → triggers an on-demand review
- **Resolution replies** → resolves threads and logs decisions
- Skips drafts and bot PRs

Configure in GitHub: Settings → Webhooks → Add webhook → `http://your-host:8000/webhook`

Optional: set `WEBHOOK_SECRET` for HMAC-SHA256 signature verification.

## Email Alerts

Alert-enabled personas (like Security) can send email notifications when findings are detected:

```bash
# .env
VIGIL_ALERT_EMAIL=dev-team@company.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=vigil@company.com
SMTP_PASSWORD=app-specific-password
```

## GitHub Action

### Drop-in workflow (for your own repo)

```yaml
# .github/workflows/vigil-review.yml
name: Vigil PR Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  issues: write  # needed for auto-issue creation

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install vigil-review
      - env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          vigil review "${{ github.event.pull_request.html_url }}" \
            --model "gemini/gemini-2.5-flash" --post
```

### Reusable action

```yaml
- uses: F2iProject/vigil@main
  with:
    model: "gemini/gemini-2.5-flash"
    profile: "default"
    gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
```

## Profiles

### `default` — 6 specialists + lead

| Specialist | Focus | Blocking |
|---|---|---|
| **Logic** | Bugs, off-by-one, null handling, race conditions | Yes |
| **Security** | Injection, secrets, auth gaps, OWASP top 10 | No (observations → issues) |
| **Architecture** | Coupling, API design, dependency direction | Yes |
| **Testing** | Coverage gaps, brittle tests, missing error path tests | Yes |
| **Performance** | N+1 queries, memory leaks, O(n²) on unbounded data | Yes |
| **DX** | Breaking changes, missing docs, confusing error messages | Yes |

Security runs as **non-blocking** by default — its findings become observations that are tracked as issues rather than blocking the PR. This is ideal for early-stage repos where security patterns aren't yet established. You can change this in `personas.py`.

### `enterprise` — 7 specialists + lead

Everything in `default`, plus:

| Specialist | Focus | Blocking |
|---|---|---|
| **Data Architecture** | Schema design, migrations, indexes, entity ownership | Yes |
| **GxP Compliance** | Audit trails, ALCOA+, 21 CFR Part 11, immutability | Yes |

The enterprise profile also includes enhanced specialists with tenant isolation checks, cross-package impact analysis, and regulatory-aware reviews.

## How review decisions work

- **APPROVE** — all specialists pass, lead finds no blocking issues
- **REQUEST_CHANGES** — any specialist found critical/high severity issues
- **BLOCK** — lead found a fundamental problem (architectural violation, scope drift)

Each specialist operates under **domain sovereignty** — they only review their area and express constraints ("external input must be validated"), not implementation directives ("use Zod"). The lead reviewer mediates conflicts between specialists using a priority hierarchy: Regulatory > Security > Reliability > Convenience.

## Supported models

Anything [litellm supports](https://docs.litellm.ai/docs/providers):

```bash
# Google
vigil review $PR -m gemini/gemini-2.5-flash
vigil review $PR -m gemini/gemini-2.5-pro

# Anthropic
vigil review $PR -m claude-sonnet-4-6
vigil review $PR -m claude-opus-4

# OpenAI
vigil review $PR -m gpt-4o
vigil review $PR -m o3-mini

# Local (Ollama)
vigil review $PR -m ollama/llama3
```

Set the corresponding API key as an environment variable (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.).

## Architecture

```
src/vigil/
├── cli.py              # Typer CLI entry point
├── reviewer.py         # Multi-persona review engine
├── personas.py         # Specialist definitions & profiles
├── models.py           # Pydantic models (Finding, PersonaVerdict, ReviewResult)
├── diff_parser.py      # Diff parsing, file routing, commentable line extraction
├── github.py           # GitHub API (fetch PR data)
├── github_review.py    # Post reviews with inline comments
├── comment_manager.py  # Comment lifecycle: fetch, resolve, dedup, decision logging
├── issue_manager.py    # Auto-create GitHub issues for observations
├── decision_log.py     # SQLite-backed decision memory (~/.vigil/decisions.db)
├── alerts.py           # Email alerting for alert-enabled personas
├── webhook.py          # FastAPI webhook server for GitHub events
└── audit.py            # Audit trail logging
```

The review pipeline:

1. **Fetch** PR diff and metadata from GitHub
2. **Parse** diff into per-file hunks
3. **Route** each specialist to only their relevant files (via glob patterns)
4. **Dispatch** specialists sequentially (each gets a focused, smaller diff)
5. **Filter** known decisions from the decision log (suppress previously acknowledged patterns)
6. **Aggregate** verdicts and run lead reviewer
7. **Create issues** for non-blocking observations (with dedup)
8. **Post** findings as inline PR comments on exact diff lines (with 4-layer fallback)

## License

[MIT](LICENSE)
