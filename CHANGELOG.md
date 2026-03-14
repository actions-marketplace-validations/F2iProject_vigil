# Changelog

All notable changes to Vigil will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Webhook server** — `vigil serve` starts a FastAPI server that receives GitHub webhook events and triggers reviews automatically. No more GitHub Actions minutes burned. Configure with `WEBHOOK_SECRET` for signature verification.
- **Non-blocking specialists** — Personas can be marked `blocking=False` (Security is non-blocking by default during early dev). Their findings become observations and don't block the review decision.
- **Email alerts** — Personas with `alert=True` trigger email notifications for their findings. Security findings send alerts even though they're non-blocking. Configure with `VIGIL_ALERT_EMAIL` and SMTP env vars.
- **Smart resolution verification** — When someone replies to a Vigil comment with an issue link (`#45` or full URL), Vigil fetches the issue and verifies it actually covers the concern (keyword overlap check). Prevents agents from dismissing findings by linking unrelated issues.
- **Expanded resolution keywords** — Resolution replies now accept "resolved", "fixed", "addressed", "done", issue links (`#123`), and combinations ("Fixed in #45").
- **Dedup against resolved threads** — New `fetch_all_vigil_comments()` includes comments from resolved threads in dedup checks. Prevents Vigil from reposting the same findings when threads are resolved by users or agents without fixing the underlying code.
- **Incremental review** — On re-review, Vigil only analyzes files changed since the last review commit, reducing noise and cost.
- **Auto-resolve addressed threads** — When re-reviewing, Vigil resolves its own comment threads where the underlying code has changed.
- **Dismiss-resolved command** — `vigil dismiss-resolved <pr-url>` resolves Vigil threads that received a "resolved" reply.
- **Force inline comments** — All findings are placed as inline diff comments. Findings on non-diff lines are relocated to the nearest commentable line with a note. Findings on files not in the diff are attached to the best-matching file.
- **Comment deduplication** — New comments are compared against existing Vigil comments using path-indexed lookup, MD5 fingerprint fast-path, and `SequenceMatcher` fuzzy matching (0.85 threshold).
- **Batched GraphQL mutations** — Thread resolution uses batched mutations (up to 50 per request) instead of N+1 individual calls.
- **`/vigil review` command** — Re-trigger a review by commenting `/vigil review` on a PR (works with both webhook and GitHub Actions).
- **Test suite** — 167 tests covering diff parsing, comment management, HTTP errors, webhook events, alerts, and resolution verification.

### Changed

- **Security reviewer non-blocking** — Security specialist findings are treated as observations (non-blocking) by default. Configurable via `blocking` flag on `Persona`. Set `blocking=True` to make security blocking again for production.
- **GitHub Actions workflow** — Removed `synchronize` trigger to stop per-commit reviews. Added `issue_comment` trigger for `/vigil review` command. Workflow is now opt-in and can be disabled independently of the webhook server.
- **Thread matching** — Uses `(path, line, session_id)` tuples instead of brittle `body[:100]` for matching REST comments to GraphQL threads.

### Fixed

- **`find_best_file_for_finding` fallback** — Now correctly skips files with empty line sets when falling back to the first alphabetical file.
- **`_mock_response` helper** — Fixed falsy `{}` bug where `json_data or []` treated empty dict as falsy.

## [0.1.0] - 2026-03-12

### Added

- Initial release of Vigil — AI-powered, model-agnostic PR review tool.
- Multi-persona specialist review with configurable profiles (default, enterprise).
- Lead reviewer synthesis with final decision (APPROVE / REQUEST_CHANGES / BLOCK).
- Support for multiple LLM providers via LiteLLM (Gemini, Claude, OpenAI, etc.).
- GitHub PR Review API integration with inline comments.
- 4-layer fallback for posting reviews (inline+event → body-only → COMMENT event → issue comment).
- Audit logging to SQLite.
- GitHub Action (`action.yml`) for CI/CD integration.
- CLI with `vigil review` and `vigil profiles` commands.
