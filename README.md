# Sentry Review — AI-Powered Code Review Platform (MVP)

A single-file React artifact demonstrating the core workflow from the
spec: upload/paste code, run real static analysis, score it, browse
findings, and get AI-generated explanations and a full review from Claude.

## What's real vs. simplified

**Real:**
- Static analysis: regex/structural rules across Python, JavaScript and
  TypeScript covering hardcoded secrets, SQL injection patterns, eval/exec,
  shell=True, unsafe pickle/yaml.load, weak hashing (md5/sha1), XSS-prone
  innerHTML, bare except / empty catch, duplicated code blocks, unused
  variables, long functions, and cyclomatic-complexity estimation.
- Scoring: four category scores (Code Quality, Security, Maintainability,
  Complexity) computed from actual issue counts and severities — formula
  is documented in-app and in `computeScores()`.
- AI: "Explain with AI" and "Generate AI review" call the Anthropic API
  directly with your real code as context — not canned text.

**Simplified for a no-network sandbox** (the full spec's FastAPI +
PostgreSQL/pgvector + Redis + Next.js + Docker Compose + JWT auth stack
needs a real dev machine with internet access to install packages,
run databases, and build containers):
- No backend/database — everything runs client-side in this one file.
- No auth/accounts.
- "Semantic search" is keyword search over findings, not embeddings.
- No repository ZIP upload, background job queue, or Docker/CI.

## How to run it

This file is a React component (`CodeReviewPlatform.jsx`) meant to be
used as a Claude.ai artifact, or dropped into any React app that has:
- Tailwind CSS (utility classes only, no custom config needed)
- `lucide-react`
- `recharts`

If you want the full production system described in the original spec
(FastAPI, Postgres+pgvector, Redis workers, Docker Compose, JWT auth,
Bandit/Ruff, CI/CD), build it with Claude Code on a machine with network
access — it can install the real dependencies and actually run
`docker compose up`.
