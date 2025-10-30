# GitHub Branch Protection Auditor

This tool scans every repository in a GitHub organization, reads branch protection and ruleset settings on the default branch, and writes the results to an Excel workbook (`branch_protection_report.xlsx`) with summaries for all repos and engineering-owned repos.

## How It Works

1. `main.go` loads GitHub App credentials from the environment and starts the audit.
2. `github_client.go` exchanges the app credentials for an installation token.
3. `audit.go` lists every repository, collects protection data concurrently, and writes both the console summary and Excel workbook.
4. `repository.go` and `ruleset.go` pull classic protections and rulesets, merging them into a single report entry.
5. `stats.go` tracks shared counters and progress while the run executes.

## Key Files

- `main.go` – entrypoint that wires configuration, logging, and the audit run.
- `config.go` – loads `APP_ID`, `INSTALLATION_ID`, `PRIVATE_KEY`, and optional `GITHUB_ORG` (defaults to `nanasec`).
- `github_client.go` – builds an authenticated GitHub client using the GitHub App.
- `audit.go` – orchestrates repository discovery, Excel output, and engineering-team reporting.
- `repository.go` – converts branch protection API responses into the report structure.
- `ruleset.go` – fetches rulesets and computes their effective protection impact.
- `stats.go` – shared counters, timers, and progress formatting.
- `logger.go` / `ratelimit.go` – structured logger and rate-limit helper.
- `auth.go` – JWT creation and helper utilities for GitHub App auth.
- `main_old_working.go` – archived legacy script (excluded by default build tags).
- `.github/workflows/audit.yml` – GitHub Actions workflow wrapper (optional automation).

## Prerequisites

- Go 1.24+
- GitHub App installed on the target organization with read-only Repository Administration and Metadata permissions
- Environment variables set:
  - `APP_ID`
  - `INSTALLATION_ID`
  - `PRIVATE_KEY`
  - `GITHUB_ORG`

## Running Locally

```bash
export APP_ID=...
export INSTALLATION_ID=...
export PRIVATE_KEY="$(cat private-key.pem)"
export GITHUB_ORG=your-org
go run ./...
```

The Excel file and console summaries are produced in the working directory.

## Running in GitHub Actions

Store the three secrets above as repository or organization secrets and use `.github/workflows/audit.yml` to run the auditor on demand. The workflow uploads the generated workbook as an artifact.
