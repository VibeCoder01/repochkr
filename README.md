# GitHub Dependency Auditor (FastHTML)

Audit a GitHub user or organisation’s public repositories for vulnerable dependencies. The app
discovers manifests, parses dependencies across ecosystems, queries OSV, scores risk, and renders a
FastHTML + Tailwind dashboard with live progress, exports, and explainer panels.

## Features
- Multi-ecosystem manifest parsing (npm, PyPI, Go, Cargo, Maven/Gradle, Pipenv, Poetry, requirements
  variants).
- OSV-backed vulnerability lookups with in-memory caching and retry logic.
- Severity-weighted risk scoring plus recommended (newer) versions when OSV reports fixes.
- Live progress bar with per-repo status while scanning; JSON and Markdown exports.
- Built-in explainers for GitHub fine-grained tokens and OSV data sources.

## Setup
- Requires Python 3.11+.
- Create a virtualenv and install dependencies:
  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install fasthtml requests uvicorn
  ```
- Optional: set `GITHUB_TOKEN` to raise rate limits and `OSV_API` to point at a different backend.

## Quickstart
Requirements: Python 3.11+, outbound access to GitHub and `api.osv.dev`.

```bash
python -m venv .venv
source .venv/bin/activate
pip install fasthtml requests uvicorn
uvicorn webapp:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

### Form inputs
- GitHub user/org.
- Include forks (`yes`/`no`).
- Minimum last-updated date (ISO date filter).
- GitHub token (fine-grained, optional): read-only repo contents is sufficient; used per request to
  raise rate limits and not stored.

## Configuration
- `GITHUB_TOKEN` (optional): increases GitHub REST rate limits. You can also paste a fine-grained
  token into the form for a single scan.
- `OSV_API` (optional): override the OSV endpoint (defaults to `https://api.osv.dev/v1/query`).
- `PORT` (optional): server port (default 8000).

## How it works
- `github_client.py`: minimal GitHub REST client for repo discovery and file fetches across common
  config directories.
- `dependency_parsers.py`: manifest handlers (`package.json`, `requirements*.txt`, `pyproject.toml`,
  `Pipfile`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`,
  `build.gradle.kts`). Extend `HANDLERS` to add new formats.
- `vuln_lookup.py`: OSV lookups with retry/backoff and caching keyed by `(ecosystem, package,
  version)`; extracts fixed versions for upgrade hints.
- `risk_model.py`: severity-weighted scoring and highest-severity detection.
- `webapp.py`: FastHTML routes, progress polling endpoint, Tailwind UI, JSON/Markdown exports.

## Data sources
OSV aggregates ecosystem-specific advisories, including npm, PyPI, Go, Rust (RustSec), and JVM
ecosystems (via imported advisories). Queries are read-only and cached in memory per scan.

## Extending
- Add manifests: register filename → parser in `dependency_parsers.HANDLERS`.
- Swap vulnerability source: change `vuln_lookup.VulnerabilityLookup` to hit a different API while
  keeping the normalized `VulnRecord`.
- Background scanning: move `scan_owner` to a worker and surface status via WebSocket or polling.

## Notes
- Handles missing accounts and missing manifests gracefully (empty results).
- Version cleaning strips common semver operators before lookups.
- Severity badge colors are defined in `webapp.py` (`severity_badge`). Adjust to match your policy.
