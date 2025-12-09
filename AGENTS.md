# Repository Guidelines

## Project Structure & Module Organization
- The repo is clean by default; add application code under `src/` with clear entrypoints (e.g., `src/main.py` or `src/app/index.js`).
- Mirror the structure in `tests/` so every module has a sibling test file; keep fixtures/stubs in `tests/fixtures/`.
- Store automation and one-off helpers in `scripts/`; place static assets in `assets/`; keep design notes in `docs/`.
- Root configs (`Makefile`, `pyproject.toml` or `package.json`, linters) and environment templates (`.env.example`) live at the repository root.

## Build, Test, and Development Commands
- Standardize on Make targets (or equivalent `package.json`/`just` scripts) to provide a single surface:
  - `make setup`: install dependencies and create the local environment.
  - `make lint`: run formatters/linters and fail on warnings.
  - `make test`: execute the full test suite; aim for fast, deterministic runs.
  - `make run`: start the app or CLI entrypoint for local development.
- Document any stack-specific runners (e.g., `pytest`, `npm test`, `npm run dev`) in the README once chosen.

## Coding Style & Naming Conventions
- Default to 4-space indentation for code and 2 for YAML/JSON; keep line length ≤ 100 unless tooling dictates otherwise.
- Use snake_case for files and functions, PascalCase for classes/types, and kebab-case for CLI commands or asset folders.
- Add formatter/linter configs (`black`/`ruff`, `prettier`/`eslint`, etc.) and run them before pushing; prefer automated fixes over manual tweaks.

## Testing Guidelines
- Select the framework native to the chosen stack (e.g., `pytest`, `vitest`) and record it in `tests/README.md`.
- Name tests after their targets (`test_<module>.py`, `<module>.spec.ts`) and keep fixtures deterministic.
- Include integration tests near entrypoints for critical flows; measure coverage on high-risk modules even if full coverage is not enforced.

## Commit & Pull Request Guidelines
- Write action-led commit messages; Conventional Commits (`feat:`, `fix:`, `chore:`) are preferred for readability and changelog generation.
- Keep PRs small and focused; include purpose, approach, and testing notes; link issues when applicable.
- Add screenshots or CLI transcripts for user-facing changes; call out follow-up tasks or known gaps in the description.

## Security & Configuration
- Do not commit secrets or private keys; use `.env` locally and provide placeholders in `.env.example`.
- Document required environment variables, ports, and external services in `docs/configuration.md` once they appear.
- Validate inputs at module boundaries and avoid logging sensitive values.
