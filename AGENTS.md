# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Python CLI application managed with `uv`.

- `src/jwvtscore/`: application code. Keep CLI flow in `cli.py`, hashing in `hashing.py`, API access in `vt_client.py`, and terminal formatting in `output.py`.
- `tests/`: `pytest` suite for CLI behavior, hashing, and VirusTotal client logic.
- `pyproject.toml`: project metadata, dependencies, and tool configuration.
- `uv.lock`: pinned dependency set for reproducible development and CI.
- `.github/workflows/ci.yml`: CI quality gate for linting, formatting, type checking, dependency audit, tests, and package build.
- `.github/workflows/publish.yml`: tag-based PyPI Trusted Publishing workflow.
- `.github/dependabot.yml`: conservative dependency and GitHub Actions update policy with cooldown and grouped updates.

## Commands (Build, Test, Development, Install)
Use `uv` for local development and dependency management.

- `uv sync`: install dependencies from `uv.lock`.
- `uv sync --locked --group dev`: reproduce the CI development environment.
- `uv run jwvtscore /path/to/file`: run the CLI against one or more regular files.
- `uv run pytest`: run the test suite.
- `uv run ruff check .`: run linting.
- `uv run ruff format --check .`: check formatting.
- `uv run ruff format .`: format Python files when needed.
- `uv run mypy`: run strict type checking over `src` and `tests`.
- `uv run pip-audit --local --progress-spinner off`: audit the synced local environment for known dependency vulnerabilities.
- `uv build`: build the source distribution and wheel.
- `uv tool install .`: install `jwvtscore` as a global uv-managed command.

## Coding Style & Naming Conventions
Target Python 3.11+ with 4-space indentation and explicit type hints for public functions. Prefer small, testable functions over large procedural blocks. The project uses strict mypy; avoid `Any`, untyped helpers, and unnecessary casts.

- Package/module names: lowercase, no hyphens.
- Functions/variables: `snake_case`.
- Classes: `PascalCase`.
- Constants and env vars: `UPPER_SNAKE_CASE`.

Keep CLI output concise. Use color only to improve readability, not to hide important information.

The package version is defined only in `pyproject.toml`. `jwvtscore.__version__` derives from installed package metadata; do not add a second hardcoded version string.

## Testing Guidelines
Use `pytest` and place tests under `tests/` with names like `test_hashing.py` or `test_cli.py`. Cover the privacy-critical behavior first:

- hashing local files correctly
- sending hash-only lookups
- never uploading file contents
- handling missing `VIRUSTOTAL_API_KEY`

Add regression tests for any bug fix before merging it.

Before committing, run the same checks as CI when practical:

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run mypy`
- `uv run pytest`
- `uv run pip-audit --local --progress-spinner off`
- `uv build`

## Commit & Pull Request Guidelines
Use Conventional Commits for new history, for example: `feat: add SHA-256 hashing helper` or `fix: prefer GUI VirusTotal permalink`.

Pull requests should include:

- a brief description of the change
- test evidence such as `uv run pytest`, `uv run mypy`, and `uv run ruff check .`
- notes on privacy impact, if network behavior changes
- example CLI output when user-facing behavior changes

## Release Guidelines
PyPI releases are automated through `.github/workflows/publish.yml` using PyPI Trusted Publishing and the GitHub environment named `pypi`. Do not add a PyPI API token secret for normal publishing.

Release flow:

- ensure `pyproject.toml` has the intended version
- ensure CI is passing on `main`
- create an annotated tag like `git tag -a v0.1.1 -m "v0.1.1"`
- push the tag with `git push origin v0.1.1`
- confirm the `Publish` workflow succeeds
- optionally create a GitHub Release for the tag with concise release notes

The publish workflow runs `uv build` and `uv publish`. Keep it tokenless unless the Trusted Publishing setup changes.

## Security & Configuration Tips
Do not read secrets from `.env`; use the `VIRUSTOTAL_API_KEY` environment variable. Preserve the repository’s core rule: only query VirusTotal with file hashes via lookup-style requests, and never upload sample contents. Treat any change that could transmit file bytes as a security-sensitive regression.

Dependency security is covered by Dependabot and `pip-audit` in CI. Dependabot cooldown applies to routine version updates, not security updates. If `pip-audit` fails, prefer upgrading the affected dependency rather than ignoring the advisory; document any necessary ignore with the vulnerability ID and rationale.
