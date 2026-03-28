# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Python CLI application managed with `uv`.

- `src/jwvtscore/`: application code. Keep CLI flow in `cli.py`, hashing in `hashing.py`, API access in `vt_client.py`, and terminal formatting in `output.py`.
- `tests/`: `pytest` suite for CLI behavior, hashing, and VirusTotal client logic.
- `pyproject.toml`: project metadata, dependencies, and tool configuration.
- `uv.lock`: pinned dependency set for reproducible development and CI.

## Commands (Build, Test, Development, Install)
Use `uv` for local development and dependency management.

- `uv sync`: install and lock dependencies.
- `uv run jwvtscore /path/to/file`: run the CLI against one or more regular files.
- `uv run pytest`: run the test suite.
- `uv run ruff check .`: run linting.
- `uv run ruff format .`: format Python files.
- `uv tool install .`: install `jwvtscore` as a global uv-managed command.

## Coding Style & Naming Conventions
Target Python 3 with 4-space indentation and explicit type hints for public functions. Prefer small, testable functions over large procedural blocks.

- Package/module names: lowercase, no hyphens.
- Functions/variables: `snake_case`.
- Classes: `PascalCase`.
- Constants and env vars: `UPPER_SNAKE_CASE`.

Keep CLI output concise. Use color only to improve readability, not to hide important information.

## Testing Guidelines
Use `pytest` and place tests under `tests/` with names like `test_hashing.py` or `test_cli.py`. Cover the privacy-critical behavior first:

- hashing local files correctly
- sending hash-only lookups
- never uploading file contents
- handling missing `VIRUSTOTAL_API_KEY`

Add regression tests for any bug fix before merging it.

## Commit & Pull Request Guidelines
Use Conventional Commits for new history, for example: `feat: add SHA-256 hashing helper` or `fix: prefer GUI VirusTotal permalink`.

Pull requests should include:

- a brief description of the change
- test evidence such as `uv run pytest` and `uv run ruff check .`
- notes on privacy impact, if network behavior changes
- example CLI output when user-facing behavior changes

## Security & Configuration Tips
Do not read secrets from `.env`; use the `VIRUSTOTAL_API_KEY` environment variable. Preserve the repository’s core rule: only query VirusTotal with file hashes via lookup-style requests, and never upload sample contents. Treat any change that could transmit file bytes as a security-sensitive regression.
