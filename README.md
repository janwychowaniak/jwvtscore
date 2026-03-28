# jwvtscore

`jwvtscore` is a privacy-first CLI for checking whether VirusTotal already knows a file by its SHA-256 hash.

## Goals

- compute the hash locally
- query VirusTotal with the hash only
- never upload file contents
- keep the CLI output concise and readable

## Development

```bash
uv sync
uv run pytest
uv run jwvtscore /path/to/file
uv tool install .
```

`uv tool install .` installs the `jwvtscore` command globally through uv. Set `VIRUSTOTAL_API_KEY` in your shell before running the CLI.
