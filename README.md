# jwvtscore

`jwvtscore` is a privacy-first CLI for checking whether VirusTotal already knows a file by its SHA-256 hash.

## Goals

- compute the hash locally
- query VirusTotal with the hash only
- never upload file contents
- keep the CLI output concise and readable

## Installation

Install the CLI in an isolated tool environment:

```bash
uv tool install jwvtscore
```

You can also install it with `pipx`:

```bash
pipx install jwvtscore
```

## Configuration

`jwvtscore` requires a VirusTotal API key. Set it with the `VIRUSTOTAL_API_KEY`
environment variable before running the command:

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
```

The CLI only sends SHA-256 hashes to VirusTotal lookup endpoints. It does not
upload file contents.

## Usage

Check one or more regular files:

```bash
jwvtscore /path/to/file
jwvtscore /path/to/file another-file.bin
```

Example output:

```text
/path/to/file
  sha256:   b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
  verdict:  malicious
  stats:    harmless=1 suspicious=2 malicious=3 undetected=4
  link:     https://www.virustotal.com/gui/file/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

## Development

```bash
uv sync
uv run pytest
uv run jwvtscore /path/to/file
uv tool install .
```
