from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Protocol

from rich.console import Console

from jwvtscore.hashing import compute_sha256
from jwvtscore.models import FileRecord
from jwvtscore.output import print_record
from jwvtscore.vt_client import LookupResult
from jwvtscore.vt_client import ConfigurationError, VirusTotalClient, VirusTotalError


class FileLookupClient(Protocol):
    def lookup_hash(self, file_hash: str) -> LookupResult: ...


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwvtscore",
        description="Query VirusTotal by local SHA-256 hash without uploading file contents.",
    )
    parser.add_argument("paths", nargs="+", help="Regular file paths to inspect.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    error_console = Console(stderr=True)

    try:
        client = VirusTotalClient.from_env()
    except ConfigurationError as exc:
        error_console.print(f"error: {exc}", style="red")
        return 2

    had_operational_error = False

    try:
        for raw_path in args.paths:
            record, failed = inspect_path(Path(raw_path), client)
            print_record(console, record)
            had_operational_error = had_operational_error or failed
    finally:
        client.close()

    return 1 if had_operational_error else 0


def inspect_path(path: Path, client: FileLookupClient) -> tuple[FileRecord, bool]:
    if not path.exists():
        return FileRecord(
            path=str(path), sha256="-", status="error", error="path does not exist"
        ), True
    if not path.is_file():
        return FileRecord(
            path=str(path), sha256="-", status="error", error="path is not a regular file"
        ), True

    try:
        file_hash = compute_sha256(path)
    except OSError as exc:
        return FileRecord(path=str(path), sha256="-", status="error", error=str(exc)), True

    try:
        result = client.lookup_hash(file_hash)
    except VirusTotalError as exc:
        return FileRecord(path=str(path), sha256=file_hash, status="error", error=str(exc)), True

    return (
        FileRecord(
            path=str(path),
            sha256=file_hash,
            status=result.status,
            stats=result.stats,
            permalink=result.permalink,
        ),
        False,
    )


if __name__ == "__main__":
    sys.exit(main())
