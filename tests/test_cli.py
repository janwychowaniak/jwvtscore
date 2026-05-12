from __future__ import annotations

from pathlib import Path

import pytest

from jwvtscore import cli
from jwvtscore.vt_client import LookupResult


class FakeClient:
    def __init__(self, results: dict[str, LookupResult] | None = None) -> None:
        self.results = results or {}
        self.queries: list[str] = []

    def lookup_hash(self, file_hash: str) -> LookupResult:
        self.queries.append(file_hash)
        return self.results[file_hash]

    def close(self) -> None:
        return None


def install_fake_client(monkeypatch: pytest.MonkeyPatch, fake_client: FakeClient) -> None:
    def from_env() -> FakeClient:
        return fake_client

    monkeypatch.setattr("jwvtscore.cli.VirusTotalClient.from_env", from_env)


def test_main_reports_missing_api_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    exit_code = cli.main(["missing.bin"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "VIRUSTOTAL_API_KEY is not set" in captured.err


def test_main_success_for_known_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "known.bin"
    sample.write_bytes(b"hello world")
    file_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    fake_client = FakeClient(
        {
            file_hash: LookupResult(
                found=True,
                status="malicious",
                stats={"harmless": 1, "suspicious": 2, "malicious": 3, "undetected": 4},
                permalink="https://www.virustotal.com/gui/file/example",
            )
        }
    )
    install_fake_client(monkeypatch, fake_client)

    exit_code = cli.main([str(sample)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert f"  sha256:  {file_hash}" in captured.out
    assert "  verdict: malicious" in captured.out
    assert "  link:    https://www.virustotal.com/gui/file/example" in captured.out
    assert fake_client.queries == [file_hash]


def test_main_reports_not_found_without_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "unknown.bin"
    sample.write_bytes(b"hello world")
    file_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    fake_client = FakeClient(
        {file_hash: LookupResult(found=False, status="not_found", stats=None, permalink=None)}
    )
    install_fake_client(monkeypatch, fake_client)

    exit_code = cli.main([str(sample)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "  verdict: no existing VirusTotal record found" in captured.out


def test_main_continues_after_file_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "known.bin"
    sample.write_bytes(b"hello world")
    file_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    fake_client = FakeClient(
        {
            file_hash: LookupResult(
                found=True,
                status="clean",
                stats={"harmless": 72, "suspicious": 0, "malicious": 0, "undetected": 1},
                permalink="https://www.virustotal.com/gui/file/example",
            )
        }
    )
    install_fake_client(monkeypatch, fake_client)

    exit_code = cli.main([str(tmp_path / "missing.bin"), str(sample)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "  error:   path does not exist" in captured.out
    assert "  verdict: clean" in captured.out


def test_inspect_path_rejects_directory(tmp_path: Path) -> None:
    fake_client = FakeClient()

    record, failed = cli.inspect_path(tmp_path, fake_client)

    assert failed is True
    assert record.error == "path is not a regular file"
