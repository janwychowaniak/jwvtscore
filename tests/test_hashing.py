from __future__ import annotations

from pathlib import Path

from jwvtscore.hashing import compute_sha256


def test_compute_sha256(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world")

    assert (
        compute_sha256(sample) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )
