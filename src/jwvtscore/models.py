from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FileRecord:
    path: str
    sha256: str
    status: str
    stats: dict[str, int] | None = None
    permalink: str | None = None
    error: str | None = None
