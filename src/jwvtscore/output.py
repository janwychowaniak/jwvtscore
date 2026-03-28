from __future__ import annotations

from rich.console import Console
from rich.text import Text

from jwvtscore.models import FileRecord


def print_record(console: Console, record: FileRecord) -> None:
    status_text = Text()
    status_text.append(record.path, style="bold")
    status_text.append("\n")

    if record.error:
        status_text.append(_line("error:", record.error), style="red")
        console.print(status_text, soft_wrap=True)
        return

    status_text.append(_line("sha256:", record.sha256) + "\n", style="cyan")

    if record.status == "not_found":
        status_text.append(_line("verdict:", "no existing VirusTotal record found"), style="yellow")
        console.print(status_text, soft_wrap=True)
        return

    status_style = {
        "clean": "green",
        "suspicious": "yellow",
        "malicious": "red",
    }.get(record.status, "white")
    status_text.append(_line("verdict:", record.status) + "\n", style=status_style)

    stats = record.stats or {}
    counts = (
        f"harmless={stats.get('harmless', 0)} "
        f"suspicious={stats.get('suspicious', 0)} "
        f"malicious={stats.get('malicious', 0)} "
        f"undetected={stats.get('undetected', 0)}"
    )
    status_text.append(_line("stats:", counts) + "\n")
    if record.permalink:
        status_text.append(_line("link:", record.permalink), style="blue")

    console.print(status_text, soft_wrap=True)


def _line(label: str, value: str) -> str:
    return f"  {label:<8} {value}"
