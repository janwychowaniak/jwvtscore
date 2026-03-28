from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

VT_BASE_URL = "https://www.virustotal.com/api/v3/files"


class ConfigurationError(RuntimeError):
    """Raised when required local configuration is missing."""


class VirusTotalError(RuntimeError):
    """Raised for remote API or transport failures."""


@dataclass(slots=True)
class LookupResult:
    found: bool
    status: str
    stats: dict[str, int] | None
    permalink: str | None


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=VT_BASE_URL,
            headers={"x-apikey": api_key},
            timeout=timeout,
            transport=transport,
        )

    @classmethod
    def from_env(
        cls,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> "VirusTotalClient":
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise ConfigurationError("VIRUSTOTAL_API_KEY is not set.")
        return cls(api_key, timeout=timeout, transport=transport)

    def close(self) -> None:
        self._client.close()

    def lookup_hash(self, file_hash: str) -> LookupResult:
        try:
            response = self._client.get(f"/{file_hash}")
        except httpx.HTTPError as exc:
            raise VirusTotalError(f"VirusTotal request failed: {exc}") from exc

        if response.status_code == httpx.codes.NOT_FOUND:
            return LookupResult(found=False, status="not_found", stats=None, permalink=None)
        if response.status_code == httpx.codes.UNAUTHORIZED:
            raise VirusTotalError("VirusTotal rejected the API key.")
        if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
            raise VirusTotalError("VirusTotal rate limit exceeded.")
        if response.is_error:
            raise VirusTotalError(f"VirusTotal returned HTTP {response.status_code}.")

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        status = _classify_status(stats)
        permalink = f"https://www.virustotal.com/gui/file/{file_hash}"

        return LookupResult(found=True, status=status, stats=stats, permalink=permalink)


def _classify_status(stats: dict[str, int]) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"
