from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from jwvtscore.vt_client import ConfigurationError, VirusTotalClient, VirusTotalError


def make_transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_from_env_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    with pytest.raises(ConfigurationError):
        VirusTotalClient.from_env()


def test_lookup_hash_uses_hash_only_path() -> None:
    seen: dict[str, str | bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["body"] = request.read()
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 67,
                            "suspicious": 0,
                            "malicious": 0,
                            "undetected": 5,
                        }
                    },
                    "links": {"self": "https://www.virustotal.com/api/v3/files/abc"},
                }
            },
        )

    client = VirusTotalClient("token", transport=make_transport(handler))
    result = client.lookup_hash("abc")
    client.close()

    assert result.found is True
    assert result.status == "clean"
    assert result.permalink == "https://www.virustotal.com/gui/file/abc"
    assert seen["method"] == "GET"
    seen_url = seen["url"]
    assert isinstance(seen_url, str)
    assert seen_url.endswith("/files/abc")
    assert seen["body"] == b""


def test_lookup_hash_returns_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    client = VirusTotalClient("token", transport=make_transport(handler))
    result = client.lookup_hash("missing")
    client.close()

    assert result.found is False
    assert result.status == "not_found"


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (401, "API key"),
        (429, "rate limit"),
        (500, "HTTP 500"),
    ],
)
def test_lookup_hash_raises_for_api_errors(status_code: int, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={})

    client = VirusTotalClient("token", transport=make_transport(handler))
    with pytest.raises(VirusTotalError, match=message):
        client.lookup_hash("abc")
    client.close()
