"""Token-exchange client authentication: confidential vs public clients."""

from __future__ import annotations

import httpx

from crudauth.oauth.providers.google import GoogleOAuthProvider


def _fake_async_client(captured: dict):
    """An httpx.AsyncClient stand-in that records the POST it receives."""

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"access_token": "tok", "token_type": "Bearer"}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, data=None, headers=None):
            captured["url"] = url
            captured["data"] = dict(data)
            captured["headers"] = dict(headers or {})
            return FakeResponse()

    return FakeAsyncClient


# --- confidential client (has a secret): client auth rides in the body --------
async def test_exchange_code_sends_secret_for_confidential_client(monkeypatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_async_client(captured))

    prov = GoogleOAuthProvider("cid", "s3cret", "https://app/cb")
    result = await prov.exchange_code("code-1", code_verifier="ver-1")

    assert result["access_token"] == "tok"
    assert captured["data"]["client_secret"] == "s3cret"
    assert captured["data"]["code_verifier"] == "ver-1"
    assert captured["data"]["grant_type"] == "authorization_code"


# --- public client (no secret): the field must be absent, not empty -----------
async def test_exchange_code_omits_secret_for_public_client(monkeypatch) -> None:
    # A PKCE-only public client (token_endpoint_auth_method=none) must not send
    # client authentication; several IdPs reject client_secret="" outright.
    captured: dict = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_async_client(captured))

    prov = GoogleOAuthProvider("cid", "", "https://app/cb")
    await prov.exchange_code("code-1", code_verifier="ver-1")

    assert "client_secret" not in captured["data"]
    assert captured["data"]["client_id"] == "cid"
    assert captured["data"]["code_verifier"] == "ver-1"
    assert captured["data"]["grant_type"] == "authorization_code"
