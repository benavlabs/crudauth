"""Unit tests for get_client_ip and the trusted-proxy-hops boundary."""

from __future__ import annotations

from starlette.requests import Request

from crudauth.utils import get_client_ip


def _request(headers: dict[str, str] | None = None, client_host: str = "10.0.0.1") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
            "client": (client_host, 1234),
        }
    )


def test_get_client_ip_ignores_xff_without_trusted_hops() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_uses_socket_peer_by_default() -> None:
    assert get_client_ip(_request(client_host="203.0.113.9")) == "203.0.113.9"


def test_get_client_ip_single_trusted_hop() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=1) == "1.2.3.4"


def test_get_client_ip_ignores_prepended_spoof() -> None:
    # Attacker prepends a fake left-most value; one trusted hop reads the
    # right-most entry (set by our proxy), not the spoof.
    req = _request({"x-forwarded-for": "9.9.9.9, 1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=1) == "1.2.3.4"


def test_get_client_ip_two_trusted_hops() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4, 172.16.0.1"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=2) == "1.2.3.4"


def test_get_client_ip_chain_shorter_than_hops_clamps_to_leftmost() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=5) == "1.2.3.4"
