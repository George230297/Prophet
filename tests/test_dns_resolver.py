"""
Unit tests for DNSResolver (core/dns_resolver.py).

Tests cover:
- Successful IP → hostname resolution (mocked socket)
- socket.herror / generic exception → returns None
- Empty-string input → returns None immediately (no DNS call made)
- LRU cache: same IP resolves only once per test (cache cleared between tests)
"""
import socket
import pytest
from unittest.mock import patch

from src.core.dns_resolver import DNSResolver


@pytest.fixture(autouse=True)
def clear_lru_cache():
    """Clear LRU cache before each test to prevent state pollution."""
    DNSResolver.resolve_ip.cache_clear()
    yield
    DNSResolver.resolve_ip.cache_clear()


def test_resolve_ip_returns_hostname():
    """Should return the hostname string when gethostbyaddr succeeds."""
    with patch("socket.gethostbyaddr", return_value=("my-host.local", [], ["1.2.3.4"])):
        result = DNSResolver.resolve_ip("1.2.3.4")
    assert result == "my-host.local"


def test_resolve_ip_returns_none_on_socket_herror():
    """socket.herror (no PTR record) should yield None without raising."""
    with patch("socket.gethostbyaddr", side_effect=socket.herror(1, "Host not found")):
        result = DNSResolver.resolve_ip("10.0.0.1")
    assert result is None


def test_resolve_ip_returns_none_on_generic_exception():
    """Any unexpected exception from gethostbyaddr should yield None."""
    with patch("socket.gethostbyaddr", side_effect=OSError("timeout")):
        result = DNSResolver.resolve_ip("10.0.0.2")
    assert result is None


def test_resolve_ip_returns_none_for_empty_string():
    """Empty string must short-circuit and return None without any DNS call."""
    with patch("socket.gethostbyaddr") as mock_dns:
        result = DNSResolver.resolve_ip("")
        mock_dns.assert_not_called()
    assert result is None


def test_resolve_ip_is_cached():
    """The same IP address should only trigger one real DNS call (LRU cache hit)."""
    with patch("socket.gethostbyaddr", return_value=("cached-host", [], ["5.5.5.5"])) as mock_dns:
        result1 = DNSResolver.resolve_ip("5.5.5.5")
        result2 = DNSResolver.resolve_ip("5.5.5.5")

    mock_dns.assert_called_once()
    assert result1 == result2 == "cached-host"
