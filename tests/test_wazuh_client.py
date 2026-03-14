"""
Unit tests for WazuhClient (services/wazuh_client.py).

Tests cover:
- _authenticate: success (token stored), invalid response format, network error
- get_alerts: normal path, 401 token refresh, 404 handling, network error
"""
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import requests

from src.services.wazuh_client import WazuhClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code=200, json_data=None):
    """Builds a mock requests.Response object."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    # raise_for_status raises only for 4xx/5xx
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=response
        )
    else:
        response.raise_for_status.return_value = None
    return response


# ---------------------------------------------------------------------------
# _authenticate tests
# ---------------------------------------------------------------------------

def test_authenticate_sets_token(mocker):
    """A successful auth response must populate client.token."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = None
    client.timeout = 10

    client.session.post.return_value = _mock_response(
        200, {"data": {"token": "jwt-abc123"}}
    )

    client._authenticate()

    assert client.token == "jwt-abc123"


def test_authenticate_raises_on_missing_token_key(mocker):
    """If the response JSON doesn't contain data.token, ValueError must be raised."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = None
    client.timeout = 10

    client.session.post.return_value = _mock_response(200, {"data": {}})

    with pytest.raises(ValueError, match="Could not retrieve token"):
        client._authenticate()


def test_authenticate_raises_on_network_error(mocker):
    """A RequestException during auth must propagate upward."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = None
    client.timeout = 10

    client.session.post.side_effect = requests.exceptions.ConnectionError("refused")

    with pytest.raises(requests.exceptions.ConnectionError):
        client._authenticate()


# ---------------------------------------------------------------------------
# get_alerts tests
# ---------------------------------------------------------------------------

def test_get_alerts_returns_items(mocker):
    """Normal 200 response should return the items list."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = "valid-token"
    client.timeout = 10

    items = [{"id": "1", "rule": {}}, {"id": "2", "rule": {}}]
    client.session.get.return_value = _mock_response(
        200, {"data": {"items": items}}
    )

    result = client.get_alerts(limit=10)

    assert result == items
    assert client.session.get.call_count == 1


def test_get_alerts_reauthenticates_on_401(mocker):
    """A 401 must trigger re-authentication and a second GET request."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = "expired-token"
    client.timeout = 10

    auth_response = _mock_response(401, {})
    auth_response.raise_for_status.side_effect = None  # 401 handled manually, not via raise_for_status
    success_response = _mock_response(200, {"data": {"items": []}})

    client.session.get.side_effect = [auth_response, success_response]

    with patch.object(client, "_authenticate") as mock_auth:
        result = client.get_alerts()
        mock_auth.assert_called_once()

    assert result == []
    assert client.session.get.call_count == 2


def test_get_alerts_returns_empty_on_404(mocker):
    """A 404 should be handled gracefully, returning an empty list."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = "valid-token"
    client.timeout = 10

    client.session.get.return_value = _mock_response(404, {})

    result = client.get_alerts()

    assert result == []


def test_get_alerts_returns_empty_on_network_error(mocker):
    """A RequestException during get_alerts must be caught, returning empty list."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = "valid-token"
    client.timeout = 10

    client.session.get.side_effect = requests.exceptions.ConnectionError("timeout")

    result = client.get_alerts()

    assert result == []


def test_get_alerts_returns_empty_when_data_key_missing(mocker):
    """If the response JSON lacks 'data.items', return empty list (no KeyError)."""
    client = WazuhClient.__new__(WazuhClient)
    client.base_url = "https://mock-wazuh"
    client.session = MagicMock()
    client.token = "valid-token"
    client.timeout = 10

    client.session.get.return_value = _mock_response(200, {"status": "ok"})

    result = client.get_alerts()

    assert result == []
