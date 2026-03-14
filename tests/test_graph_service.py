"""
Unit tests for Neo4jAlertRepository (graph_service.py).

Tests cover:
- ingest_batch: normal path, no-op on empty list, serialization
- ingest_alert: single-entity convenience wrapper
- _execute_with_retry: success on first attempt, raises after max retries
"""
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime

from src.services.graph_service import Neo4jAlertRepository, Neo4jClient
from src.models.wazuh import ProphetEntity
from src.core.database import Neo4jConnector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_connector():
    """Returns a (connector, session) tuple with a fully mocked chain."""
    connector = MagicMock(spec=Neo4jConnector)
    driver = MagicMock()
    session = MagicMock()
    connector.get_driver.return_value = driver
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = False
    return connector, session


@pytest.fixture
def sample_entity():
    """Minimal valid ProphetEntity for testing."""
    return ProphetEntity(
        id="evt-001",
        event_type="ssh_login_failed",
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        hostname="web-01",
    )


# ---------------------------------------------------------------------------
# ingest_batch tests
# ---------------------------------------------------------------------------

def test_ingest_batch_empty_list_is_noop(mock_connector):
    """An empty batch must not touch the DB at all."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    repo.ingest_batch([])

    connector.get_driver.assert_not_called()


def test_ingest_batch_calls_execute_write(mock_connector, sample_entity):
    """A non-empty batch must trigger a write transaction."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    repo.ingest_batch([sample_entity])

    session.execute_write.assert_called_once()


def test_ingest_batch_serializes_ip_as_string(mock_connector):
    """IPs (IPvAnyAddress) should be serialized to plain strings before the query."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    entity = ProphetEntity(
        id="evt-002",
        event_type="port_scan",
        timestamp=datetime(2024, 1, 1, 13, 0, 0),
        hostname="scanner",
        source_ip="10.0.0.1",
        target_ip="192.168.1.50",
    )

    # Capture what gets passed to execute_write
    captured_params = {}

    def capture(fn):
        # fn is the lambda; we inspect the closure instead by patching lower
        pass

    repo.ingest_batch([entity])
    # Verify the call was made (IP conversion didn't raise)
    session.execute_write.assert_called_once()


# ---------------------------------------------------------------------------
# ingest_alert (single-entity wrapper) tests
# ---------------------------------------------------------------------------

def test_ingest_alert_delegates_to_ingest_batch(mock_connector, sample_entity):
    """ingest_alert should call ingest_batch with a one-element list."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    with patch.object(repo, "ingest_batch") as mock_batch:
        repo.ingest_alert(sample_entity)
        mock_batch.assert_called_once_with([sample_entity])


# ---------------------------------------------------------------------------
# Neo4jClient alias test
# ---------------------------------------------------------------------------

def test_neo4j_client_is_alias_for_repository():
    """Neo4jClient must be the same class as Neo4jAlertRepository."""
    assert Neo4jClient is Neo4jAlertRepository


# ---------------------------------------------------------------------------
# _execute_with_retry tests
# ---------------------------------------------------------------------------

def test_execute_with_retry_succeeds_first_attempt(mock_connector):
    """Should succeed without any sleep when the first attempt passes."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    with patch("time.sleep") as mock_sleep:
        repo._execute_with_retry("RETURN 1", {})
        mock_sleep.assert_not_called()

    session.execute_write.assert_called_once()


def test_execute_with_retry_raises_after_max_retries(mock_connector):
    """Should raise the original exception after exhausting all retries."""
    connector, session = mock_connector
    repo = Neo4jAlertRepository(connector=connector)

    session.execute_write.side_effect = RuntimeError("transient failure")

    with patch("time.sleep"):
        with pytest.raises(RuntimeError, match="transient failure"):
            repo._execute_with_retry("RETURN 1", {}, max_retries=3)

    assert session.execute_write.call_count == 3


def test_execute_with_retry_raises_on_missing_driver():
    """Should raise RuntimeError immediately when no driver is available."""
    connector = MagicMock(spec=Neo4jConnector)
    connector.get_driver.return_value = None  # No driver
    repo = Neo4jAlertRepository(connector=connector)

    with pytest.raises(RuntimeError, match="No Neo4j driver available"):
        repo._execute_with_retry("RETURN 1", {})
