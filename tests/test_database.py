import pytest
from unittest.mock import MagicMock, patch
from src.core.database import Neo4jConnector

def test_neo4j_connector_singleton(mocker):
    """Test that Neo4jConnector acts as a Singleton."""
    # Reset singleton for testing
    Neo4jConnector._instance = None
    
    # Mock driver to avoid real connection attempt
    mocker.patch("neo4j.GraphDatabase.driver")
    
    conn1 = Neo4jConnector()
    conn2 = Neo4jConnector()
    
    assert conn1 is conn2
    assert conn1.get_driver() is conn2.get_driver()

def test_neo4j_connector_connection_failure(mocker):
    """Test handling of connection failure."""
    Neo4jConnector._instance = None
    
    # Mock driver to raise exception
    mock_driver = mocker.patch("neo4j.GraphDatabase.driver")
    mock_driver.side_effect = Exception("Connection refused")
    
    # Should not raise exception, but log error
    conn = Neo4jConnector()
    assert conn.get_driver() is None
