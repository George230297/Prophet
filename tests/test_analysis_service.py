
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta
from src.services.analysis_service import AnalysisService
from src.core.database import Neo4jConnector

@pytest.fixture
def mock_connector():
    connector = MagicMock(spec=Neo4jConnector)
    driver = MagicMock()
    session = MagicMock()
    connector.get_driver.return_value = driver
    driver.session.return_value.__enter__.return_value = session
    return connector, session

def test_detect_lateral_movement(mock_connector):
    connector, session = mock_connector
    service = AnalysisService(connector=connector)
    
    # Mock return data
    mock_record = {
        "user": "alice",
        "source_host": "host-a",
        "target_host": "host-b",
        "event1": {
            "timestamp": "2023-10-27T10:00:00",
            "type": "logon",
            "hostname": "host-a"
        },
        "event2": {
            "timestamp": "2023-10-27T10:05:00",
            "type": "logon",
            "hostname": "host-b"
        }
    }
    
    # Session.run returns an iterator of records
    session.run.return_value = [mock_record]
    
    results = service.detect_lateral_movement()
    
    assert len(results) == 1
    path = results[0]
    assert path.user == "alice"
    assert path.source_host == "host-a"
    assert path.target_host == "host-b"
    assert path.timestamp_end > path.timestamp_start
    assert path.confidence_score == 0.85

def test_detect_suspicious_ip_chains(mock_connector):
    connector, session = mock_connector
    service = AnalysisService(connector=connector)
    
    # Mock Neo4j Nodes as dicts for simplicity as our service converts them
    mock_record = {
        "ip1": {"address": "192.168.1.10"},
        "e": {"type": "scan", "timestamp": "2023-10-27T12:00:00"},
        "ip2": {"address": "10.0.0.5"}
    }
    
    session.run.return_value = [mock_record]
    
    results = service.detect_suspicious_ip_chains()
    
    assert len(results) == 1
    chain = results[0]
    assert chain.chain_type == "IP Hopping"
    assert len(chain.nodes) == 3
    assert chain.nodes[0].label == "IP"
    assert chain.nodes[0].properties["address"] == "192.168.1.10"
