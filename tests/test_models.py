import pytest
from datetime import datetime
from src.models.wazuh import WazuhAlert, ProphetEntity

def test_wazuh_alert_normalization():
    """Test normalization from WazuhAlert to ProphetEntity."""
    raw_data = {
        "timestamp": "2023-10-27T10:00:00",
        "rule": {"description": "SSH Failed Login", "id": "5710"},
        "agent": {"name": "web-server-01", "id": "001"},
        "manager": {"name": "wazuh-manager"},
        "id": "12345",
        "location": "/var/log/auth.log",
        "data": {
            "srcip": "192.168.1.100",
            "dstip": "10.0.0.5",
            "user": "admin"
        }
    }
    
    alert = WazuhAlert(**raw_data)
    entity = alert.to_entity()
    
    assert entity.event_type == "SSH Failed Login"
    assert entity.hostname == "web-server-01"
    assert entity.user == "admin"
    assert str(entity.source_ip) == "192.168.1.100"
    assert str(entity.target_ip) == "10.0.0.5"

def test_prophet_entity_sanitization():
    """Test input sanitization for ProphetEntity."""
    entity = ProphetEntity(
        event_type="test_event",
        timestamp=datetime.now(),
        hostname="malicious<script>host",
        user="user; DROP TABLE students; --"
    )
    
    # Check if dangerous chars were removed
    assert "<" not in entity.hostname
    assert ";" not in entity.user
    # The sanitization only removes non-alphanumeric chars, not keywords.
    # So 'DROP' remains, but the semicolon and spaces are gone, rendering it harmless as a command.
    assert entity.hostname == "maliciousscripthost"
    assert entity.user == "userDROPTABLEstudents--"
