import pytest
from src.services.threat_intelligence.factory import ThreatFeedFactory
from src.services.threat_intelligence.parsers import AlienVaultParser, MISPParser

def test_factory_creates_correct_parsers():
    """Test that factory returns correct parser instances."""
    assert isinstance(ThreatFeedFactory.get_parser("AlienVault"), AlienVaultParser)
    assert isinstance(ThreatFeedFactory.get_parser("MISP"), MISPParser)

def test_factory_invalid_source():
    """Test that factory raises error for unknown source."""
    with pytest.raises(ValueError):
        ThreatFeedFactory.get_parser("UnknownSource")

def test_alienvault_parser_format():
    """Test AlienVault parser output format."""
    parser = AlienVaultParser()
    raw_data = [{"indicator": "1.2.3.4", "type": "IPv4"}]
    
    results = parser.parse(raw_data)
    
    assert len(results) == 1
    assert results[0]["indicator"] == "1.2.3.4"
    assert results[0]["source"] == "AlienVault"
    assert "timestamp" in results[0]
