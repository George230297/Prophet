"""
Unit tests for threat intelligence parsers (services/threat_intelligence/parsers.py).

Complements existing test_threat_intelligence.py which only covers AlienVaultParser
with a happy path. This file covers MISPParser, OTXParser, and edge cases.
"""
import pytest
from src.services.threat_intelligence.parsers import (
    AlienVaultParser,
    MISPParser,
    OTXParser,
)


# ---------------------------------------------------------------------------
# AlienVaultParser edge cases
# ---------------------------------------------------------------------------

class TestAlienVaultParser:
    def test_empty_list_returns_empty(self):
        """Empty raw_data list should produce no results."""
        parser = AlienVaultParser()
        assert parser.parse([]) == []

    def test_null_indicator_passes_through(self):
        """An item without 'indicator' key should set indicator to None."""
        parser = AlienVaultParser()
        result = parser.parse([{"type": "IPv4"}])
        assert result[0]["indicator"] is None

    def test_unknown_type_defaults_to_unknown(self):
        """Missing 'type' key should default to 'unknown'."""
        parser = AlienVaultParser()
        result = parser.parse([{"indicator": "1.1.1.1"}])
        assert result[0]["type"] == "unknown"

    def test_multiple_indicators_parsed(self):
        """Multiple items should produce the same number of results."""
        parser = AlienVaultParser()
        raw = [{"indicator": f"1.1.1.{i}", "type": "IPv4"} for i in range(5)]
        result = parser.parse(raw)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# MISPParser tests
# ---------------------------------------------------------------------------

class TestMISPParser:
    def test_parses_attributes_correctly(self):
        """Standard MISP event dict should parse each attribute."""
        parser = MISPParser()
        raw = {
            "Attribute": [
                {"value": "evil.com", "type": "domain"},
                {"value": "192.168.99.1", "type": "ip-src"},
            ]
        }
        result = parser.parse(raw)

        assert len(result) == 2
        assert result[0]["indicator"] == "evil.com"
        assert result[0]["type"] == "domain"
        assert result[0]["source"] == "MISP"
        assert result[1]["indicator"] == "192.168.99.1"

    def test_empty_attribute_list_returns_empty(self):
        """MISP event with no attributes should return empty list."""
        parser = MISPParser()
        result = parser.parse({"Attribute": []})
        assert result == []

    def test_missing_attribute_key_returns_empty(self):
        """MISP event dict without 'Attribute' key should return empty list."""
        parser = MISPParser()
        result = parser.parse({})
        assert result == []

    def test_attribute_missing_type_defaults_to_unknown(self):
        """Attribute without 'type' key defaults to 'unknown'."""
        parser = MISPParser()
        result = parser.parse({"Attribute": [{"value": "hash123"}]})
        assert result[0]["type"] == "unknown"

    def test_result_contains_timestamp(self):
        """Each normalized result must include an ISO timestamp."""
        parser = MISPParser()
        result = parser.parse({"Attribute": [{"value": "test", "type": "text"}]})
        assert "timestamp" in result[0]


# ---------------------------------------------------------------------------
# OTXParser tests
# ---------------------------------------------------------------------------

class TestOTXParser:
    def test_parses_nested_pulses_and_indicators(self):
        """Standard OTX response structure should produce flattened results."""
        parser = OTXParser()
        raw = {
            "pulses": [
                {
                    "indicators": [
                        {"indicator": "3.3.3.3", "type": "IPv4"},
                        {"indicator": "bad.ru", "type": "domain"},
                    ]
                },
                {
                    "indicators": [
                        {"indicator": "4.4.4.4", "type": "IPv4"},
                    ]
                }
            ]
        }
        result = parser.parse(raw)

        assert len(result) == 3
        assert result[0]["indicator"] == "3.3.3.3"
        assert result[0]["source"] == "OTX"
        assert result[2]["indicator"] == "4.4.4.4"

    def test_empty_pulses_returns_empty(self):
        """OTX response with no pulses should return empty list."""
        parser = OTXParser()
        assert parser.parse({"pulses": []}) == []

    def test_missing_pulses_key_returns_empty(self):
        """OTX response without 'pulses' key should return empty list."""
        parser = OTXParser()
        assert parser.parse({}) == []

    def test_pulse_with_no_indicators_produces_no_results(self):
        """A pulse with an empty indicators list should contribute nothing."""
        parser = OTXParser()
        result = parser.parse({"pulses": [{"indicators": []}]})
        assert result == []
