from abc import ABC, abstractmethod
from typing import List, Dict, Any
import datetime

class ThreatFeedParser(ABC):
    @abstractmethod
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Parses raw data into a normalized format."""
        pass

    def _normalize(self, indicator: str, type_: str, source: str) -> Dict[str, Any]:
        """Helper to create a normalized dictionary."""
        return {
            "indicator": indicator,
            "type": type_,
            "source": source,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

class AlienVaultParser(ThreatFeedParser):
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        # Mock implementation assuming raw_data is a list of indicators
        # In a real scenario, this would parse OTX SDK response or simple JSON
        results = []
        for item in raw_data:
            results.append(self._normalize(
                indicator=item.get("indicator"),
                type_=item.get("type", "unknown"),
                source="AlienVault"
            ))
        return results

class MISPParser(ThreatFeedParser):
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        # Mock implementation for MISP events
        results = []
        # Assuming raw_data is a MISP event dict with 'Attribute' list
        attributes = raw_data.get("Attribute", [])
        for attr in attributes:
            results.append(self._normalize(
                indicator=attr.get("value"),
                type_=attr.get("type", "unknown"),
                source="MISP"
            ))
        return results

class OTXParser(ThreatFeedParser):
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        # Mock implementation
        results = []
        for pulse in raw_data.get("pulses", []):
            for indicator in pulse.get("indicators", []):
                 results.append(self._normalize(
                    indicator=indicator.get("indicator"),
                    type_=indicator.get("type", "unknown"),
                    source="OTX"
                ))
        return results
