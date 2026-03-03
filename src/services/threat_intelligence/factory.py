from typing import Dict, Type
from .parsers import ThreatFeedParser, AlienVaultParser, MISPParser, OTXParser

class ThreatFeedFactory:
    _parsers: Dict[str, Type[ThreatFeedParser]] = {
        "AlienVault": AlienVaultParser,
        "MISP": MISPParser,
        "OTX": OTXParser
    }

    @staticmethod
    def get_parser(source_name: str) -> ThreatFeedParser:
        """Factory method to get the appropriate parser."""
        parser_class = ThreatFeedFactory._parsers.get(source_name)
        if not parser_class:
            raise ValueError(f"Unknown threat feed source: {source_name}")
        return parser_class()
