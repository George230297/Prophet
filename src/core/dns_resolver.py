import socket
from typing import Optional
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

class DNSResolver:
    """
    A simple thread-safe synchronous DNS resolver with an LRU cache
    to avoid blocking the ETL pipeline due to repetitive DNS lookups.
    """

    @staticmethod
    @lru_cache(maxsize=1000)
    def resolve_ip(ip_address: str) -> Optional[str]:
        """
        Attempts to resolve an IP address to a hostname.
        Uses lru_cache to memorize up to 1000 typical resolutions.
        Returns None if resolution fails (e.g. no PTR record or timeout).
        """
        if not ip_address:
            return None
        
        try:
            # gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except Exception as e:
            # Common exceptions are socket.herror (Host not found)
            logger.debug(f"DNS resolution failed for {ip_address}: {e}")
            return None
