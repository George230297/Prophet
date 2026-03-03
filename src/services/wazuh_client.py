import requests
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from typing import List, Dict, Any, Optional
import urllib3

from src.config.settings import settings

# Setup logger
logger = logging.getLogger(__name__)

# Suppress insecure request warnings if SSL verification is disabled
if not settings.wazuh_verify_ssl:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.warning("SECURITY WARNING: SSL verification is disabled for Wazuh API connections.")

class WazuhClient:
    def __init__(self):
        self.base_url = settings.wazuh_url.rstrip('/')
        self.session = requests.Session()
        self.token: Optional[str] = None
        
        # Configure retry strategy
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        
        # Security: Default timeout for all requests
        self.timeout = 10  # seconds

    def _get_headers(self) -> Dict[str, str]:
        """Returns headers with JWT token if available."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _authenticate(self) -> None:
        """
        Authenticates with Wazuh API to obtain a JWT token.
        Uses Basic Auth to retrieve the token from /security/user/authenticate.
        """
        url = f"{self.base_url}/security/user/authenticate"
        
        # Using requests auth parameter which handles Base64 encoding automatically
        # equivalent to: Authorization: Basic base64(user:pass)
        try:
            response = self.session.post(
                url,
                auth=(settings.wazuh_user, settings.wazuh_password),
                verify=settings.wazuh_verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            if "data" in data and "token" in data["data"]:
                self.token = data["data"]["token"]
                logger.info("Successfully authenticated with Wazuh API")
            else:
                logger.error(f"Authentication failed: Unexpected response format: {data}")
                raise ValueError("Could not retrieve token from response")

        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            raise

    def get_alerts(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Fetches the latest alerts from Wazuh.
        Tries to fetch from /manager/alerts (simulated/placeholder).
        """
        if not self.token:
            self._authenticate()

        # NOTE: 'GET /manager/alerts' is the requested endpoint path. 
        # In some Wazuh versions this might need to be '/analysis/security/events' or query via Indexer.
        url = f"{self.base_url}/manager/alerts" 
        
        params = {
            "limit": limit,
            "sort": "-timestamp" 
        }

        try:
            response = self.session.get(
                url,
                headers=self._get_headers(),
                params=params,
                verify=settings.wazuh_verify_ssl,
                timeout=self.timeout
            )

            # Handle Token Expiration
            if response.status_code == 401:
                logger.warning("Token expired or invalid. Re-authenticating...")
                self._authenticate()
                # Retry request once
                response = self.session.get(
                    url,
                    headers=self._get_headers(),
                    params=params,
                    verify=settings.wazuh_verify_ssl,
                    timeout=self.timeout
                )

            # If the endpoint doesn't exist (404), we might return empty list gracefully for this MVP
            # to prevent crashing if the user provided URL is just the base.
            if response.status_code == 404:
                logger.error(f"The endpoint {url} was not found (404). Check Wazuh API version/URL.")
                return []

            response.raise_for_status()
            
            data = response.json()
            if "data" in data and "items" in data["data"]:
                return data["data"]["items"]
            return []

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []
