from neo4j import GraphDatabase, Driver, basic_auth
from src.config.settings import settings
from src.models.wazuh import ProphetEntity
import logging
import time
from typing import Optional

# Setup basic logger
logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=settings.log_level)

from src.core.database import Neo4jConnector

class Neo4jClient:
    def __init__(self, connector: Optional[Neo4jConnector] = None):
        """Initialize client. Supports dependency injection for testing."""
        self.connector = connector if connector else Neo4jConnector()

    @property
    def _driver(self) -> Driver:
        """Access the driver from the connector."""
        return self.connector.get_driver()

    def close(self):
        """Close the driver connection via connector."""
        self.connector.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def ingest_alert(self, alert: ProphetEntity):
        """
        Ingest a ProphetEntity into the graph.
        Uses idempotent MERGE operations.
        """
        query = """
        MERGE (e:Event {
            timestamp: $timestamp, 
            hostname: $hostname, 
            type: $event_type
        })
        
        MERGE (h:Host {hostname: $hostname})
        MERGE (e)-[:OCCURRED_ON]->(h)
        
        FOREACH (ignoreMe IN CASE WHEN $user IS NOT NULL THEN [1] ELSE [] END |
            MERGE (u:User {username: $user})
            MERGE (u)-[:TRIGGERED]->(e)
        )
        
        FOREACH (ignoreMe IN CASE WHEN $source_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (src:IP {address: $source_ip})
            MERGE (src)-[:INITIATED]->(e)
        )
        
        FOREACH (ignoreMe IN CASE WHEN $target_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (dst:IP {address: $target_ip})
            MERGE (e)-[:TARGETED]->(dst)
        )
        """
        
        # Prepare parameters (Convert standard types if needed)
        params = {
            "timestamp": alert.timestamp.isoformat(),
            "hostname": alert.hostname,
            "event_type": alert.event_type,
            "user": alert.user,
            "source_ip": str(alert.source_ip) if alert.source_ip else None,
            "target_ip": str(alert.target_ip) if alert.target_ip else None
        }

        self._execute_with_retry(query, params)

    def _execute_with_retry(self, query: str, params: dict, max_retries: int = 3):
        """Executes a write transaction with exponential backoff for transient errors."""
        for attempt in range(max_retries):
            try:
                if not self._driver:
                    self._connect()
                
                with self._driver.session() as session:
                    session.execute_write(lambda tx: tx.run(query, **params))
                return
            except Exception as e:
                wait_time = 2 ** attempt
                logger.warning(f"Neo4j transaction failed (Attempt {attempt+1}/{max_retries}). Retrying in {wait_time}s. Error: {e}")
                if attempt == max_retries - 1:
                    logger.error("Max retries reached. Transaction failed.")
                    raise e
                time.sleep(wait_time)
