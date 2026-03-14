from neo4j import Driver
from src.models.wazuh import ProphetEntity
import logging
import time
from typing import Optional

from src.core.database import Neo4jConnector

logger = logging.getLogger(__name__)

class Neo4jAlertRepository:
    def __init__(self, connector: Optional[Neo4jConnector] = None):
        """Initialize repository. Supports dependency injection for testing."""
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

    def ingest_batch(self, alerts: list[ProphetEntity]):
        """
        Ingest a batch of ProphetEntity into the graph.
        Uses UNWIND for high-performance and scalable MERGE operations.
        Ensures mapping to MITRE ATT&CK schema.
        """
        if not alerts:
            return

        query = """
        UNWIND $batch AS alert
        
        // 1. Merge core Event and Host
        MERGE (e:Event {id: alert.id})
        SET e.timestamp = alert.timestamp, e.type = alert.event_type
        
        MERGE (h:Host {hostname: alert.hostname})
        MERGE (e)-[:OCCURRED_ON]->(h)
        
        // 2. Merge User if present
        FOREACH (ignoreMe IN CASE WHEN alert.user IS NOT NULL THEN [1] ELSE [] END |
            MERGE (u:User {username: alert.user})
            MERGE (u)-[:TRIGGERED]->(e)
        )
        
        // 3. Merge Source IP if present
        FOREACH (ignoreMe IN CASE WHEN alert.source_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (src:IP {address: alert.source_ip})
            MERGE (src)-[:INITIATED]->(e)
        )
        
        // 4. Merge Target IP if present
        FOREACH (ignoreMe IN CASE WHEN alert.target_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (dst:IP {address: alert.target_ip})
            MERGE (e)-[:TARGETED]->(dst)
        )
        
        // 5. Merge MITRE Techniques (STIX pattern)
        FOREACH (tech_id IN alert.mitre_techniques |
            MERGE (t:Technique {technique_id: tech_id})
            MERGE (e)-[:INDICATES]->(t)
        )
        
        // 6. Merge MITRE Tactics (STIX pattern)
        FOREACH (tactic_name IN alert.mitre_tactics |
            MERGE (ta:Tactic {name: tactic_name})
            MERGE (e)-[:INDICATES]->(ta)
        )
        
        // 7. Merge DNS Domain (only when both dns_domain AND target_ip are present)
        FOREACH (ignoreMe IN CASE WHEN alert.dns_domain IS NOT NULL AND alert.target_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (d:Domain {name: alert.dns_domain})
            MERGE (dst:IP {address: alert.target_ip})
            MERGE (dst)-[:RESOLVES_TO]->(d)
        )
        
        // 8. Merge Location
        FOREACH (ignoreMe IN CASE WHEN alert.location_country IS NOT NULL THEN [1] ELSE [] END |
            MERGE (loc:Location {country_name: alert.location_country})
            SET loc.city_name = alert.location_city
            
            // Conectamos la IP que inició el evento a esta geolocalización
            MERGE (src:IP {address: alert.source_ip})
            MERGE (src)-[:LOCATED_IN]->(loc)
        )

        // 9. Merge Mitigations (STIX pattern)
        FOREACH (mitigation IN alert.mitre_mitigations |
            MERGE (m:Mitigation {mitigation_id: mitigation.mitigation_id})
            SET m.description = mitigation.description
            
            // Conectar la mitigación con las técnicas de la misma alerta
            FOREACH (tech_id IN alert.mitre_techniques |
                MERGE (t:Technique {technique_id: tech_id})
                MERGE (m)-[:MITIGATES]->(t)
            )
        )
        """
        
        # Prepare parameters for the UNWIND batch
        batch_params = []
        for alert in alerts:
            batch_params.append({
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "hostname": alert.hostname,
                "event_type": alert.event_type,
                "user": alert.user,
                "source_ip": str(alert.source_ip) if alert.source_ip else None,
                "target_ip": str(alert.target_ip) if alert.target_ip else None,
                "dns_domain": alert.dns_domain,
                "location_country": alert.location_country,
                "location_city": alert.location_city,
                "mitre_techniques": alert.mitre_techniques,
                "mitre_tactics": alert.mitre_tactics,
                "mitre_mitigations": alert.mitre_mitigations
            })

        self._execute_with_retry(query, {"batch": batch_params})

    def _execute_with_retry(self, query: str, params: dict, max_retries: int = 3):
        """Executes a write transaction with exponential backoff for transient errors."""
        for attempt in range(max_retries):
            try:
                if not self._driver:
                    # Fix: Rely on connector, error if not present
                    raise RuntimeError("No Neo4j driver available from connector.")
                
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

    def ingest_alert(self, alert: ProphetEntity):
        """Convenience method to ingest a single ProphetEntity (delegates to ingest_batch)."""
        self.ingest_batch([alert])


# Backwards-compatibility alias — main.py imports Neo4jClient
Neo4jClient = Neo4jAlertRepository
