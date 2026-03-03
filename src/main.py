import time
import sys
import logging
from typing import Dict, Any, Optional

from src.config.settings import settings
from src.services.wazuh_client import WazuhClient
from src.services.graph_service import Neo4jClient
from src.models.wazuh import WazuhAlert
from src.core.logging import setup_logging

# --- Logging Configuration ---
setup_logging()
logger = logging.getLogger("prophet.main")

def main():
    logger.info("Starting Prophet Middleware...")
    
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--analyze":
            logger.info("Running Analysis Mode...")
            from src.services.analysis_service import AnalysisService
            
            analysis_service = AnalysisService()
            
            logger.info("Detecting Lateral Movement...")
            paths = analysis_service.detect_lateral_movement()
            if paths:
                logger.warning(f"Found {len(paths)} potential lateral movement paths:")
                for path in paths:
                    logger.warning(f"  [!] User '{path.user}' moved from {path.source_host} to {path.target_host} ({path.confidence_score*100:.1f}% confidence)")
            else:
                logger.info("No lateral movement detected.")
                
            logger.info("Detecting Suspicious IP Chains...")
            chains = analysis_service.detect_suspicious_ip_chains()
            if chains:
                 logger.warning(f"Found {len(chains)} suspicious IP chains:")
                 for chain in chains:
                     logger.warning(f"  [!] {chain.description}")
            else:
                logger.info("No suspicious IP chains detected.")
                
            sys.exit(0)

        # Instance Clients
        wazuh_client = WazuhClient()
        neo4j_client = Neo4jClient()
    except Exception as e:
        logger.critical(f"Failed to initialize clients: {e}")
        sys.exit(1)

    try:
        while True:
            try:
                # 1. Fetch Alerts
                alerts = wazuh_client.get_alerts(limit=50)
                
                if alerts:
                    logger.info(f"Processing {len(alerts)} alerts...")
                    processed_count = 0
                    
                    for raw_alert_data in alerts:
                        try:
                            # 2. Normalize (using domain model method)
                            # First wrap in Pydantic model
                            alert = WazuhAlert(**raw_alert_data)
                            entity = alert.to_entity()
                            
                            # 3. Ingest
                            neo4j_client.ingest_alert(entity)
                            processed_count += 1
                            
                        except Exception as inner_e:
                            logger.error(f"Error processing individual alert {raw_alert_data.get('id')}: {inner_e}")
                            continue

                    logger.info(f"Processed {processed_count} alerts.")
                else:
                    logger.debug("No new alerts found.")

                # 4. Sleep
                time.sleep(settings.polling_interval)

            except Exception as e:
                logger.exception("Unexpected error in main loop. Retrying in 5 seconds...")
                time.sleep(5)

    except KeyboardInterrupt:
        logger.info("Apagando Prophet...")
        try:
            neo4j_client.close()
        except:
            pass
        sys.exit(0)

if __name__ == "__main__":
    main()
