from typing import List, Dict, Any
from datetime import datetime
import logging
from src.core.database import Neo4jConnector
from src.models.analysis_results import LateralMovementPath, SuspiciousChain, GraphNode

logger = logging.getLogger(__name__)

class AnalysisService:
    def __init__(self, connector: Neo4jConnector = None):
        self.connector = connector if connector else Neo4jConnector()

    @property
    def _driver(self):
        return self.connector.get_driver()

    def detect_lateral_movement(self, time_window_minutes: int = 60) -> List[LateralMovementPath]:
        """
        Detects lateral movement patterns where a user logs into Host A and then Host B
        within a specific time window.
        
        Pattern: (Host A)<-[:OCCURRED_ON]-(Event 1)<-[:TRIGGERED]-(User)-[:TRIGGERED]->(Event 2)-[:OCCURRED_ON]->(Host B)
        Constraint: E1.timestamp < E2.timestamp < E1.timestamp + window
        Relationship: Host A != Host B
        """
        query = """
        MATCH (h1:Host)<-[:OCCURRED_ON]-(e1:Event)<-[:TRIGGERED]-(u:User)-[:TRIGGERED]->(e2:Event)-[:OCCURRED_ON]->(h2:Host)
        WHERE h1 <> h2
          AND e1.timestamp < e2.timestamp
          AND datetime(e2.timestamp) < datetime(e1.timestamp) + duration({minutes: $window})
        RETURN 
            u.username as user,
            h1.hostname as source_host, 
            h2.hostname as target_host,
            e1 as event1,
            e2 as event2
        ORDER BY e1.timestamp DESC
        """
        
        results = []
        try:
            with self._driver.session() as session:
                records = session.run(query, window=time_window_minutes)
                
                for record in records:
                    e1_props = dict(record["event1"])
                    e2_props = dict(record["event2"])
                    
                    path = LateralMovementPath(
                        user=record["user"],
                        source_host=record["source_host"],
                        target_host=record["target_host"],
                        events=[e1_props, e2_props],
                        timestamp_start=datetime.fromisoformat(e1_props["timestamp"]),
                        timestamp_end=datetime.fromisoformat(e2_props["timestamp"]),
                        confidence_score=0.85 # Heuristic score for this pattern
                    )
                    results.append(path)
                    
        except Exception as e:
            logger.error(f"Error detecting lateral movement: {e}")
            
        return results

    def detect_suspicious_ip_chains(self) -> List[SuspiciousChain]:
        """
        Detects chains where an IP initiates an event that targets another IP.
        (IP A)-[:INITIATED]->(Event)-[:TARGETED]->(IP B)
        """
        query = """
        MATCH (ip1:IP)-[:INITIATED]->(e:Event)-[:TARGETED]->(ip2:IP)
        WHERE ip1 <> ip2
        RETURN ip1, e, ip2
        LIMIT 100
        """
        
        results = []
        try:
             with self._driver.session() as session:
                records = session.run(query)
                for record in records:
                    nodes = [
                        GraphNode(label="IP", properties=dict(record["ip1"])),
                        GraphNode(label="Event", properties=dict(record["e"])),
                        GraphNode(label="IP", properties=dict(record["ip2"]))
                    ]
                    
                    chain = SuspiciousChain(
                        chain_type="IP Hopping",
                        nodes=nodes,
                        description=f"IP {record['ip1']['address']} targeted {record['ip2']['address']} via {record['e']['type']}"
                    )
                    results.append(chain)
        except Exception as e:
            logger.error(f"Error detecting IP chains: {e}")
            
        return results
