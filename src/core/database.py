import logging
import threading
from typing import Optional
from neo4j import GraphDatabase, Driver
from src.config.settings import settings

logger = logging.getLogger(__name__)

class Neo4jConnector:
    _instance: Optional['Neo4jConnector'] = None
    _lock: threading.Lock = threading.Lock()
    _driver: Optional[Driver] = None

    def __new__(cls):
        """Thread-safe Singleton Pattern to ensure one connector instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Neo4jConnector, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize driver only once."""
        self._driver = None
        self._connect()

    def _connect(self):
        """Establish connection to Neo4j."""
        try:
            self._driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password)
            )
            self._driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {settings.neo4j_uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            # We don't raise here to allow the app to start even if DB is down initially, 
            # but methods using the driver should check or retry.
            self._driver = None

    def get_driver(self) -> Optional[Driver]:
        """Returns the Neo4j driver instance, reconnecting if closed or None."""
        if self._driver is None:
             self._connect()
        return self._driver

    def close(self):
        """Close the driver connection."""
        if self._driver:
            self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed.")
