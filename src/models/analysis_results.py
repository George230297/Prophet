from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class GraphNode(BaseModel):
    """Represents a node in the graph (Host, IP, User, etc.)"""
    label: str
    properties: dict

class LateralMovementPath(BaseModel):
    """Represents a detected lateral movement path."""
    source_host: str
    target_host: str
    user: str
    events: List[dict] = Field(..., description="List of events involved in the path")
    timestamp_start: datetime
    timestamp_end: datetime
    confidence_score: float = Field(..., ge=0.0, le=1.0)

class SuspiciousChain(BaseModel):
    """Represents a chain of suspicious connections (e.g. IP -> Event -> IP)."""
    chain_type: str = Field(..., description="Type of chain detected (e.g., 'IP Hopping')")
    nodes: List[GraphNode]
    description: str
