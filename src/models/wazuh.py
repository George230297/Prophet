from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from typing import Optional, Any
import re
from datetime import datetime

class WazuhAlert(BaseModel):
    """
    Model representing the raw structure of a Wazuh Alert.
    Captures essential fields for analysis, allowing extra fields.
    """
    timestamp: datetime = Field(..., description="Alert timestamp")
    rule: dict[str, Any] = Field(..., description="Rule information")
    agent: dict[str, Any] = Field(..., description="Agent information")
    manager: dict[str, Any] = Field(..., description="Manager information")
    id: str = Field(..., description="Alert ID") 
    cluster: dict[str, Any] = Field(default={}, description="Cluster info")
    decoder: dict[str, Any] = Field(default={}, description="Decoder info")
    data: dict[str, Any] = Field(default={}, description="Payload data containing IPs, users, etc.")
    location: str = Field(..., description="Log location")

    model_config = {
        "extra": "ignore" # Ignore extra fields we don't explicitly need, to be robust
    }

    def to_entity(self) -> 'ProphetEntity':
        """
        Transforma la alerta cruda de Wazuh en una entidad normalizada para Prophet.
        Intenta extraer IPs y Usuarios de varios campos comunes de Wazuh.
        """
        # Extraer IP de origen (best effort)
        src_ip = self.data.get("src_ip") or self.data.get("srcip")
        
        # Extraer IP de destino (si existe)
        dst_ip = self.data.get("dst_ip") or self.data.get("dstip")
        
        # Extraer usuario (puede venir como dst_user, src_user, o user)
        user = (
            self.data.get("dst_user") or 
            self.data.get("src_user") or 
            self.data.get("user") or 
            self.data.get("system_name") # A veces el usuario es SYSTEM
        )

        return ProphetEntity(
            event_type=self.rule.get("description", "unknown_event"),
            timestamp=self.timestamp,
            hostname=self.agent.get("name", "unknown_host"),
            user=user,
            source_ip=src_ip,
            target_ip=dst_ip
        )

class ProphetEntity(BaseModel):
    """
    Normalized internal model for Graph Ingestion (Neo4j).
    Strict validation and sanitization applied here.
    """
    event_type: str = Field(..., min_length=1, max_length=100, description="Normalized event type (e.g. login_failed)")
    timestamp: datetime = Field(..., description="Event timestamp")
    hostname: str = Field(..., min_length=1, max_length=255, description="Agent hostname")
    
    # User can be optional (e.g. system events)
    user: Optional[str] = Field(None, max_length=100, description="Username associated with the event")
    
    # Network fields
    source_ip: Optional[IPvAnyAddress] = Field(None, description="Source IP Address")
    target_ip: Optional[IPvAnyAddress] = Field(None, description="Target IP Address")

    @field_validator("user")
    @classmethod
    def sanitize_username(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Remove any character that is not alphanumeric, dash, dot or underscore
        # This prevents injection of weird chars, although SQL/Cypher injection is handled by params.
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "", v)
        if not sanitized:
             return "unknown" 
        return sanitized

    @field_validator("hostname")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        # Basic hostname sanitization
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "", v)
        return sanitized if sanitized else "unknown_host"

