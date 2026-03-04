from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from typing import Optional, Any
import re
from datetime import datetime
from src.core.dns_resolver import DNSResolver

# Mock dictionary mapping MITRE Technique IDs to Mitigations (STIX conceptual mapping)
MITRE_MITIGATION_MAP = {
    "T1059": {"mitigation_id": "M1047", "description": "Audit and restrict command-line usage."},
    "T1021": {"mitigation_id": "M1030", "description": "Network segmentation and strict lateral movement controls."},
    "T1078": {"mitigation_id": "M1027", "description": "Implement Multi-Factor Authentication (MFA)."},
    "T1110": {"mitigation_id": "M1032", "description": "Lockout policies for brute-force attacks."}
}

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

        mitre_data = self.rule.get("mitre", {})
        mitre_techniques = mitre_data.get("id", [])
        if isinstance(mitre_techniques, str):
            mitre_techniques = [mitre_techniques]
        
        mitre_tactics = mitre_data.get("tactic", [])
        if isinstance(mitre_tactics, str):
            mitre_tactics = [mitre_tactics]

        # Mapeo estático de mitigaciones basado en técnicas identificadas
        mitre_mitigations = []
        for tech in mitre_techniques:
            if tech in MITRE_MITIGATION_MAP:
                mitre_mitigations.append(MITRE_MITIGATION_MAP[tech])

        # Extraer GeoIP si está disponible
        geoip_data = self.data.get("geoip", {})
        location_country = geoip_data.get("country_name")
        location_city = geoip_data.get("city_name")

        # Resolucion DNS (cacheada) de la IP destino
        dns_domain = None
        if dst_ip:
            dns_domain = DNSResolver.resolve_ip(str(dst_ip))
            
        return ProphetEntity(
            id=self.id,
            event_type=self.rule.get("description", "unknown_event"),
            timestamp=self.timestamp,
            hostname=self.agent.get("name", "unknown_host"),
            user=user,
            source_ip=src_ip,
            target_ip=dst_ip,
            dns_domain=dns_domain,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            mitre_mitigations=mitre_mitigations,
            location_country=location_country,
            location_city=location_city
        )

class ProphetEntity(BaseModel):
    """
    Normalized internal model for Graph Ingestion (Neo4j).
    Strict validation and sanitization applied here.
    """
    id: str = Field(..., description="Alert ID")
    event_type: str = Field(..., min_length=1, max_length=100, description="Normalized event type (e.g. login_failed)")
    timestamp: datetime = Field(..., description="Event timestamp")
    hostname: str = Field(..., min_length=1, max_length=255, description="Agent hostname")
    
    # User can be optional (e.g. system events)
    user: Optional[str] = Field(None, max_length=100, description="Username associated with the event")
    
    # Network fields
    source_ip: Optional[IPvAnyAddress] = Field(None, description="Source IP Address")
    target_ip: Optional[IPvAnyAddress] = Field(None, description="Target IP Address")
    dns_domain: Optional[str] = Field(None, description="Resolved DNS Domain for Target IP")

    # Geolocation fields
    location_country: Optional[str] = Field(None, description="Country from GeoIP")
    location_city: Optional[str] = Field(None, description="City from GeoIP")

    # Threat Intelligence fields (MITRE ATT&CK)
    mitre_techniques: list[str] = Field(default=[], description="MITRE ATT&CK Technique IDs")
    mitre_tactics: list[str] = Field(default=[], description="MITRE ATT&CK Tactics")
    mitre_mitigations: list[dict[str, str]] = Field(default=[], description="List of mitigations {id, description}")

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

