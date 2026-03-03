from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    """
    Application Configuration using Environment Variables.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Wazuh Configuration
    wazuh_url: str = Field(..., description="Wazuh API URL")
    wazuh_user: str = Field(..., description="Wazuh API Username")
    wazuh_password: str = Field(..., description="Wazuh API Password")
    wazuh_verify_ssl: bool = Field(True, description="Verify SSL Certificates")

    # Neo4j Configuration
    neo4j_uri: str = Field("bolt://localhost:7687", description="Neo4j Connection URI")
    neo4j_user: str = Field("neo4j", description="Neo4j Username")
    neo4j_password: str = Field(..., description="Neo4j Password")

    # Logging & App Configuration
    log_level: str = Field("INFO", description="Logging Level")
    app_env: str = Field("development", description="Application Environment (development/production)")
    polling_interval: int = Field(10, description="Seconds to wait between polling cycles")

settings = Settings()
