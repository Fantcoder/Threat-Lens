"""Configuration management using pydantic-settings.

Reads environment variables with prefix 'THREATLENS_'.
Never hardcodes secrets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for ThreatLens."""

    model_config = SettingsConfigDict(
        env_prefix="THREATLENS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Provider API Keys ---
    virustotal_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None

    # --- Service Authentication ---
    api_key: SecretStr | None = None

    # --- Application & Storage ---
    cache_dir: Path = Field(default=Path("./data"))
    log_level: str = "INFO"
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8000
    client_rate_limit: int = 60  # req/min for ThreatLens's own API per client

    # --- Provider Rate Limits (Free Tier Defaults) ---
    virustotal_rpm: int = 4
    virustotal_daily: int = 500
    virustotal_timeout: float = 15.0

    otx_rpm: int = 10
    otx_daily: int = 1000
    otx_timeout: float = 15.0

    abuseipdb_rpm: int = 10
    abuseipdb_daily: int = 1000
    abuseipdb_timeout: float = 15.0

    # Max wait time before rate-limiter gives up and returns 'rate_limited' status
    max_rate_limit_wait: float = 5.0

    # --- Circuit Breaker Config ---
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: float = 60.0

    # --- Scoring Engine Weights ---
    weight_virustotal: Annotated[float, Field(ge=0.0, le=1.0)] = 0.50
    weight_otx: Annotated[float, Field(ge=0.0, le=1.0)] = 0.25
    weight_abuseipdb: Annotated[float, Field(ge=0.0, le=1.0)] = 0.25

    # --- Verdict Thresholds ---
    threshold_clean_max: int = 9
    threshold_low_risk_max: int = 34
    threshold_suspicious_max: int = 64
    # >= 65 is malicious

    # Minimum score confidence required to issue a clean or low_risk verdict
    min_confidence_for_clean: float = 0.6

    # Strong-signal floor factor: prevents strong evidence from being diluted by neutral feeds
    strong_signal_factor: float = 0.8

    # --- Cache TTL (seconds) ---
    ttl_malicious: int = 21600  # 6 hours
    ttl_suspicious: int = 21600  # 6 hours
    ttl_clean: int = 86400  # 24 hours
    ttl_low_risk: int = 86400  # 24 hours
    ttl_unknown: int = 900  # 15 minutes


def get_settings() -> Settings:
    """Instantiate and return application settings."""
    return Settings()
