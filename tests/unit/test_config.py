"""Tests for configuration settings."""

from __future__ import annotations

import os
from unittest import mock

from threatlens.config import Settings, get_settings


def test_default_settings() -> None:
    settings = Settings()
    assert settings.virustotal_rpm == 4
    assert settings.virustotal_daily == 500
    assert settings.otx_rpm == 10
    assert settings.abuseipdb_rpm == 10
    assert settings.weight_virustotal == 0.50
    assert settings.weight_otx == 0.25
    assert settings.weight_abuseipdb == 0.25
    assert settings.threshold_clean_max == 9
    assert settings.threshold_low_risk_max == 34
    assert settings.threshold_suspicious_max == 64
    assert settings.ttl_malicious == 21600
    assert settings.ttl_clean == 86400
    assert settings.ttl_unknown == 900


def test_env_override() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "THREATLENS_VIRUSTOTAL_API_KEY": "test_vt_key",
            "THREATLENS_LOG_LEVEL": "DEBUG",
            "THREATLENS_PORT": "9000",
        },
    ):
        settings = get_settings()
        assert settings.virustotal_api_key is not None
        assert settings.virustotal_api_key.get_secret_value() == "test_vt_key"
        assert settings.log_level == "DEBUG"
        assert settings.port == 9000
