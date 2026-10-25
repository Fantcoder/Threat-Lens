"""Scaffolding and package structure smoke test."""

import threatlens
from threatlens.errors import (
    CacheError,
    CircuitBreakerOpenError,
    ConfigurationError,
    InvalidIoCError,
    ProviderError,
    RateLimitExceededError,
    ThreatLensError,
)


def test_package_metadata() -> None:
    """Verify package version is set."""
    assert threatlens.__version__ == "1.0.0"


def test_exception_hierarchy() -> None:
    """Verify custom exceptions inherit from ThreatLensError."""
    assert issubclass(InvalidIoCError, ThreatLensError)
    assert issubclass(ProviderError, ThreatLensError)
    assert issubclass(RateLimitExceededError, ThreatLensError)
    assert issubclass(CircuitBreakerOpenError, ThreatLensError)
    assert issubclass(CacheError, ThreatLensError)
    assert issubclass(ConfigurationError, ThreatLensError)

    err = InvalidIoCError("bad_ioc", "malformed")
    assert "bad_ioc" in str(err)
    assert err.value == "bad_ioc"
    assert err.reason == "malformed"

    p_err = ProviderError("virustotal", "API key invalid")
    assert p_err.provider == "virustotal"
    assert "[virustotal] API key invalid" in str(p_err)

    rl_err_with_retry = RateLimitExceededError("virustotal", retry_after=15.5)
    assert rl_err_with_retry.provider == "virustotal"
    assert rl_err_with_retry.retry_after == 15.5
    assert "15.5s" in str(rl_err_with_retry)

    rl_err_no_retry = RateLimitExceededError("otx")
    assert rl_err_no_retry.provider == "otx"
    assert rl_err_no_retry.retry_after is None
    assert str(rl_err_no_retry) == "Rate limit exceeded for otx"

    cb_err = CircuitBreakerOpenError("abuseipdb")
    assert cb_err.provider == "abuseipdb"
    assert "Circuit breaker open for abuseipdb" in str(cb_err)

    cache_err = CacheError("database disk full")
    assert "database disk full" in str(cache_err)

    cfg_err = ConfigurationError("missing required secret")
    assert "missing required secret" in str(cfg_err)
