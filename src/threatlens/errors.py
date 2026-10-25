"""Custom exception hierarchy for ThreatLens."""

from __future__ import annotations


class ThreatLensError(Exception):
    """Base exception for all ThreatLens errors."""


class InvalidIoCError(ThreatLensError):
    """Raised when an IoC value cannot be parsed or is invalid."""

    def __init__(self, value: str, reason: str = "unrecognised format") -> None:
        self.value = value
        self.reason = reason
        super().__init__(f"Invalid IoC '{value}': {reason}")


class ProviderError(ThreatLensError):
    """Raised when a provider encounters an unexpected error."""

    def __init__(self, provider: str, message: str) -> None:
        self.provider = provider
        super().__init__(f"[{provider}] {message}")


class RateLimitExceededError(ThreatLensError):
    """Raised when rate limits are exhausted."""

    def __init__(self, provider: str, retry_after: float | None = None) -> None:
        self.provider = provider
        self.retry_after = retry_after
        msg = f"Rate limit exceeded for {provider}"
        if retry_after is not None:
            msg += f" (retry after {retry_after:.1f}s)"
        super().__init__(msg)


class CircuitBreakerOpenError(ThreatLensError):
    """Raised when a provider's circuit breaker is open."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        super().__init__(f"Circuit breaker open for {provider}")


class CacheError(ThreatLensError):
    """Raised on cache read/write failures."""


class ConfigurationError(ThreatLensError):
    """Raised when configuration is invalid or missing."""
