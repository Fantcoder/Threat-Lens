"""Structured JSON Logging with Secret Redaction and Correlation IDs."""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variable for tracking Request ID across async coroutines
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")

# Global set of sensitive secret strings to redact
_REDACT_SECRETS: set[str] = set()


def register_secret_for_redaction(secret: str | None) -> None:
    """Register a sensitive token or key that must be redacted from all log messages."""
    if secret and len(secret.strip()) >= 4:
        _REDACT_SECRETS.add(secret.strip())


class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts registered API keys and sensitive tokens."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact(a) for a in record.args)
        return True

    @staticmethod
    def _redact(val: Any) -> Any:
        if not isinstance(val, str):
            return val
        redacted = val
        for secret in _REDACT_SECRETS:
            if secret in redacted:
                redacted = redacted.replace(secret, "***REDACTED***")
        return redacted


class JSONFormatter(logging.Formatter):
    """Formats log records as structured, machine-parseable JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get(),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure root logger with JSON formatter and secret redaction."""
    root = logging.getLogger()
    root.setLevel(log_level.upper())

    # Avoid duplicate handlers
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        handler.addFilter(SecretRedactionFilter())
        root.addHandler(handler)
    else:
        for h in root.handlers:
            h.addFilter(SecretRedactionFilter())
