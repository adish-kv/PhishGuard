"""Structured logging for PhishGuard.

Provides JSON-formatted logging for production use and
human-readable formatting for development.

IMPORTANT: Never log:
- API keys or secrets
- Full URLs being analyzed (truncate to domain)
- Internal file paths
- Database credentials
- User IP addresses (hash them)
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging.

    Produces one JSON object per log line, suitable for
    log aggregation systems (ELK, Splunk, CloudWatch).
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON.

        Args:
            record: The log record to format.

        Returns:
            JSON string representation of the log record.
        """
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data

        # Add exception info if present
        if record.exc_info and record.exc_info[1]:
            log_data["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable log formatter for development."""

    FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    def __init__(self) -> None:
        super().__init__(fmt=self.FORMAT, datefmt="%Y-%m-%d %H:%M:%S")


def setup_logging(
    level: str = "INFO",
    log_format: str = "json",
    log_file: str | None = None,
) -> logging.Logger:
    """Configure application logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Format type ('json' or 'text').
        log_file: Optional file path for log output.

    Returns:
        Configured root logger for PhishGuard.
    """
    logger = logging.getLogger("phishguard")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Choose formatter
    if log_format == "json":
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a named logger under the phishguard namespace.

    Args:
        name: Logger name (typically module name).

    Returns:
        Logger instance.

    Example:
        logger = get_logger(__name__)
        logger.info("URL analyzed", extra={"extra_data": {"domain": "example.com"}})
    """
    return logging.getLogger(f"phishguard.{name}")
