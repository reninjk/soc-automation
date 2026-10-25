#!/usr/bin/env python3
"""
Logging utility for SOC Automation scripts.
Provides structured JSON logging with configurable levels.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class TextFormatter(logging.Formatter):
    """Human-readable formatter for local development."""

    LEVEL_COLOURS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.LEVEL_COLOURS.get(record.levelname, "")
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"{ts} {colour}{record.levelname:<8}{self.RESET} [{record.name}] {msg}"


def setup_logger(name: str, level: str = None) -> logging.Logger:
    """
    Create and return a configured logger.

    Uses JSON format when LOG_FORMAT=json (default in production),
    or human-readable text format for local development.

    Args:
        name: Logger name (use __name__ from calling module).
        level: Override log level. Falls back to LOG_LEVEL env var, then INFO.

    Returns:
        Configured logging.Logger instance.

    Example:
        from utils.logger import setup_logger
        logger = setup_logger(__name__)
        logger.info("Script started")
        logger.error("Something went wrong", exc_info=True)
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    log_level_str = level or os.getenv("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    log_format = os.getenv("LOG_FORMAT", "text").lower()
    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(TextFormatter())

    logger.addHandler(handler)
    logger.propagate = False
    return logger
