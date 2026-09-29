"""
Logging setup for RDRS.

Creates five rotating log files, one per concern, so an investigator can
follow exactly one thread of activity without wading through everything else:

  logs/system.log  - startup, shutdown, config, general app lifecycle
  logs/events.log  - every raw file-system event observed
  logs/alerts.log  - Warning/Critical alerts and incidents
  logs/errors.log  - exceptions and recoverable errors
  logs/audit.log   - every response action taken (or simulated)

Implementation note: uses stdlib `logging` with RotatingFileHandler rather
than `loguru`. Same behavior (independent rotating sinks per channel); if you
install loguru you can swap this module's internals without touching any
caller, since everyone else just calls get_logger("channel_name").
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.config import Settings

_CHANNELS = ["system", "events", "alerts", "errors", "audit"]
_configured = False


def _parse_size(size_str: str) -> int:
    """'10 MB' -> 10 * 1024 * 1024 bytes."""
    size_str = size_str.strip().upper()
    num = float("".join(c for c in size_str if (c.isdigit() or c == ".")))
    if "MB" in size_str:
        return int(num * 1024 * 1024)
    if "KB" in size_str:
        return int(num * 1024)
    if "GB" in size_str:
        return int(num * 1024 * 1024 * 1024)
    return int(num)


def setup_logging(settings: Settings) -> None:
    global _configured
    log_dir = Path(settings.logging.dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    max_bytes = _parse_size(settings.logging.rotation)
    level = getattr(logging, settings.logging.level.upper(), logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    for channel in _CHANNELS:
        logger = logging.getLogger(f"rdrs.{channel}")
        logger.setLevel(level)
        logger.propagate = False
        if logger.handlers:
            continue  # already configured (e.g. re-entrant call)

        file_handler = RotatingFileHandler(
            log_dir / f"{channel}.log", maxBytes=max_bytes, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)

    # errors.log receives ERROR+ from every channel, in addition to its own.
    for channel in _CHANNELS:
        if channel == "errors":
            continue
        logger = logging.getLogger(f"rdrs.{channel}")
        # setup_logging() is intentionally safe to call more than once. Do
        # not attach a second errors.log fan-out handler on reconfiguration.
        if any(getattr(handler, "_rdrs_errors_fanout", False) for handler in logger.handlers):
            continue
        errors_handler = RotatingFileHandler(
            log_dir / "errors.log", maxBytes=max_bytes, backupCount=5, encoding="utf-8"
        )
        errors_handler.setLevel(logging.ERROR)
        errors_handler.setFormatter(fmt)
        errors_handler._rdrs_errors_fanout = True
        logger.addHandler(errors_handler)

    _configured = True


def get_logger(channel: str) -> logging.Logger:
    """Return the logger for a named channel (system/events/alerts/errors/audit)."""
    return logging.getLogger(f"rdrs.{channel}")
