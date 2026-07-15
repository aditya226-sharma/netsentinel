"""Logging setup for NetSentinel using Rich for console output."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


console = Console(stderr=True)


def setup_logger(
    name: str,
    level: str | int = "INFO",
    log_file: str | Path | None = None,
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> logging.Logger:
    """Create and configure a logger with Rich console and optional file output.

    Args:
        name: Logger name (typically module name).
        level: Log level as string ("DEBUG", "INFO", etc.) or int.
        log_file: Optional path to a log file for RotatingFileHandler.
        max_bytes: Maximum log file size before rotation.
        backup_count: Number of rotated log files to keep.

    Returns:
        Configured logging.Logger instance.
    """
    if isinstance(level, str):
        numeric_level = getattr(logging, level.upper(), logging.INFO)
    else:
        numeric_level = level

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(numeric_level)
    logger.propagate = False

    rich_handler = RichHandler(
        console=console,
        show_path=False,
        show_time=True,
        show_level=True,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        level=numeric_level,
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(rich_handler)

    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def setup_root_logger(
    level: str = "INFO",
    log_file: str | Path | None = None,
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> logging.Logger:
    """Set up the root netsentinel logger that all child loggers inherit from.

    Args:
        level: Root log level.
        log_file: Optional file path for log rotation.
        max_bytes: Maximum file size before rotation.
        backup_count: Number of backup files.

    Returns:
        The root netsentinel logger.
    """
    root = setup_logger(
        name="netsentinel",
        level=level,
        log_file=log_file,
        max_bytes=max_bytes,
        backup_count=backup_count,
    )

    for lib_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lib_logger = logging.getLogger(lib_name)
        lib_logger.handlers.clear()
        lib_logger.propagate = True

    return root
