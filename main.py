"""NetSentinel - Network Traffic Analysis Framework.

Main entry point that initializes configuration, logging, and database.
When run directly, invokes the Typer CLI application.
"""

from __future__ import annotations

import sys
from pathlib import Path

from config.settings import get_config
from utils.logger import setup_logger, setup_root_logger
from database.db_manager import DatabaseManager

BANNER = r"""
    _   __     __  _____                     __
   / | / /__  / /_/ ___/____  ___  _____   / /___  __  ______
  /  |/ / _ \/ __/\__ \/ __ \/ _ \/ __ |  / / __ \/ / / / __ \
 / /|  /  __/ /_ ___/ / /_/ /  __/ /_/ / / / /_/ / /_/ / / / /
/_/ |_/\___/\__//____/ .___/\___/\__, (_)/_/\____/\__,_/_/ /_/
                    /_/          /____/

  v1.0.0 - Network Traffic Analysis Framework
"""


def initialize() -> None:
    """Initialize all NetSentinel subsystems."""
    config = get_config()

    setup_root_logger(
        level=config.logging.level,
        log_file=config.logging.file,
        max_bytes=config.logging.max_size,
        backup_count=config.logging.backup_count,
    )

    logger = setup_logger("netsentinel.main")
    logger.info("NetSentinel starting up...")

    db_path = Path(config.database.path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with DatabaseManager(config.database.path) as db:
        logger.info("Database ready at %s", config.database.path)

    logger.info(
        "Configuration loaded: API %s:%d, auth=%s, capture_interface=%r",
        config.api.host,
        config.api.port,
        "enabled" if config.auth.enabled else "disabled",
        config.capture.interface or "(auto-detect)",
    )


def main() -> None:
    """Application entry point."""
    from cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
