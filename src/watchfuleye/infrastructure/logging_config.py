
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from watchfuleye.infrastructure.paths import get_user_data_directory


def configure_logging() -> None:
    """
    Configure application logging.

    Logs are written to a rotating file.
    Nothing is printed to the console.
    """

    log_directory = get_user_data_directory() / "logs"
    log_directory.mkdir(parents=True, exist_ok=True)

    log_file = log_directory / "watchfuleye.log"

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | "
        "%(name)s | %(message)s"
    )

    file_handler.setFormatter(formatter)

    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler],
        force=True,
    )
