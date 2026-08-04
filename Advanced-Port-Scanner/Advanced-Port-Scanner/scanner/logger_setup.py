"""
logger_setup.py
-----------------
Central logging configuration for the Advanced Port Scanner.
Writes rotating logs to the logs/ directory and also prints to console.
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_dir: str = "logs", log_file: str = "scanner.log") -> logging.Logger:
    """
    Configure and return the application-wide logger.

    Args:
        log_dir: Directory where log files are stored.
        log_file: Log file name.

    Returns:
        Configured Logger instance.
    """
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)

    logger = logging.getLogger("AdvancedPortScanner")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        # Avoid duplicate handlers if setup_logging is called more than once
        return logger

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = RotatingFileHandler(
        log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
