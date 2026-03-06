"""
Structured logging setup for the Wazuh-TI platform.

Configures a rotating file handler and console handler with consistent
formatting. All modules should use `get_logger(__name__)` to obtain
a logger instance.

Log output format:
    2024-01-10 10:00:00 [INFO] app.core.pipeline: Sync started for feed 1
"""

import os
import logging
from logging.handlers import RotatingFileHandler


def get_logger(name: str, log_file: str = None, level: str = None) -> logging.Logger:
    """
    Create and configure a logger instance.

    Args:
        name: Logger name (typically __name__).
        log_file: Optional path to log file. Falls back to env or default.
        level: Optional log level string. Falls back to LOG_LEVEL env var.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if logger already configured
    if logger.handlers:
        return logger

    log_level = getattr(logging, (level or os.environ.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    logger.setLevel(log_level)

    # Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler — always enabled
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler — enabled if a log file path is provided
    _log_file = log_file or os.environ.get("LOG_FILE")
    if _log_file:
        try:
            log_dir = os.path.dirname(os.path.abspath(_log_file))
            os.makedirs(log_dir, exist_ok=True)
            file_handler = RotatingFileHandler(
                _log_file,
                maxBytes=50 * 1024 * 1024,  # 50 MB
                backupCount=5,
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not create log file handler: {e}")

    return logger
