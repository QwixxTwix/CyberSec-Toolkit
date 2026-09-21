"""Настройка логирования с ротацией."""
import logging
from logging.handlers import RotatingFileHandler
from core.config import LOG_DIR

LOG_FILE = LOG_DIR / "toolkit.log"


def get_logger(name: str = "cyber_toolkit") -> logging.Logger:
    """Возвращает логгер с ротацией и stderr-хендлером."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger