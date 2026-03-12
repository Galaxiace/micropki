import logging
import sys
from typing import Optional


class MicroPKILogger:
    def __init__(self, name: str = 'micropki', log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        formatter = logging.Formatter(
            fmt='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )

        if log_file:
            handler = logging.FileHandler(log_file)
        else:
            handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def debug(self, message: str):
        self.logger.debug(message)


def setup_logger(log_file: Optional[str] = None) -> MicroPKILogger:
    return MicroPKILogger(log_file=log_file)