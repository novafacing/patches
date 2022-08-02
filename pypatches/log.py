"""
Logging handler installer
"""


from dataclasses import dataclass
from logging import (
    CRITICAL,
    FileHandler,
    LogRecord,
    getLogger,
    getLogRecordFactory,
    setLogRecordFactory,
)
from os import getenv
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from coloredlogs import ColoredFormatter, install


@dataclass
class LoggingConfig:
    """
    Logging configuration for the project
    """

    default_level: str = "INFO"
    max_name_len: int = 24
    sname_intersp: str = "..."
    log_fmt: str = (
        f"{{levelname:<8s}} | "
        f"{{name:>{max_name_len + len(sname_intersp)}s}}:{{lineno:04d}} | "
        f"{{message}}"
    )
    factory: Callable[
        [
            str,
            int,
            str,
            int,
            str,
            List[Any],
            Optional[Tuple[Exception]],
            str,
            str,
            Dict[str, Any],
        ],
        LogRecord,
    ] = getLogRecordFactory()
    logdir: Optional[Path] = None
    logfile: str = "log.txt"


LOGGING_CONFIG = LoggingConfig(default_level=getenv("PATCHES_LOG_LEVEL", "DEBUG"))


def __record_factory__(
    *args: List[Any],
    **kwargs: Dict[str, Any],
) -> LogRecord:
    """
    Log record factory replacement for coloredlogging.
    Replaces `name` with a length-stabilized
    name so logs are horizontally aligned.
    :return: The new record
    :rtype: LogRecord
    """
    record = LOGGING_CONFIG.factory(*args, **kwargs)  # type: ignore
    if len(record.name) > LOGGING_CONFIG.max_name_len + len(
        LOGGING_CONFIG.sname_intersp
    ):
        record.name = (
            record.name[: LOGGING_CONFIG.max_name_len // 2]
            + LOGGING_CONFIG.sname_intersp
            + record.name[-(LOGGING_CONFIG.max_name_len // 2) :]
        )
    else:
        record.name = record.name.rjust(
            LOGGING_CONFIG.max_name_len + len(LOGGING_CONFIG.sname_intersp), " "
        )
    return record


def __init_logging__(config: LoggingConfig) -> None:
    """
    Set up logging for the project
    :param config: A logging configuration.
    """
    root_logger = getLogger()
    install(
        level=config.default_level, fmt=config.log_fmt, style="{", reconfigure=False
    )
    setLogRecordFactory(__record_factory__)
    root_logger.setLevel(config.default_level)
    root_handler = root_logger.handlers[0]
    root_handler.setFormatter(ColoredFormatter(fmt=config.log_fmt, style="{"))
    logger = getLogger(__name__)
    if config.logdir is not None:
        logfile = config.logdir / config.logfile
        assert (
            logfile.exists() and config.logdir.is_dir()
        ), f"Log directory {str(config.logdir.resolve())} does not exist!"

        fh = FileHandler(logfile)
        fh.setFormatter(ColoredFormatter(fmt=config.log_fmt, style="{"))
        root_logger.addHandler(fh)

    logger.info(f"{__name__} project logging configured.")
    parso_logger = getLogger("parso")
    parso_logger.setLevel(CRITICAL)


__init_logging__(LOGGING_CONFIG)
