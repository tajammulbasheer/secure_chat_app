import logging
import os

def setup_logger(name, log_file=None, level=logging.INFO, console_level=None):
    """
    Sets up a logger with a console handler and an optional file handler.
    
    :param name: Name of the logger.
    :param log_file: Path to the log file (optional). If directory doesn't exist, it will be created.
    :param level: Minimum logging level for the logger (default: logging.INFO).
    :param console_level: Minimum logging level for the console handler. If None, defaults to `level`.
    """
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    
    effective_level = level
    if console_level is not None:
        effective_level = min(level, console_level)
    
    logger.setLevel(effective_level)

    # Clear existing handlers to prevent duplicate logging
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console Handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    if console_level is not None:
        ch.setLevel(console_level)
    else:
        ch.setLevel(level)
    logger.addHandler(ch)

    # Optional File Handler
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        fh.setLevel(level)
        logger.addHandler(fh)

    return logger
