import logging
import os
import tempfile
import pytest
from shared.logger import setup_logger

def test_setup_logger_console_only():
    logger_name = "test_logger_console"
    logger = setup_logger(logger_name, log_file=None, level=logging.INFO)
    
    assert logger.name == logger_name
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.StreamHandler)
    logger.handlers.clear()

def test_setup_logger_with_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "subdir", "test.log")
        logger_name = "test_logger_file"
        
        # Verify directory creation and file logging
        logger = setup_logger(logger_name, log_file=log_file, level=logging.DEBUG)
        
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 2
        
        # Determine handlers
        stream_handler = [h for h in logger.handlers if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)]
        file_handler = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        
        assert len(stream_handler) == 1
        assert len(file_handler) == 1
        
        # Log something
        test_message = "Hello logging world"
        logger.debug(test_message)
        
        # Flush and close so file is written/released
        file_handler[0].close()
        logger.handlers.clear()
        
        assert os.path.exists(log_file)
        with open(log_file, "r") as f:
            content = f.read()
            assert test_message in content
            assert "DEBUG" in content

def test_setup_logger_console_level_isolation():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "test_isolation.log")
        logger_name = "test_logger_isolation"
        
        # Logger overall/file level is DEBUG, console is ERROR
        logger = setup_logger(logger_name, log_file=log_file, level=logging.DEBUG, console_level=logging.ERROR)
        
        # Min level should be DEBUG (which is min(DEBUG, ERROR))
        assert logger.level == logging.DEBUG
        
        stream_handler = [h for h in logger.handlers if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)][0]
        file_handler = [h for h in logger.handlers if isinstance(h, logging.FileHandler)][0]
        
        assert stream_handler.level == logging.ERROR
        assert file_handler.level == logging.DEBUG
        
        file_handler.close()
        logger.handlers.clear()
