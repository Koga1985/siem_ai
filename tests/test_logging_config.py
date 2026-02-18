"""
Unit tests for logging configuration
"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../services"))  # noqa: E402

from common.logging_config import log_audit_event, setup_logging  # noqa: E402


class TestLoggingSetup:
    """Test logging configuration"""

    def test_setup_logging_creates_logger(self):
        """Test that setup_logging creates a logger"""
        logger = setup_logging("test_service")

        assert logger is not None
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_service"

    def test_logger_default_level(self):
        """Test default log level is INFO"""
        logger = setup_logging("test_service")

        assert logger.level == logging.INFO

    def test_logger_custom_level(self):
        """Test custom log level"""
        logger = setup_logging("test_service", log_level="DEBUG")

        assert logger.level == logging.DEBUG

    def test_logger_has_handlers(self):
        """Test logger has at least one handler"""
        logger = setup_logging("test_service")

        assert len(logger.handlers) > 0

    def test_log_output(self, caplog):
        """Test that logging actually works"""
        logger = setup_logging("test_service")
        # setup_logging sets propagate=False (JSON→stdout only); re-enable for caplog
        logger.propagate = True

        with caplog.at_level(logging.INFO):
            logger.info("Test message", extra={"key": "value"})

        # Check that something was logged
        assert len(caplog.records) > 0

    def test_audit_event_logging(self, caplog):
        """Test audit event logging"""
        logger = setup_logging("test_service")
        # setup_logging sets propagate=False (JSON→stdout only); re-enable for caplog
        logger.propagate = True

        with caplog.at_level(logging.INFO):
            log_audit_event(logger, "test_event", user="testuser", action="test")

        # Verify audit log was created
        assert len(caplog.records) > 0
        # The audit event should be logged
        assert any("AUDIT_EVENT" in record.message for record in caplog.records)


class TestLoggerIsolation:
    """Test that loggers don't interfere with each other"""

    def test_multiple_loggers_independent(self):
        """Test that multiple loggers are independent"""
        logger1 = setup_logging("service1", log_level="DEBUG")
        logger2 = setup_logging("service2", log_level="WARNING")

        assert logger1.name != logger2.name
        assert logger1.level == logging.DEBUG
        assert logger2.level == logging.WARNING
