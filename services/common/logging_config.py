"""
Structured logging configuration for SIEM AI services
Provides JSON logging with audit trails for production environments
"""
import logging
import os
import sys
from pythonjsonlogger import jsonlogger

def setup_logging(service_name: str, log_level: str = None) -> logging.Logger:
    """
    Configure structured JSON logging for a service

    Args:
        service_name: Name of the service (e.g., 'event_bridge', 'ai_generator')
        log_level: Optional log level override (default: INFO, or from LOG_LEVEL env)

    Returns:
        Configured logger instance
    """
    # Determine log level
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()

    numeric_level = getattr(logging, log_level, logging.INFO)

    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(numeric_level)

    # Clear any existing handlers
    logger.handlers = []

    # JSON formatter with standard fields
    log_format = '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d'
    formatter = jsonlogger.JsonFormatter(
        log_format,
        rename_fields={
            'levelname': 'level',
            'asctime': 'timestamp',
            'pathname': 'file',
            'lineno': 'line'
        }
    )

    # Console handler for stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if LOG_FILE is set
    log_file = os.getenv('LOG_FILE')
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create file handler: {e}")

    # Don't propagate to root logger
    logger.propagate = False

    return logger


def log_audit_event(logger: logging.Logger, event_type: str, **kwargs):
    """
    Log an audit event with standard structure

    Args:
        logger: Logger instance
        event_type: Type of audit event (e.g., 'webhook_received', 'playbook_generated')
        **kwargs: Additional fields to include in audit log
    """
    audit_data = {
        'audit': True,
        'event_type': event_type,
        **kwargs
    }
    logger.info('AUDIT_EVENT', extra=audit_data)
