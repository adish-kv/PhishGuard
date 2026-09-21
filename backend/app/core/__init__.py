"""PhishGuard core module.

Provides configuration, security, logging, and database management.
"""

from backend.app.core.config import Settings, get_settings, reset_settings
from backend.app.core.database import Base, get_db_session, init_db, close_db
from backend.app.core.logging import get_logger, setup_logging
from backend.app.core.security import SSRFProtector, URLValidationResult, sanitize_url

__all__ = [
    "Settings",
    "get_settings",
    "reset_settings",
    "Base",
    "get_db_session",
    "init_db",
    "close_db",
    "get_logger",
    "setup_logging",
    "SSRFProtector",
    "URLValidationResult",
    "sanitize_url",
]
