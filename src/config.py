"""
Configuration management for the Thoughts Dashboard.

Loads all settings from environment variables.
NO secrets or credentials are hardcoded here.

See: specs/architecture/web_application.spec (Configuration Management)
See: specs/security/secrets_management.spec
"""
import logging
import os

logger = logging.getLogger(__name__)


class Config:
    """Application configuration loaded from environment variables."""

    # --- Database ---
    DB_HOST: str = os.environ.get("DB_HOST", "")
    DB_NAME: str = os.environ.get("DB_NAME", "")
    DB_USER: str = os.environ.get("DB_USER", "")
    DB_PASSWORD: str = os.environ.get("DB_PASSWORD", "")
    DB_PORT: int = int(os.environ.get("DB_PORT", "5432"))
    DB_POOL_MIN: int = int(os.environ.get("DB_POOL_MIN", "1"))
    DB_POOL_MAX: int = int(os.environ.get("DB_POOL_MAX", "10"))
    DB_TIMEOUT: int = int(os.environ.get("DB_TIMEOUT", "30"))

    # --- Flask ---
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # --- Pagination ---
    DEFAULT_PAGE_SIZE: int = int(os.environ.get("DEFAULT_PAGE_SIZE", "50"))
    MAX_PAGE_SIZE: int = int(os.environ.get("MAX_PAGE_SIZE", "500"))

    @classmethod
    def validate(cls) -> None:
        """
        Validate all required configuration is present.
        Raises ValueError with a descriptive message if anything is missing.
        Fails fast — application will not start with invalid config.
        """
        required = {
            "DB_HOST": cls.DB_HOST,
            "DB_NAME": cls.DB_NAME,
            "DB_USER": cls.DB_USER,
            "DB_PASSWORD": cls.DB_PASSWORD,
            "SECRET_KEY": cls.SECRET_KEY,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(
                f"Required environment variables not set: {', '.join(missing)}. "
                "See config/.env.example for required variables."
            )
        logger.info("Configuration validated successfully (values not logged)")
