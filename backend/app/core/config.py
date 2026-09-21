"""PhishGuard configuration management.

Loads configuration from:
1. configs/default.yaml (defaults)
2. Environment variables (overrides)
3. .env file (local development)

All configurable parameters live here. No magic numbers elsewhere.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class BaseConfig(BaseSettings):
    """Base configuration class for all sub-configs.

    Sets extra='ignore' so unrecognized YAML keys don't cause errors.
    This is important because the YAML config may evolve faster than
    the Python config models during development.
    """

    model_config = {"extra": "ignore"}


def load_yaml_config(path: Path | None = None) -> dict[str, Any]:
    """Load YAML configuration file.

    Args:
        path: Path to YAML config file. Defaults to configs/default.yaml.

    Returns:
        Dictionary of configuration values.
    """
    if path is None:
        path = PROJECT_ROOT / "configs" / "default.yaml"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


class SecurityConfig(BaseConfig):
    """Security-related configuration.

    Controls SSRF protection, rate limiting, and input validation.
    """

    blocked_ip_ranges: list[str] = Field(
        default=[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "0.0.0.0/8",
            "::1/128",
            "fc00::/7",
        ],
        description="IP ranges blocked for SSRF protection",
    )
    blocked_hostnames: list[str] = Field(
        default=["localhost", "metadata.google.internal", "metadata.internal"],
        description="Hostnames blocked for SSRF protection",
    )
    allowed_schemes: list[str] = Field(
        default=["http", "https"],
        description="URL schemes allowed for analysis",
    )
    max_redirects: int = Field(default=3, ge=0, le=10)
    request_timeout_seconds: int = Field(default=15, ge=1, le=60)
    max_response_size_bytes: int = Field(
        default=5 * 1024 * 1024,  # 5MB
        description="Maximum HTTP response body size",
    )
    rate_limit_per_minute: int = Field(default=10, ge=1)


class AnalysisConfig(BaseConfig):
    """Analysis pipeline configuration."""

    mode: str = Field(
        default="adaptive",
        description="Analysis mode: 'full' or 'adaptive'",
    )
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    max_concurrent: int = Field(default=5, ge=1)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("full", "adaptive"):
            raise ValueError(f"Analysis mode must be 'full' or 'adaptive', got '{v}'")
        return v


class AdaptiveConfig(BaseConfig):
    """Adaptive decision engine configuration.

    Thresholds are tuned experimentally — these are initial defaults.
    Do NOT treat these as final values.
    """

    stage1_low_threshold: float = Field(
        default=0.15, ge=0.0, le=1.0,
        description="Below this probability, Stage 1 classifies as benign",
    )
    stage1_high_threshold: float = Field(
        default=0.85, ge=0.0, le=1.0,
        description="Above this probability, Stage 1 classifies as phishing",
    )
    stage2_low_threshold: float = Field(default=0.10, ge=0.0, le=1.0)
    stage2_high_threshold: float = Field(default=0.90, ge=0.0, le=1.0)
    uncertainty_threshold: float = Field(
        default=0.3, ge=0.0, le=1.0,
        description="Entropy threshold for requesting additional modalities",
    )
    enable_html_stage: bool = Field(default=True)
    enable_visual_stage: bool = Field(default=True)


class DatabaseConfig(BaseConfig):
    """Database configuration."""

    url: str = Field(
        default="postgresql+asyncpg://phishguard:phishguard@localhost:5432/phishguard",
        alias="DATABASE_URL",
    )
    echo: bool = Field(default=False, alias="DATABASE_ECHO")


class ScreenshotConfig(BaseConfig):
    """Screenshot service configuration."""

    viewport_width: int = Field(default=1280, ge=320, le=3840)
    viewport_height: int = Field(default=720, ge=240, le=2160)
    timeout_ms: int = Field(default=15000, ge=1000, le=60000)
    max_redirects: int = Field(default=3, ge=0)
    wait_after_load_ms: int = Field(default=2000, ge=0)


class OCRConfig(BaseConfig):
    """OCR module configuration."""

    languages: list[str] = Field(default=["en"])
    gpu: bool = Field(default=False)
    confidence_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    brand_names: list[str] = Field(
        default=[
            "google", "facebook", "microsoft", "apple", "amazon",
            "paypal", "netflix", "instagram", "twitter", "linkedin",
            "chase", "wellsfargo", "bankofamerica", "citi", "dropbox",
            "adobe", "dhl", "usps", "fedex", "walmart",
        ],
        description="Known brand names for OCR text matching",
    )


class VisualConfig(BaseConfig):
    """Visual analysis configuration."""

    model_name: str = Field(default="openai/clip-vit-base-patch32")
    embedding_dim: int = Field(default=512)
    similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    top_k: int = Field(default=5, ge=1)


class FusionConfig(BaseConfig):
    """Feature fusion model configuration."""

    architecture: str = Field(
        default="mlp",
        description="Fusion architecture: 'mlp', 'late', 'attention'",
    )
    url_encoder_dim: int = Field(default=32)
    html_encoder_dim: int = Field(default=32)
    ssl_encoder_dim: int = Field(default=16)
    domain_encoder_dim: int = Field(default=16)
    ocr_encoder_dim: int = Field(default=32)
    visual_projector_dim: int = Field(default=64)
    hidden_dim: int = Field(default=128)
    dropout: float = Field(default=0.3, ge=0.0, le=0.9)


class TrainingConfig(BaseConfig):
    """ML training configuration."""

    batch_size: int = Field(default=64, ge=1)
    learning_rate: float = Field(default=0.001, gt=0.0)
    epochs: int = Field(default=50, ge=1)
    early_stopping_patience: int = Field(default=10, ge=1)
    random_seeds: list[int] = Field(default=[42, 123, 456, 789, 1024])
    val_split: float = Field(default=0.15, ge=0.0, lt=1.0)
    test_split: float = Field(default=0.15, ge=0.0, lt=1.0)


class LoggingConfig(BaseConfig):
    """Logging configuration."""

    level: str = Field(default="INFO")
    format: str = Field(
        default="json",
        description="Log format: 'json' or 'text'",
    )
    file: str | None = Field(default=None)


class SSLConfig(BaseConfig):
    """SSL analyzer configuration."""

    timeout_seconds: int = Field(default=5, ge=1, le=30)
    verify_hostname: bool = Field(default=True)


class DomainConfig(BaseConfig):
    """Domain age analyzer configuration."""

    whois_timeout_seconds: int = Field(default=10, ge=1, le=30)
    rdap_fallback: bool = Field(default=True)
    missing_value: int = Field(default=-1)


class Settings(BaseSettings):
    """Root application settings.

    Aggregates all configuration sections.
    Loads from environment variables and .env file.
    """

    # Application metadata
    app_name: str = Field(default="PhishGuard")
    app_version: str = Field(default="0.1.0")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_secret_key: str = Field(
        default="change-this-to-a-random-secret-key",
        alias="APP_SECRET_KEY",
    )

    # Sub-configurations
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    adaptive: AdaptiveConfig = Field(default_factory=AdaptiveConfig)
    ssl_analyzer: SSLConfig = Field(default_factory=SSLConfig)
    domain_analyzer: DomainConfig = Field(default_factory=DomainConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    screenshot: ScreenshotConfig = Field(default_factory=ScreenshotConfig)
    ocr: OCRConfig = Field(default_factory=OCRConfig)
    visual: VisualConfig = Field(default_factory=VisualConfig)
    fusion: FusionConfig = Field(default_factory=FusionConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @classmethod
    def from_yaml(cls, yaml_path: Path | None = None) -> "Settings":
        """Create settings with YAML defaults, overridden by env vars.

        Args:
            yaml_path: Path to YAML config. Defaults to configs/default.yaml.

        Returns:
            Configured Settings instance.
        """
        yaml_config = load_yaml_config(yaml_path)
        # Environment variables take precedence over YAML
        return cls(**yaml_config)


# Global settings singleton
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings singleton.

    Returns:
        The application Settings instance.
    """
    global _settings
    if _settings is None:
        _settings = Settings.from_yaml()
    return _settings


def reset_settings() -> None:
    """Reset the settings singleton. Useful for testing."""
    global _settings
    _settings = None
