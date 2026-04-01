"""Configuration management for AuthKeeper.

Provides application settings using platformdirs for
standard configuration paths.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir, user_data_dir


# Default paths
DEFAULT_CONFIG_DIR = Path(user_config_dir("authkeeper", "authkeeper"))
DEFAULT_DATA_DIR = Path(user_data_dir("authkeeper", "authkeeper"))


@dataclass
class AppConfig:
    """Application configuration.

    Attributes:
        data_dir: Directory for vault and data files.
        config_dir: Directory for configuration files.
        clipboard_timeout: Seconds before clipboard auto-clear.
        auto_lock_enabled: Whether auto-lock is enabled.
        auto_lock_timeout: Seconds before auto-lock.
        theme: UI theme ("dark" or "light").
    """

    data_dir: Path = field(default_factory=lambda: DEFAULT_DATA_DIR)
    config_dir: Path = field(default_factory=lambda: DEFAULT_CONFIG_DIR)
    clipboard_timeout: int = 30
    auto_lock_enabled: bool = True
    auto_lock_timeout: int = 300  # 5 minutes
    theme: str = "dark"

    def ensure_directories(self) -> None:
        """Create configuration and data directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)


# Global configuration instance
_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Get the global configuration instance.

    Returns:
        The global AppConfig instance.
    """
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def set_config(config: AppConfig) -> None:
    """Set the global configuration instance.

    Args:
        config: The configuration to use.
    """
    global _config
    _config = config
