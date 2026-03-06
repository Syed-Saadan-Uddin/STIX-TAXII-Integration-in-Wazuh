"""
Pydantic-based configuration loader for the Wazuh-TI platform.

Loads settings from config.yaml and overrides with environment variables.
Access config with: `config = get_config()`

Sections:
- database: SQLite database path
- wazuh: CDB list path, reload command, log path
- scheduler: default interval, auto-sync toggle
- api: host, port, API key settings
- logging: level, file, rotation settings
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    path: str = "./data/wazuh_ti.db"


class WazuhConfig(BaseModel):
    cdb_list_path: str = "/var/ossec/etc/lists/threat_intel"
    reload_command: str = "/var/ossec/bin/ossec-control reload"
    log_path: str = "/var/ossec/logs/wazuh-ti.log"


class SchedulerConfig(BaseModel):
    default_interval_minutes: int = 60
    auto_sync_enabled: bool = True


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    api_key_enabled: bool = False
    api_key: Optional[str] = None


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: Optional[str] = None
    max_size_mb: int = 50
    backup_count: int = 5


class AppConfig(BaseModel):
    """Top-level application configuration."""
    database: DatabaseConfig = DatabaseConfig()
    wazuh: WazuhConfig = WazuhConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    api: ApiConfig = ApiConfig()
    logging: LoggingConfig = LoggingConfig()


def _load_yaml(config_path: str) -> dict:
    """Load a YAML configuration file and return its contents as a dict."""
    path = Path(config_path)
    if path.exists():
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


@lru_cache()
def get_config() -> AppConfig:
    """
    Load and cache the application configuration.

    Priority: environment variables > config.yaml > defaults
    """
    config_path = os.environ.get("CONFIG_PATH", "config.yaml")
    raw = _load_yaml(config_path)

    # Override with environment variables where applicable
    if os.environ.get("DATABASE_PATH"):
        raw.setdefault("database", {})["path"] = os.environ["DATABASE_PATH"]

    if os.environ.get("LOG_LEVEL"):
        raw.setdefault("logging", {})["level"] = os.environ["LOG_LEVEL"]

    if os.environ.get("API_KEY_ENABLED"):
        raw.setdefault("api", {})["api_key_enabled"] = os.environ["API_KEY_ENABLED"].lower() == "true"

    if os.environ.get("API_KEY"):
        raw.setdefault("api", {})["api_key"] = os.environ["API_KEY"]

    return AppConfig(**raw)
