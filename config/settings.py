"""Configuration management for NetSentinel."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
import bcrypt

from utils.logger import setup_logger

logger = setup_logger("netsentinel.config")

CONFIG_DIR = Path(__file__).parent
PROJECT_ROOT = CONFIG_DIR.parent
DEFAULT_CONFIG_PATH = CONFIG_DIR / "default.yaml"


@dataclass(frozen=True)
class CaptureConfig:
    interface: str = ""
    bpf_filter: str = ""
    packet_limit: int = 0
    snap_length: int = 65535


@dataclass(frozen=True)
class DatabaseConfig:
    path: str = "data/netsentinel.db"
    wal_mode: bool = True


@dataclass(frozen=True)
class ApiConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    cors_origins: list[str] = field(default_factory=lambda: [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ])


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool = True
    secret_key: str = ""
    algorithm: str = "HS256"
    token_expire_minutes: int = 60
    username: str = "admin"
    password_hash: str = ""


@dataclass(frozen=True)
class DashboardConfig:
    refresh_interval: int = 5
    theme: str = "dark"


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = "logs/netsentinel.log"
    max_size: int = 10_485_760
    backup_count: int = 5


@dataclass(frozen=True)
class AlertRule:
    name: str = ""
    condition: str = ""
    severity: str = "info"
    message: str = ""


@dataclass(frozen=True)
class AlertsConfig:
    enabled: bool = True
    rules: list[AlertRule] = field(default_factory=list)


@dataclass(frozen=True)
class PluginsConfig:
    enabled: bool = True
    directory: str = "plugins"


@dataclass(frozen=True)
class ReportsConfig:
    output_dir: str = "reports/output"
    formats: list[str] = field(default_factory=lambda: ["pdf", "html", "json"])


@dataclass(frozen=True)
class Config:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Override config values with NETSENTINEL_* environment variables.

    Mapping convention:
        NETSENTINEL_CAPTURE_INTERFACE  -> capture.interface
        NETSENTINEL_DATABASE_PATH     -> database.path
        NETSENTINEL_API_HOST          -> api.host
        NETSENTINEL_API_PORT          -> api.port
        NETSENTINEL_AUTH_ENABLED      -> auth.enabled  (true/false)
        NETSENTINEL_AUTH_SECRET_KEY   -> auth.secret_key
        NETSENTINEL_LOGGING_LEVEL     -> logging.level
        NETSENTINEL_LOGGING_FILE      -> logging.file
    """
    env_map: dict[str, tuple[str, str]] = {
        "NETSENTINEL_CAPTURE_INTERFACE": ("capture", "interface"),
        "NETSENTINEL_CAPTURE_BPF_FILTER": ("capture", "bpf_filter"),
        "NETSENTINEL_CAPTURE_PACKET_LIMIT": ("capture", "packet_limit"),
        "NETSENTINEL_CAPTURE_SNAP_LENGTH": ("capture", "snap_length"),
        "NETSENTINEL_DATABASE_PATH": ("database", "path"),
        "NETSENTINEL_DATABASE_WAL_MODE": ("database", "wal_mode"),
        "NETSENTINEL_API_HOST": ("api", "host"),
        "NETSENTINEL_API_PORT": ("api", "port"),
        "NETSENTINEL_AUTH_ENABLED": ("auth", "enabled"),
        "NETSENTINEL_AUTH_SECRET_KEY": ("auth", "secret_key"),
        "NETSENTINEL_AUTH_USERNAME": ("auth", "username"),
        "NETSENTINEL_AUTH_PASSWORD_HASH": ("auth", "password_hash"),
        "NETSENTINEL_AUTH_TOKEN_EXPIRE_MINUTES": ("auth", "token_expire_minutes"),
        "NETSENTINEL_DASHBOARD_REFRESH_INTERVAL": ("dashboard", "refresh_interval"),
        "NETSENTINEL_DASHBOARD_THEME": ("dashboard", "theme"),
        "NETSENTINEL_LOGGING_LEVEL": ("logging", "level"),
        "NETSENTINEL_LOGGING_FILE": ("logging", "file"),
        "NETSENTINEL_LOGGING_MAX_SIZE": ("logging", "max_size"),
        "NETSENTINEL_LOGGING_BACKUP_COUNT": ("logging", "backup_count"),
        "NETSENTINEL_ALERTS_ENABLED": ("alerts", "enabled"),
        "NETSENTINEL_PLUGINS_ENABLED": ("plugins", "enabled"),
        "NETSENTINEL_PLUGINS_DIRECTORY": ("plugins", "directory"),
        "NETSENTINEL_REPORTS_OUTPUT_DIR": ("reports", "output_dir"),
    }

    bool_values = {"true": True, "false": False, "1": True, "0": False}
    int_keys = {
        "packet_limit", "snap_length", "port", "token_expire_minutes",
        "refresh_interval", "max_size", "backup_count",
    }

    for env_var, (section, key) in env_map.items():
        value = os.environ.get(env_var)
        if value is None:
            continue
        if section not in raw:
            raw[section] = {}

        if key in int_keys:
            try:
                raw[section][key] = int(value)
            except ValueError:
                logger.warning("Invalid integer for %s=%s, ignoring", env_var, value)
                continue
        elif key in {"enabled", "wal_mode"}:
            raw[section][key] = bool_values.get(value.lower(), True)
        else:
            raw[section][key] = value

        logger.debug("Env override applied: %s -> %s.%s = %s", env_var, section, key, value)

    return raw


def _parse_alert_rules(rules_raw: list[dict[str, Any]]) -> list[AlertRule]:
    """Parse raw alert rule dicts into AlertRule dataclasses."""
    rules: list[AlertRule] = []
    for rule in rules_raw:
        rules.append(AlertRule(
            name=rule.get("name", ""),
            condition=rule.get("condition", ""),
            severity=rule.get("severity", "info"),
            message=rule.get("message", ""),
        ))
    return rules


def _build_config(raw: dict[str, Any]) -> Config:
    """Build a Config dataclass from a raw dictionary."""
    capture_raw = raw.get("capture", {})
    database_raw = raw.get("database", {})
    api_raw = raw.get("api", {})
    auth_raw = raw.get("auth", {})
    dashboard_raw = raw.get("dashboard", {})
    logging_raw = raw.get("logging", {})
    alerts_raw = raw.get("alerts", {})
    plugins_raw = raw.get("plugins", {})
    reports_raw = raw.get("reports", {})

    return Config(
        capture=CaptureConfig(
            interface=capture_raw.get("interface", ""),
            bpf_filter=capture_raw.get("bpf_filter", ""),
            packet_limit=int(capture_raw.get("packet_limit", 0)),
            snap_length=int(capture_raw.get("snap_length", 65535)),
        ),
        database=DatabaseConfig(
            path=database_raw.get("path", "data/netsentinel.db"),
            wal_mode=database_raw.get("wal_mode", True),
        ),
        api=ApiConfig(
            host=api_raw.get("host", "0.0.0.0"),
            port=int(api_raw.get("port", 8080)),
            cors_origins=api_raw.get("cors_origins", []),
        ),
        auth=AuthConfig(
            enabled=auth_raw.get("enabled", True),
            secret_key=auth_raw.get("secret_key", ""),
            algorithm=auth_raw.get("algorithm", "HS256"),
            token_expire_minutes=int(auth_raw.get("token_expire_minutes", 60)),
            username=auth_raw.get("username", "admin"),
            password_hash=auth_raw.get("password_hash", ""),
        ),
        dashboard=DashboardConfig(
            refresh_interval=int(dashboard_raw.get("refresh_interval", 5)),
            theme=dashboard_raw.get("theme", "dark"),
        ),
        logging=LoggingConfig(
            level=logging_raw.get("level", "INFO"),
            file=logging_raw.get("file", "logs/netsentinel.log"),
            max_size=int(logging_raw.get("max_size", 10_485_760)),
            backup_count=int(logging_raw.get("backup_count", 5)),
        ),
        alerts=AlertsConfig(
            enabled=alerts_raw.get("enabled", True),
            rules=_parse_alert_rules(alerts_raw.get("rules", [])),
        ),
        plugins=PluginsConfig(
            enabled=plugins_raw.get("enabled", True),
            directory=plugins_raw.get("directory", "plugins"),
        ),
        reports=ReportsConfig(
            output_dir=reports_raw.get("output_dir", "reports/output"),
            formats=reports_raw.get("formats", ["pdf", "html", "json"]),
        ),
    )


def _validate_config(config: Config) -> None:
    """Validate configuration values and raise ValueError on issues."""
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if config.logging.level.upper() not in valid_levels:
        raise ValueError(
            f"Invalid logging level: {config.logging.level!r}. "
            f"Must be one of {valid_levels}"
        )

    if config.api.port < 1 or config.api.port > 65535:
        raise ValueError(f"Invalid API port: {config.api.port}")

    if config.auth.token_expire_minutes < 1:
        raise ValueError(
            f"Invalid token expiry: {config.auth.token_expire_minutes}"
        )

    if config.capture.snap_length < 0:
        raise ValueError(
            f"Invalid snap length: {config.capture.snap_length}"
        )

    if config.auth.enabled and not config.auth.secret_key:
        raise ValueError(
            "Authentication is enabled but no secret_key is configured. "
            "Set NETSENTINEL_AUTH_SECRET_KEY or provide one in config."
        )

    if config.dashboard.theme not in ("dark", "light"):
        raise ValueError(
            f"Invalid dashboard theme: {config.dashboard.theme!r}. "
            "Must be 'dark' or 'light'."
        )

    valid_severities = {"info", "warning", "critical", "error"}
    for rule in config.alerts.rules:
        if rule.severity.lower() not in valid_severities:
            raise ValueError(
                f"Invalid severity {rule.severity!r} in alert rule "
                f"{rule.name!r}. Must be one of {valid_severities}"
            )


def _generate_defaults(config: Config) -> Config:
    """Generate default values for empty secret fields."""
    from dataclasses import replace

    updates: dict[str, Any] = {}

    if not config.auth.secret_key:
        updates["secret_key"] = secrets.token_urlsafe(64)
        logger.info("Generated random auth secret key")

    if not config.auth.password_hash:
        updates["password_hash"] = bcrypt.hashpw(
            b"admin", bcrypt.gensalt()
        ).decode("utf-8")
        logger.info("Generated default password hash for user 'admin'")

    if updates:
        return replace(config, auth=replace(config.auth, **updates))
    return config


def load_config(
    config_path: Path | str | None = None,
    *,
    validate: bool = True,
    generate_defaults: bool = True,
) -> Config:
    """Load configuration from YAML file with env overrides.

    Args:
        config_path: Path to YAML config file. Uses default.yaml if None.
        validate: Whether to validate the loaded config.
        generate_defaults: Whether to auto-generate secret keys/hashes.

    Returns:
        Fully resolved Config dataclass.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    config_path = Path(config_path)

    raw: dict[str, Any] = {}
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        logger.debug("Loaded config from %s", config_path)
    else:
        logger.warning("Config file %s not found, using defaults", config_path)

    raw = _apply_env_overrides(raw)
    config = _build_config(raw)

    if generate_defaults:
        config = _generate_defaults(config)

    if validate:
        _validate_config(config)

    logger.info("Configuration loaded and validated successfully")
    return config


_config_instance: Config | None = None


def get_config(
    config_path: Path | str | None = None,
    *,
    force_reload: bool = False,
) -> Config:
    """Get or create the singleton Config instance.

    Args:
        config_path: Path to YAML config file.
        force_reload: If True, reload config even if already loaded.

    Returns:
        The singleton Config instance.
    """
    global _config_instance
    if _config_instance is None or force_reload:
        _config_instance = load_config(config_path)
    return _config_instance
