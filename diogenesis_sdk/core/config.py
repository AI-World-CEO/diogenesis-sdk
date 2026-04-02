"""Configuration loader with sensible defaults."""

import json
import os

DEFAULT_CONFIG = {
    "enabled": True,
    "buffer_size": 10000,
    "interceptors": {
        "import": True,
        "file": True,
        "subprocess": True,
        "network": True,
    },
    "whitelist": {
        "import_modules": [],
        "file_paths": [],
        "network_hosts": ["localhost", "127.0.0.1"],
        "subprocess_commands": [],
    },
    "suspicious_patterns": {
        "imports": [],
        "file_paths": [],
        "network_hosts": [],
        "subprocess_commands": ["rm -rf", "del /f", "format", "mkfs"],
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base. Override values win. Lists are replaced, not appended."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_dict: dict = None, config_file: str = "diogenesis_sdk.json") -> dict:
    """Load configuration from dict, file, or defaults.

    Priority: config_dict > config_file > defaults.
    User config is merged with defaults so partial configs work.
    """
    config = dict(DEFAULT_CONFIG)

    # Try loading from file
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                file_config = json.load(f)
            config = _deep_merge(config, file_config)
        except Exception:
            pass

    # Dict override wins
    if config_dict:
        config = _deep_merge(config, config_dict)

    return config
