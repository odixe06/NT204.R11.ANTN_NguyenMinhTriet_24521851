import copy
from pathlib import Path
from typing import Any

import yaml

# các cấu hình mặc định của pipeline

DEFAULTS: dict[str, Any] = {
    "parser": {
        "max_body_bytes": 65536,
    },
    "flow": {
        # thời gian chờ lớn nhất của 1 packet trong flow TCP là 120s
        "tcp_idle_timeout": 120,
        # ... 1 flow UDP là 30s 
        "udp_idle_timeout": 30,
    },
    "preprocess": {
        "invalid_policy": "keep",
        "unsupported_policy": "keep",
    },
}


class ConfigError(Exception):
    pass


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_config(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        return copy.deepcopy(DEFAULTS)

    try:
        with config_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid YAML in '{config_path}': {error}") from error

    if data is None:
        return copy.deepcopy(DEFAULTS)
    if not isinstance(data, dict):
        raise ConfigError(
            f"Invalid config in '{config_path}': top level must be a mapping"
        )
    return merge_config(DEFAULTS, data)
