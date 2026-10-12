# file này chứa config loader, đọc các giá trị config 
import copy
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

POLICIES = ("keep", "drop")

# giá trị mặc định nếu thiếu key/không có file yaml
DEFAULTS: dict[str, Any] = {
    "parser": {
        "max_body_bytes": 65536,
    },
    "flow": {
        "tcp_idle_timeout": 120,
        "udp_idle_timeout": 30,
    },
    "preprocess": {
        "invalid_policy": "keep",
        "unsupported_policy": "keep",
    },
}


# đọc file YAML để điền vào dict các giá trị
class ConfigError(Exception):
    pass


def _is_positive_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value > 0
    )


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_policy(value: Any) -> bool:
    return isinstance(value, str) and value in POLICIES


VALIDATORS: dict[str, tuple[Callable[[Any], bool], str]] = {
    "parser.max_body_bytes": (_is_positive_int, "an integer greater than 0"),
    "flow.tcp_idle_timeout": (_is_positive_number, "a number greater than 0"),
    "flow.udp_idle_timeout": (_is_positive_number, "a number greater than 0"),
    "preprocess.invalid_policy": (_is_policy, "'keep' or 'drop'"),
    "preprocess.unsupported_policy": (_is_policy, "'keep' or 'drop'"),
}


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_config(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _warn_unknown_keys(
    user: dict[str, Any], known: dict[str, Any], source: Path, prefix: str = ""
) -> None:
    for key, value in user.items():
        path = f"{prefix}{key}"
        if key not in known:
            logger.warning("Unknown config key '%s' in '%s' is ignored", path, source)
        elif isinstance(known[key], dict) and isinstance(value, dict):
            _warn_unknown_keys(value, known[key], source, f"{path}.")


def validate_config(config: dict[str, Any], source: Path) -> None:
    for path, (check, expected) in VALIDATORS.items():
        group, key = path.split(".")
        section = config.get(group)
        if not isinstance(section, dict):
            raise ConfigError(
                f"Invalid config in '{source}': '{group}' must be a mapping"
            )
        value = section.get(key)
        if not check(value):
            raise ConfigError(
                f"Invalid config in '{source}': '{path}' must be {expected}, "
                f"got {value!r}"
            )


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)

    try:
        with config_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError:
        logger.warning(
            "Config file '%s' not found, using default configuration", config_path
        )
        return copy.deepcopy(DEFAULTS)
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid YAML in '{config_path}': {error}") from error
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"Cannot read config '{config_path}': {error}") from error

    if data is None:
        return copy.deepcopy(DEFAULTS)
    if not isinstance(data, dict):
        raise ConfigError(
            f"Invalid config in '{config_path}': top level must be a mapping"
        )

    _warn_unknown_keys(data, DEFAULTS, config_path)
    config = merge_config(DEFAULTS, data)
    validate_config(config, config_path)
    return config
