import os
import yaml


_DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config.yaml",
)

_config: dict = {}


def load_config(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    global _config
    with open(path, "r") as f:
        _config = yaml.safe_load(f) or {}
    return _config


def get_config() -> dict:
    if not _config:
        load_config()
    return _config


def get(section: str, key: str, default=None):
    cfg = get_config()
    return cfg.get(section, {}).get(key, default)
