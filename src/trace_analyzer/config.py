"""Load the YAML configuration and resolve data paths."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "config.yaml"

REQUIRED_SECTIONS = ("data", "protocol", "nodes", "timing", "rasta", "output")


class ConfigError(ValueError):
    pass


def load_config(path: Path | str = DEFAULT_CONFIG) -> dict:
    path = Path(path).resolve()
    with path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    missing = [s for s in REQUIRED_SECTIONS if s not in cfg]
    if missing:
        raise ConfigError(f"{path}: missing section(s): {', '.join(missing)}")

    # Paths resolve against base_dir, which is relative to the config file's directory.
    base = (path.parent / cfg.get("base_dir", ".")).resolve()
    cfg["base_dir"] = base
    cfg["data"] = {key: (base / value).resolve() for key, value in cfg["data"].items()}
    cfg["output"]["dir"] = (base / cfg["output"]["dir"]).resolve()
    return cfg
