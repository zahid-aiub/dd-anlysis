import pytest
import yaml

from trace_analyzer.config import PROJECT_ROOT, ConfigError, load_config

MINIMAL = {
    "data": {"pcapng": "traces/run.pcapng"},
    "protocol": {"sci_tds_baseline": 5},
    "nodes": {},
    "timing": {},
    "rasta": {},
    "output": {"dir": "out"},
}


def write(path, cfg):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


def test_default_config_resolves_to_project_root():
    cfg = load_config()
    assert cfg["base_dir"] == PROJECT_ROOT
    assert cfg["data"]["pcapng"] == PROJECT_ROOT / "TDS_Task/TDS_Task/RealOCWorking_TDS_21026.pcapng"


def test_paths_relative_to_config_file_without_base_dir(tmp_path):
    cfg = load_config(write(tmp_path / "elsewhere" / "cfg.yaml", MINIMAL))
    assert cfg["data"]["pcapng"] == tmp_path / "elsewhere" / "traces" / "run.pcapng"
    assert cfg["output"]["dir"] == tmp_path / "elsewhere" / "out"


def test_base_dir_is_relative_to_config_file(tmp_path):
    cfg = load_config(write(tmp_path / "project" / "config" / "cfg.yaml", {**MINIMAL, "base_dir": ".."}))
    assert cfg["data"]["pcapng"] == tmp_path / "project" / "traces" / "run.pcapng"


def test_missing_section_is_reported(tmp_path):
    broken = {k: v for k, v in MINIMAL.items() if k != "rasta"}
    with pytest.raises(ConfigError, match="rasta"):
        load_config(write(tmp_path / "cfg.yaml", broken))
