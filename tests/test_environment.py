"""Phase 0 smoke tests: toolchain, Wireshark dissectors and input data are in place."""

import importlib
import shutil
import subprocess
import sys

import pytest

from trace_analyzer.config import load_config

CFG = load_config()
TSHARK = CFG["wireshark"]["tshark"]
BASELINE = CFG["protocol"]["sci_tds_baseline"]


def run_tshark(*args: str) -> str:
    result = subprocess.run([TSHARK, *args], capture_output=True, text=True, timeout=120)
    return result.stdout + result.stderr


def test_python_version():
    assert sys.version_info >= (3, 11)


@pytest.mark.parametrize("module", ["dpkt", "fitz", "pandas", "openpyxl", "yaml", "jinja2", "plotly"])
def test_library_imports(module):
    importlib.import_module(module)


def test_tshark_available():
    assert shutil.which(TSHARK), f"{TSHARK} not found on PATH"


@pytest.mark.parametrize("proto", ["rasta_red", "rasta_saf", "sci", f"sci_tds_bl{BASELINE}"])
def test_neupro_dissector_loaded(proto):
    protocols = {line.split("\t")[2] for line in run_tshark("-G", "protocols").splitlines() if line.count("\t") >= 2}
    assert proto in protocols


@pytest.mark.parametrize("key", list(CFG["data"]))
def test_data_file_present(key):
    assert CFG["data"][key].exists(), CFG["data"][key]


def test_pcapng_decodes_with_configured_baseline():
    pcapng = str(CFG["data"]["pcapng"])
    expert = run_tshark("-r", pcapng, "-o", f"sci.tds_bl:{BASELINE}", "-q", "-z", "expert,error")
    assert "Lua Error" not in expert

    frames = run_tshark("-r", pcapng, "-o", f"sci.tds_bl:{BASELINE}", "-Y", f"sci_tds_bl{BASELINE}", "-T", "fields", "-e", "frame.number")
    assert len(frames.split()) > 0
