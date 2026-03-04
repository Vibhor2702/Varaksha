# test_sample.py — minimal pytest suite inside sandbox
# GATE-M GA006 exec test runs this suite to verify safe exec approval.

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from sample_agent import run, compute


def test_run_returns_string():
    result = run("hello")
    assert isinstance(result, str)
    assert "hello" in result


def test_compute_adds():
    assert compute(2, 3) == 5
    assert compute(0, 0) == 0
