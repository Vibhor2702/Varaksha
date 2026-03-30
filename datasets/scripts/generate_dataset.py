#!/usr/bin/env python3
"""Run the V2 raw physics data generator."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_SCRIPT = ROOT / "varaksha-v2-core" / "00_generate_indian_physics.py"


def main() -> int:
    cmd = [sys.executable, str(GEN_SCRIPT)] + sys.argv[1:]
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
