"""Pytest configuration: make the shared mock model importable from every lab."""
import sys
from pathlib import Path

SHARED = Path(__file__).parent / "shared"
if str(SHARED) not in sys.path:
    sys.path.insert(0, str(SHARED))
