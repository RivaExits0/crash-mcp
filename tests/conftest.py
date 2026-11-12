"""Pytest configuration and ELF-core fixture setup for crash-mcp."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

CORE = os.path.join(ROOT, "tests", "core")
CRASH_BIN = os.path.join(ROOT, "tests", "crash")
CRASH_SRC = os.path.join(ROOT, "tests", "crash.c")

sys.path.insert(0, os.path.join(ROOT, "tests"))


def pytest_sessionstart(session):
    """Ensure a real ELF core dump fixture exists before the tests run."""
    from make_core import ensure

    ensure()
