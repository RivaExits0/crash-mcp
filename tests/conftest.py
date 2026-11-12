import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

CORE = os.path.join(ROOT, "tests", "core")
CRASH_BIN = os.path.join(ROOT, "tests", "crash")
CRASH_SRC = os.path.join(ROOT, "tests", "crash.c")


def pytest_sessionstart(session):
    if not os.path.exists(CRASH_BIN):
        subprocess.check_call(["gcc", "-O0", "-g", "-static", "-o", CRASH_BIN, CRASH_SRC])
    if not os.path.exists(CORE):
        subprocess.check_call(["bash", "-c", "ulimit -c unlimited && (./crash || true)"], cwd=os.path.dirname(CRASH_BIN))
