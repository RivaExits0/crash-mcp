import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from analyzer import CrashAnalyzer, CrashSessionError

CORE = os.path.join(ROOT, "tests", "core")
CRASH_BIN = os.path.join(ROOT, "tests", "crash")


def test_load_missing_binary():
    a = CrashAnalyzer()
    try:
        a.load(CORE, binary_paths=["/no/such/binary"])
        assert False
    except CrashSessionError as e:
        assert "binary not found" in str(e)


def test_load_missing_dump():
    a = CrashAnalyzer()
    try:
        a.load("/no/such/core")
        assert False
    except CrashSessionError as e:
        assert "not found" in str(e)


def test_summary_no_dump():
    a = CrashAnalyzer()
    try:
        a.summary()
        assert False
    except CrashSessionError as e:
        assert "no dump loaded" in str(e)


def test_threads_pagination_offset():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.threads(1, 100)
    assert res["threads"] == []
    assert res["total"] == 1


def test_disassemble_caps_analyzer():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.disassemble("0x4007c4", 100, 100)
    assert len(res["instructions"]) <= 65
