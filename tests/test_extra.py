"""Tests for session management, validation and pagination edge cases."""

import os
import sys

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


def test_load_missing_symbols():
    a = CrashAnalyzer()
    try:
        a.load(CORE, binary_paths=[CRASH_BIN], symbols_path="/no/such/symbols")
        assert False
    except CrashSessionError as e:
        assert "symbols file not found" in str(e)


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
    assert res["total"] >= 1


def test_threads_limit_is_capped():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.threads(100000, 0)
    assert res["limit"] <= 1000


def test_disassemble_caps_analyzer():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.disassemble(hex(a.loaded.crash_pc), 100, 100)
    assert len(res["instructions"]) <= 65


def test_disassemble_invalid_address():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    try:
        a.disassemble("not-an-address", 1, 1)
        assert False
    except CrashSessionError as e:
        assert "invalid address" in str(e)


def test_compare_missing_second_dump():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    try:
        a.compare("/no/such/core")
        assert False
    except CrashSessionError as e:
        assert "failed to load second dump" in str(e)


def test_reload_replaces_previous_session():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    first = a.loaded
    a.load(CORE, binary_paths=[CRASH_BIN])
    assert a.loaded is not first
    assert a.summary()["format"] == "ELF core"
