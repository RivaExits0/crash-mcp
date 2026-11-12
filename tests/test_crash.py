"""Tests for ELF core dump analysis.

The assertions are architecture independent so the suite passes on any Linux
host (x86_64, aarch64, ...).
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer import CrashAnalyzer, CrashSessionError
from elf_core import ElfCore, ElfCoreError

CORE = os.path.join(ROOT, "tests", "core")
CRASH_BIN = os.path.join(ROOT, "tests", "crash")
BAD = os.path.join(ROOT, "tests", "not_a_dump.bin")


def _core():
    return ElfCore(CORE)


def test_no_dump_loaded():
    a = CrashAnalyzer()
    try:
        a.summary()
        assert False, "expected error"
    except CrashSessionError as e:
        assert "no dump loaded" in str(e)


def test_invalid_dump_file():
    with open(BAD, "wb") as f:
        f.write(b"NOTADUMP" * 10)
    try:
        CrashAnalyzer().load(BAD)
        assert False, "expected error"
    except CrashSessionError:
        pass
    finally:
        os.remove(BAD)


def test_elf_core_load_and_summary():
    a = CrashAnalyzer()
    info = a.load(CORE, binary_paths=[CRASH_BIN])
    assert info["format"] == "ELF core"
    assert info["arch"] in ("x64", "x86", "arm64", "arm", "riscv")
    assert info["crash_signal"].startswith("SIG")
    assert info["crash_pc"].startswith("0x")
    assert info["thread_count"] >= 1
    assert info["module_count"] >= 1
    assert info["process_name"] == "crash"


def test_elf_core_process_name_and_signal_code():
    c = _core()
    assert c.process_name == "crash"
    assert c.signal_code is not None
    assert c.signal_code > 0


def test_elf_threads_and_pagination():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.threads(1, 0)
    assert res["total"] >= 1
    assert len(res["threads"]) == 1
    res2 = a.threads(1, 10)
    assert res2["threads"] == []


def test_elf_threads_marks_crashed_thread():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.threads(10, 0)
    crashed = [t for t in res["threads"] if t["state"] == "crashed"]
    assert len(crashed) == 1
    assert crashed[0]["thread_id"] == a.loaded.crash_thread


def test_elf_stack():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.stack(a.loaded.crash_thread, 30, 0)
    assert res["source"] == "gdb"
    assert res["total"] >= 1
    assert "boom" in res["frames"][0]["text"]


def test_elf_stack_wrong_thread():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.stack(999999, 30, 0)
    assert "frames" in res
    assert res.get("error")


def test_elf_stack_pagination():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    full = a.stack(a.loaded.crash_thread, 30, 0)
    page = a.stack(a.loaded.crash_thread, 1, 1)
    assert page["total"] == full["total"]
    assert len(page["frames"]) <= 1


def test_elf_disassemble():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    pc = a.loaded.crash_pc
    res = a.disassemble(hex(pc), 2, 2)
    assert res["address"] == hex(pc)
    assert len(res["instructions"]) >= 1
    assert any(i["address"] == pc for i in res["instructions"])


def test_elf_disassemble_unmapped():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    try:
        a.disassemble(0xDEADBEEF, 2, 2)
        assert False, "expected error"
    except CrashSessionError as e:
        assert "not found" in str(e) or "address" in str(e)


def test_elf_compare():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.compare(CORE)
    assert res["format_a"] == "elf_core"
    assert res["crash_signal_a"] == res["crash_signal_b"]
    assert res["crash_pc_a"] == res["crash_pc_b"]


def test_gdb_unavailable(monkeypatch):
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    monkeypatch.setattr(a.loaded, "_find_gdb", lambda: None)
    res = a.stack(a.loaded.crash_thread, 10, 0)
    assert res["source"] == "none"
    assert "gdb not found" in res["error"]
    assert "registers" in res


def test_gdb_timeout(monkeypatch):
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])

    def fake(binary_paths, timeout=30):
        return {"available": True, "error": "gdb timeout", "traces": {}}

    monkeypatch.setattr(a.loaded, "gdb_backtrace", fake)
    res = a.stack(a.loaded.crash_thread, 10, 0)
    assert res["source"] == "none"
    assert "timeout" in res["error"]


def test_minidump_invalid():
    with open(BAD, "wb") as f:
        f.write(b"MDMP" + b"\x00" * 100)
    try:
        try:
            from minidump_reader import MinidumpAnalyzer
            MinidumpAnalyzer(BAD)
        except Exception:
            pass
    finally:
        if os.path.exists(BAD):
            os.remove(BAD)


def test_minidump_wrong_magic():
    with open(BAD, "wb") as f:
        f.write(b"XXXX" * 10)
    a = CrashAnalyzer()
    try:
        a.load(BAD)
        assert False, "expected error"
    except CrashSessionError:
        pass
    finally:
        os.remove(BAD)


def test_disassemble_caps():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.disassemble(hex(a.loaded.crash_pc), 100, 100)
    assert len(res["instructions"]) <= 65
