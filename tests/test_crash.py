import os
import sys
import json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer import CrashAnalyzer, CrashSessionError
from elf_core import ElfCore, ElfCoreError
from minidump_reader import MinidumpError

CORE = os.path.join(ROOT, "tests", "core")
CRASH_BIN = os.path.join(ROOT, "tests", "crash")
BAD = os.path.join(ROOT, "tests", "not_a_dump.bin")


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
    assert info["arch"] == "arm64"
    assert info["crash_signal"] == "SIGSEGV"
    assert info["crash_pc"] == "0x4007c4"
    assert info["thread_count"] == 1
    assert info["module_count"] >= 1


def test_elf_threads_and_pagination():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.threads(1, 0)
    assert res["total"] == 1
    assert len(res["threads"]) == 1
    res2 = a.threads(1, 10)
    assert res2["threads"] == []


def test_elf_stack():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.stack(a.loaded.crash_thread, 30, 0)
    assert res["source"] == "gdb"
    assert res["total"] == 2
    assert "boom" in res["frames"][0]["text"]


def test_elf_stack_wrong_thread():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.stack(999999, 30, 0)
    # falls back to first trace or reports unavailable
    assert "frames" in res


def test_elf_disassemble():
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    res = a.disassemble("0x4007c4", 2, 2)
    assert res["address"] == "0x4007c4"
    assert len(res["instructions"]) >= 1
    assert any(i["mnemonic"] == "str" for i in res["instructions"])


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


def test_gdb_unavailable(monkeypatch):
    a = CrashAnalyzer()
    a.load(CORE, binary_paths=[CRASH_BIN])
    monkeypatch.setattr(a.loaded, "_find_gdb", lambda: None)
    res = a.stack(a.loaded.crash_thread, 10, 0)
    assert res["source"] == "none"
    assert "gdb not found" in res["error"]


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
        # may parse header then fail; either way no crash
        try:
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
    # before/after capped to 32 by server; analyzer also caps
    res = a.disassemble("0x4007c4", 100, 100)
    assert len(res["instructions"]) <= 65
