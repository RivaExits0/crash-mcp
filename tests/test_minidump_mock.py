import os, sys, types
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pytest
from unittest import mock
from minidump_reader import MinidumpAnalyzer
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE


def make_fake_md():
    md = types.SimpleNamespace()
    si = types.SimpleNamespace()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AMD64
    md.sysinfo = si
    mod = types.SimpleNamespace()
    mod.name = "fake.dll"
    mod.baseaddress = 0x1000
    mod.size = 0x2000
    ml = types.SimpleNamespace()
    ml.modules = [mod]
    md.modules = ml
    ctx = types.SimpleNamespace()
    ctx.Rip = 0x1234
    ctx.Rsp = 0x5000
    ctx.Rbp = 0x4ff0
    t = types.SimpleNamespace()
    t.ThreadId = 7
    t.ContextObject = ctx
    tl = types.SimpleNamespace()
    tl.threads = [t]
    md.threads = tl
    er = types.SimpleNamespace()
    er.ThreadId = 7
    er.ExceptionCode = 0xC0000005
    er.ExceptionAddress = 0x1234
    er.ExceptionInformation = []
    ex = types.SimpleNamespace()
    ex.exception_records = [er]
    md.exception = ex
    reader = types.SimpleNamespace()
    reader.read = lambda addr, size: b"\x90" * size
    md.get_reader = lambda: reader
    return md


def test_minidump_mock_happy_path(monkeypatch, tmp_path):
    fake = make_fake_md()
    p = tmp_path / "fake.dmp"
    p.write_bytes(b"MDMP" + b"\x00" * 100)
    import minidump.minidumpfile as mdf
    import minidump_reader
    monkeypatch.setattr(mdf.MinidumpFile, "parse", staticmethod(lambda path: fake))
    monkeypatch.setattr(minidump_reader.MinidumpFile, "parse", staticmethod(lambda path: fake))
    a = MinidumpAnalyzer(str(p))
    assert a.arch == "x64"
    assert a.crash_thread == 7
    assert a.crash_code == 0xC0000005
    assert a.crash_addr == 0x1234
    assert len(a.threads) == 1
    assert a.threads[0]["pc"] == 0x1234
    assert a.modules[0]["name"] == "fake.dll"
    assert a.read_memory(0x1000, 4) == b"\x90" * 4
    assert "fake.dll" in a.addr_str(0x1100)
    ins = a.disassemble(0x1000, 1, 1)
    assert len(ins) >= 1
    res = a.stack_frames(7, 5, 0)
    assert res["thread_id"] == 7
    assert "frames" in res


def test_minidump_mock_no_exception(monkeypatch, tmp_path):
    fake = make_fake_md()
    fake.exception = None
    fake.threads.threads = []
    p = tmp_path / "fake.dmp"
    p.write_bytes(b"MDMP" + b"\x00" * 100)
    import minidump.minidumpfile as mdf
    import minidump_reader
    monkeypatch.setattr(mdf.MinidumpFile, "parse", staticmethod(lambda path: fake))
    monkeypatch.setattr(minidump_reader.MinidumpFile, "parse", staticmethod(lambda path: fake))
    a = MinidumpAnalyzer(str(p))
    assert a.crash_code is None
    assert a.crash_addr is None


def test_minidump_mock_unknown_arch(monkeypatch, tmp_path):
    fake = make_fake_md()
    fake.sysinfo.ProcessorArchitecture = 999
    p = tmp_path / "fake.dmp"
    p.write_bytes(b"MDMP" + b"\x00" * 100)
    import minidump.minidumpfile as mdf
    import minidump_reader
    monkeypatch.setattr(mdf.MinidumpFile, "parse", staticmethod(lambda path: fake))
    monkeypatch.setattr(minidump_reader.MinidumpFile, "parse", staticmethod(lambda path: fake))
    a = MinidumpAnalyzer(str(p))
    assert a.arch not in ("x64", "x86")
