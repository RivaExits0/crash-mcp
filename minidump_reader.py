"""Windows minidump parsing helpers."""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Optional

from minidump.minidumpfile import MinidumpFile
from minidump.minidumpreader import MinidumpFileReader
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.constants import MINIDUMP_STREAM_TYPE

ARCH_MAP = {
    PROCESSOR_ARCHITECTURE.AMD64: "x64",
    PROCESSOR_ARCHITECTURE.INTEL: "x86",
    PROCESSOR_ARCHITECTURE.ARM: "arm",
    "AMD64": "x64",
    "INTEL": "x86",
}


class MinidumpError(Exception):
    pass


class MinidumpAnalyzer:
    def __init__(self, path: str):
        self.path = path
        if not os.path.isfile(path):
            raise MinidumpError(f"file not found: {path}")
        try:
            self.md = MinidumpFile.parse(path)
        except Exception as e:
            raise MinidumpError(f"not a valid minidump: {e}")
        self.reader = self.md.get_reader()
        self.arch = self._arch()
        self.os = "Windows"
        self.modules = self._modules()
        self.threads = self._threads()
        self.exception = self._exception()
        self.crash_thread = self.exception.get("thread_id")
        self.crash_code = self.exception.get("code")
        self.crash_addr = self.exception.get("address")
        if self.crash_thread is None and self.threads:
            self.crash_thread = self.threads[0]["thread_id"]
            self.crash_addr = self.threads[0].get("pc")

    def _arch(self) -> str:
        si = self.md.sysinfo
        if si is None:
            return "unknown"
        pa = getattr(si, "ProcessorArchitecture", None)
        if isinstance(pa, int):
            try:
                pa = PROCESSOR_ARCHITECTURE(pa)
            except Exception:
                pass
        name = getattr(pa, "name", str(pa))
        return ARCH_MAP.get(pa, ARCH_MAP.get(name, name))

    def _modules(self) -> List[Dict[str, Any]]:
        out = []
        ml = self.md.modules
        if ml is None:
            return out
        for m in getattr(ml, "modules", []) or []:
            out.append({
                "name": getattr(m, "name", None) or "?",
                "base": getattr(m, "baseaddress", None),
                "size": getattr(m, "size", None),
            })
        return out

    def _threads(self) -> List[Dict[str, Any]]:
        out = []
        tl = self.md.threads
        if tl is None:
            return out
        for t in getattr(tl, "threads", []) or []:
            ctx = getattr(t, "ContextObject", None)
            regs = self._context_to_regs(ctx)
            out.append({
                "thread_id": getattr(t, "ThreadId", None),
                "state": "stopped",
                "pc": regs.get("pc"),
                "registers": regs,
            })
        return out

    def _context_to_regs(self, ctx) -> Dict[str, int]:
        if ctx is None:
            return {}
        # ctx may be a structure with fields; extract common names
        regs = {}
        # try attribute names
        candidates = {
            "x64": ["Rip", "Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp",
                    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"],
            "x86": ["Eip", "Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp"],
        }
        for name in candidates.get(self.arch, []) + candidates["x64"] + candidates["x86"]:
            if hasattr(ctx, name):
                try:
                    regs[name.lower()] = int(getattr(ctx, name))
                except Exception:
                    pass
        # pc alias
        for pcname in ("rip", "eip", "pc"):
            if pcname in regs:
                regs["pc"] = regs[pcname]
                break
        return regs

    def _exception(self) -> Dict[str, Any]:
        ex = self.md.exception
        if ex is None:
            return {"thread_id": None, "code": None, "address": None}
        # ExceptionList has .ExceptionRecords maybe
        recs = getattr(ex, "exception_records", None) or []
        if isinstance(recs, list) and recs:
            r = recs[0]
            return {
                "thread_id": getattr(r, "ThreadId", None),
                "code": getattr(r, "ExceptionCode", None),
                "address": getattr(r, "ExceptionAddress", None),
                "parameters": list(getattr(r, "ExceptionInformation", []) or []),
            }
        return {"thread_id": None, "code": None, "address": None}

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        try:
            return self.reader.read(addr, size)
        except Exception:
            return None

    def module_for_addr(self, addr: int) -> Optional[Dict[str, Any]]:
        for m in self.modules:
            if m["base"] is not None and m["size"] is not None:
                if m["base"] <= addr < m["base"] + m["size"]:
                    return m
        return None

    def addr_str(self, addr: int) -> str:
        m = self.module_for_addr(addr)
        if m:
            return f"0x{addr:x} ({m['name']}+0x{addr - m['base']:x})"
        return f"0x{addr:x}"

    def summary(self) -> Dict[str, Any]:
        return {
            "format": "Windows minidump",
            "arch": self.arch,
            "os": self.os,
            "crash_thread": self.crash_thread,
            "exception_code": (hex(self.crash_code) if self.crash_code is not None else "unknown"),
            "crash_address": (f"0x{self.crash_addr:x}" if self.crash_addr is not None else "unknown"),
            "crash_address_str": (self.addr_str(self.crash_addr) if self.crash_addr is not None else "unknown"),
            "thread_count": len(self.threads),
            "module_count": len(self.modules),
        }

    def stack_frames(self, thread_id: int, limit: int, offset: int) -> Dict[str, Any]:
        t = self._find_thread(thread_id)
        if t is None:
            return {"error": f"thread {thread_id} not found", "frames": []}
        regs = t["registers"]
        frames = []
        # naive frame-pointer walk for x64/x86
        pc = t.get("pc")
        if pc is not None:
            frames.append({"index": 0, "address": pc, "address_str": self.addr_str(pc)})
        bp = regs.get("rbp") or regs.get("ebp")
        sp = regs.get("rsp") or regs.get("esp")
        # walk rbp chain
        if bp and self.arch in ("x64", "x86"):
            cur = bp
            seen = set()
            for i in range(1, limit + offset + 5):
                if cur in seen or cur is None:
                    break
                seen.add(cur)
                # read saved rbp and return address
                if self.arch == "x64":
                    saved_bp = self._read_ptr(cur)
                    ret = self._read_ptr(cur + 8)
                else:
                    saved_bp = self._read_ptr(cur)
                    ret = self._read_ptr(cur + 4)
                if ret is None:
                    break
                frames.append({"index": len(frames), "address": ret, "address_str": self.addr_str(ret)})
                if saved_bp is None or saved_bp <= cur:
                    break
                cur = saved_bp
        # apply offset/limit
        total = len(frames)
        frames = frames[offset:offset + limit]
        return {"thread_id": thread_id, "frames": frames, "total": total,
                "note": "best-effort frame-pointer walk; may be incomplete"}

    def _find_thread(self, tid):
        for t in self.threads:
            if t["thread_id"] == tid:
                return t
        return None

    def _read_ptr(self, addr: int) -> Optional[int]:
        data = self.read_memory(addr, 8 if self.arch == "x64" else 4)
        if not data or len(data) < (8 if self.arch == "x64" else 4):
            return None
        if self.arch == "x64":
            return struct.unpack("<Q", data[:8])[0]
        return struct.unpack("<I", data[:4])[0]

    def disassemble(self, address: int, before: int, after: int):
        import capstone
        before = max(0, min(before, 64))
        after = max(0, min(after, 64))
        cs_arch, cs_mode = self._capstone_mode()
        cs = capstone.Cs(cs_arch, cs_mode)
        span = (before + after + 8) * 16
        window_start = address - span
        best_insns = None
        best_idx = -1
        for align in range(16):
            start = window_start + align
            data = self.read_memory(start, span + 16)
            if not data:
                continue
            insns = list(cs.disasm(data, start))
            idx = None
            for i, ins in enumerate(insns):
                if ins.address <= address < ins.address + ins.size:
                    idx = i
                    break
                if ins.address > address:
                    idx = max(0, i - 1)
                    break
            if idx is None:
                continue
            if idx >= before and (best_insns is None or idx > best_idx):
                best_insns = insns
                best_idx = idx
        if best_insns is None:
            data = self.read_memory(address, (after + 1) * 16)
            if not data:
                raise MinidumpError(f"address 0x{address:x} not found in dump memory")
            best_insns = list(cs.disasm(data, address))
            best_idx = 0
        lo = max(0, best_idx - before)
        hi = min(len(best_insns), best_idx + after + 1)
        out = []
        for ins in best_insns[lo:hi]:
            out.append({
                "address": ins.address,
                "address_str": self.addr_str(ins.address),
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
                "bytes": ins.bytes.hex(),
            })
        if not out:
            raise MinidumpError(f"address 0x{address:x} not found in dump memory")
        return out

    def _capstone_mode(self):
        import capstone
        m = self.arch
        if m == "x64":
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
        if m == "x86":
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        if m == "arm64":
            return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
        if m == "arm":
            return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
        raise MinidumpError(f"unsupported arch: {m}")

    def compare(self, other: "MinidumpAnalyzer") -> Dict[str, Any]:
        return {
            "format_a": "minidump", "format_b": "minidump",
            "exception_code_a": hex(self.crash_code) if self.crash_code is not None else "unknown",
            "exception_code_b": hex(other.crash_code) if other.crash_code is not None else "unknown",
            "crash_address_a": (f"0x{self.crash_addr:x}" if self.crash_addr is not None else "unknown"),
            "crash_address_b": (f"0x{other.crash_addr:x}" if other.crash_addr is not None else "unknown"),
            "arch_a": self.arch, "arch_b": other.arch,
            "module_a": (self.module_for_addr(self.crash_addr)["name"] if self.crash_addr is not None and self.module_for_addr(self.crash_addr) else "unknown"),
            "module_b": (other.module_for_addr(other.crash_addr)["name"] if other.crash_addr is not None and other.module_for_addr(other.crash_addr) else "unknown"),
            "thread_count_a": len(self.threads), "thread_count_b": len(other.threads),
            "note": "best-effort comparison; stack unwinding may be unavailable",
        }
