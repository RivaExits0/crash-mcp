"""ELF core dump parsing helpers."""

from __future__ import annotations

import os
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment

ARCH_MAP = {
    "EM_X86_64": "x64",
    "EM_386": "x86",
    "EM_AARCH64": "arm64",
    "EM_ARM": "arm",
    "EM_RISCV": "riscv",
}


def _machine_name(e_machine) -> str:
    name = getattr(e_machine, "name", str(e_machine))
    return name


class ElfCoreError(Exception):
    pass


class ElfCore:
    def __init__(self, path: str):
        self.path = path
        if not os.path.isfile(path):
            raise ElfCoreError(f"file not found: {path}")
        try:
            self._f = open(path, "rb")
            self.elf = ELFFile(self._f)
        except Exception as e:
            raise ElfCoreError(f"not a valid ELF file: {e}")
        if self.elf.header.e_type != "ET_CORE":
            raise ElfCoreError(f"not an ELF core dump (e_type={self.elf.header.e_type})")
        self.arch = ARCH_MAP.get(_machine_name(self.elf.header.e_machine), _machine_name(self.elf.header.e_machine))
        self.os = "Linux/Unix"
        self._loads = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.threads: List[Dict[str, Any]] = []
        self.modules: List[Dict[str, Any]] = []
        self.crash_thread: Optional[int] = None
        self.crash_signal: Optional[str] = None
        self.crash_pc: Optional[int] = None
        self.process_name: Optional[str] = None
        self.signal_code: Optional[int] = None
        self._parse_notes()
        self._parse_modules()

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass

    # ---------- notes ----------
    def _parse_notes(self):
        prstatus_list = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_NOTE":
                continue
            if not isinstance(seg, NoteSegment):
                continue
            for note in seg.iter_notes():
                ntype = note["n_type"]
                desc = note["n_desc"]
                if ntype == "NT_PRSTATUS":
                    pr = self._parse_prstatus_bytes(desc)
                    prstatus_list.append(pr)
                elif ntype == "NT_PRPSINFO":
                    try:
                        fname = getattr(desc, "pr_fname", None)
                        if isinstance(fname, (bytes, bytearray)):
                            self.process_name = fname.split(b"\x00")[0].decode("utf-8", "replace")
                        elif fname is not None:
                            self.process_name = str(fname)
                    except Exception:
                        pass
                elif ntype == "NT_SIGINFO":
                    try:
                        if isinstance(desc, (bytes, bytearray)) and len(desc) >= 8:
                            self.signal_code = struct.unpack_from("<i", bytes(desc), 8)[0]
                    except Exception:
                        pass
                elif ntype == "NT_FILE":
                    self._parse_nt_file(desc)
        for pr in prstatus_list:
            tid = pr.get("pid") if pr.get("pid") is not None else len(self.threads) + 1
            sig = pr.get("signal", 0)
            pc = pr.get("pc")
            self.threads.append({
                "thread_id": tid,
                "state": "stopped",
                "signal": sig,
                "pc": pc,
                "registers": pr.get("regs", {}),
            })
        for t in self.threads:
            if t.get("signal", 0) not in (0, None):
                self.crash_thread = t["thread_id"]
                self.crash_signal = self._signal_name(t["signal"])
                self.crash_pc = t.get("pc")
                break
        if self.crash_thread is None and self.threads:
            self.crash_thread = self.threads[0]["thread_id"]
            self.crash_pc = self.threads[0].get("pc")

    def _parse_prstatus_bytes(self, desc) -> Dict[str, Any]:
        result = {"pid": None, "signal": 0, "pc": None, "regs": {}}
        if not isinstance(desc, (bytes, bytearray)):
            # maybe dict
            if isinstance(desc, dict):
                result["pid"] = desc.get("pr_pid")
                result["signal"] = desc.get("pr_cursig", 0)
                regs = desc.get("pr_reg", {})
                if isinstance(regs, dict):
                    result["regs"] = dict(regs)
                    for pcname in ("rip", "eip", "pc", "r15"):
                        if pcname in regs:
                            result["pc"] = regs[pcname]
                            break
            return result
        data = bytes(desc)
        result["signal"] = struct.unpack_from("<i", data, 0)[0]
        is64 = self.arch in ("x64", "arm64")
        if is64:
            pid_off = 32
            reg_off = 112
            reg_size = 8
        else:
            pid_off = 24
            reg_off = 64
            reg_size = 4
        if pid_off + 4 <= len(data):
            result["pid"] = struct.unpack_from("<i", data, pid_off)[0]
        # pc register index
        if self.arch == "x64":
            pc_index = 16
        elif self.arch == "arm64":
            pc_index = 32
        elif self.arch == "x86":
            pc_index = 12
        elif self.arch == "arm":
            pc_index = 15
        else:
            pc_index = None
        if pc_index is not None:
            off = reg_off + pc_index * reg_size
            if off + reg_size <= len(data):
                fmt = "<Q" if is64 else "<I"
                result["pc"] = struct.unpack_from(fmt, data, off)[0]
        return result

    def _parse_nt_file(self, desc):
        # desc is Container with entries and filename list
        try:
            entries = getattr(desc, "Elf_Nt_File_Entry", None)
            names = getattr(desc, "filename", None)
            if entries is None and isinstance(desc, dict):
                entries = desc.get("Elf_Nt_File_Entry", [])
                names = desc.get("filename", [])
            if not entries:
                return
            for i, e in enumerate(entries):
                vm_start = int(getattr(e, "vm_start", e.get("vm_start") if isinstance(e, dict) else 0))
                vm_end = int(getattr(e, "vm_end", e.get("vm_end") if isinstance(e, dict) else 0))
                path = ""
                if names and i < len(names):
                    raw = names[i]
                    if isinstance(raw, (bytes, bytearray)):
                        path = raw.split(b"\x00")[0].decode("utf-8", "replace")
                    else:
                        path = str(raw)
                self.modules.append({
                    "path": path,
                    "base": vm_start,
                    "size": vm_end - vm_start,
                })
        except Exception:
            pass

    def _parse_prstatus(self, desc) -> Dict[str, Any]:
        # desc is dict-like from pyelftools for NT_PRSTATUS
        result = {"pid": 0, "signal": 0, "pc": None, "regs": {}}
        try:
            # pyelftools returns a dict with 'pr_pid', 'pr_cursig', 'pr_reg'
            result["pid"] = desc.get("pr_pid", 0) if isinstance(desc, dict) else 0
            result["signal"] = desc.get("pr_cursig", 0) if isinstance(desc, dict) else 0
            regs = desc.get("pr_reg", {}) if isinstance(desc, dict) else {}
            # pc register name varies
            for pcname in ("rip", "eip", "pc", "r15"):
                if pcname in regs:
                    result["pc"] = regs[pcname]
                    break
            result["regs"] = dict(regs) if isinstance(regs, dict) else {}
        except Exception:
            pass
        # fallback: if desc is bytes, skip
        return result

    def _signal_name(self, sig: int) -> str:
        names = {
            4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
            10: "SIGSEGV", 11: "SIGSEGV", 5: "SIGTRAP",
        }
        return names.get(sig, f"signal {sig}")

    def _parse_modules(self):
        # If NT_FILE didn't populate, try to infer from PT_LOAD file-backed? Keep as is.
        # Deduplicate by path
        seen = set()
        uniq = []
        for m in self.modules:
            key = (m["path"], m["base"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(m)
        self.modules = uniq

    # ---------- memory ----------
    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        for seg in self._loads:
            vaddr = seg["p_vaddr"]
            filesz = seg["p_filesz"]
            if vaddr <= addr < vaddr + filesz:
                off = addr - vaddr
                if off + size > filesz:
                    # maybe span segments; return partial
                    avail = filesz - off
                    if avail <= 0:
                        return None
                    data = seg.data()[off:off + avail]
                    # try to fill rest from next segments
                    rest = size - len(data)
                    if rest > 0:
                        nxt = self.read_memory(addr + len(data), rest)
                        if nxt:
                            data += nxt
                    return data
                return seg.data()[off:off + size]
        return None

    def module_for_addr(self, addr: int) -> Optional[Dict[str, Any]]:
        for m in self.modules:
            if m["base"] <= addr < m["base"] + m["size"]:
                return m
        return None

    def addr_str(self, addr: int) -> str:
        m = self.module_for_addr(addr)
        if m:
            return f"0x{addr:x} ({m['path']}+0x{addr - m['base']:x})"
        return f"0x{addr:x}"

    # ---------- gdb ----------
    def gdb_backtrace(self, binary_paths: List[str], timeout: int = 30) -> Dict[str, Any]:
        gdb = self._find_gdb()
        if not gdb:
            return {"available": False, "error": "gdb not found", "traces": {}}
        cmd = [gdb, "-batch", "-nx", "-q"]
        exe = None
        for b in binary_paths or []:
            if os.path.isfile(b):
                exe = b
                break
        if exe:
            cmd.append(exe)
        cmd.append(self.path)
        cmd += ["-ex", "set pagination off", "-ex", "thread apply all bt"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"available": True, "error": "gdb timeout", "traces": {}}
        except Exception as e:
            return {"available": True, "error": str(e), "traces": {}}
        # parse per-thread bt
        traces = self._parse_gdb_bt(proc.stdout)
        return {"available": True, "error": None, "raw": proc.stdout, "traces": traces,
                "stderr": proc.stderr}

    def _find_gdb(self) -> Optional[str]:
        import shutil
        return shutil.which("gdb")

    def gdb_available(self) -> bool:
        return self._find_gdb() is not None

    def _parse_gdb_bt(self, text: str) -> Dict[str, List[str]]:
        traces: Dict[str, List[str]] = {}
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Thread "):
                # "Thread 1 (LWP 123):" -> prefer LWP id
                parts = stripped.split()
                tid = parts[1]
                if "(" in stripped and "LWP" in stripped:
                    try:
                        lwp = stripped.split("LWP")[1].split(")")[0].strip()
                        tid = lwp
                    except Exception:
                        pass
                current = tid
                traces[current] = []
            elif current is not None and stripped.startswith("#"):
                traces[current].append(stripped)
        if not traces and text.strip():
            traces["1"] = [l.strip() for l in text.splitlines() if l.strip().startswith("#")]
        return traces

    # ---------- disassembly ----------
    def disassemble(self, address: int, before: int, after: int) -> List[Dict[str, Any]]:
        before = max(0, min(before, 64))
        after = max(0, min(after, 64))
        import capstone
        cs_arch, cs_mode = self._capstone_mode()
        cs = capstone.Cs(cs_arch, cs_mode)
        cs.detail = False
        # Read a generous window and try several alignments to find a
        # disassembly whose instruction stream contains the target address.
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
            # fallback: disassemble from address directly
            data = self.read_memory(address, (after + 1) * 16)
            if not data:
                raise ElfCoreError(f"address 0x{address:x} not found in dump memory")
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
            raise ElfCoreError(f"address 0x{address:x} not found in dump memory")
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
        raise ElfCoreError(f"unsupported arch for disassembly: {m}")

    # ---------- summary ----------
    def summary(self) -> Dict[str, Any]:
        return {
            "format": "ELF core",
            "arch": self.arch,
            "os": self.os,
            "process_name": self.process_name or "unknown",
            "crash_thread": self.crash_thread,
            "crash_signal": self.crash_signal or "unknown",
            "signal_code": self.signal_code if self.signal_code is not None else "unknown",
            "crash_pc": f"0x{self.crash_pc:x}" if self.crash_pc is not None else "unknown",
            "crash_pc_str": self.addr_str(self.crash_pc) if self.crash_pc is not None else "unknown",
            "thread_count": len(self.threads),
            "module_count": len(self.modules),
            "symbol_resolution": "unknown (provide binaries/symbols)",
        }
