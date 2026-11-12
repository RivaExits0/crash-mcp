"""Session management and common reporting for crash-mcp."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from elf_core import ElfCore, ElfCoreError
from minidump_reader import MinidumpAnalyzer, MinidumpError


class CrashSessionError(Exception):
    pass


class CrashAnalyzer:
    def __init__(self):
        self.loaded = None  # ElfCore or MinidumpAnalyzer
        self.path: Optional[str] = None
        self.binary_paths: List[str] = []
        self.symbols_path: Optional[str] = None
        self.format: Optional[str] = None  # "elf_core" | "minidump"

    def _make(self, path: str):
        # detect
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic == b"\x7fELF":
            return ElfCore(path), "elf_core"
        if magic == b"MDMP":
            return MinidumpAnalyzer(path), "minidump"
        raise CrashSessionError(f"unsupported dump format (magic={magic!r})")

    def load(self, dump_path: str, binary_paths=None, symbols_path=None) -> Dict[str, Any]:
        binary_paths = binary_paths or []
        if not os.path.isfile(dump_path):
            raise CrashSessionError(f"dump file not found: {dump_path}")
        for b in binary_paths:
            if not os.path.isfile(b):
                raise CrashSessionError(f"binary not found: {b}")
        if symbols_path and not os.path.isfile(symbols_path):
            raise CrashSessionError(f"symbols file not found: {symbols_path}")
        # close previous
        if self.loaded is not None and hasattr(self.loaded, "close"):
            try:
                self.loaded.close()
            except Exception:
                pass
        analyzer, fmt = self._make(dump_path)
        self.loaded = analyzer
        self.path = dump_path
        self.binary_paths = list(binary_paths)
        self.symbols_path = symbols_path
        self.format = fmt
        return self.summary()

    def require_loaded(self):
        if self.loaded is None:
            raise CrashSessionError("no dump loaded; call crash_load first")

    def summary(self) -> Dict[str, Any]:
        self.require_loaded()
        base = self.loaded.summary()
        base["binary_paths"] = self.binary_paths
        base["symbols_path"] = self.symbols_path
        base["path"] = self.path
        # symbol resolution status
        if self.binary_paths:
            base["symbol_resolution"] = "binaries provided"
        else:
            base["symbol_resolution"] = "no binaries provided"
        # gdb availability for elf
        if self.format == "elf_core":
            base["gdb_available"] = self.loaded.gdb_available()
            if getattr(self.loaded, "process_name", None):
                base["process_name"] = self.loaded.process_name
        return base

    def threads(self, limit: int, offset: int) -> Dict[str, Any]:
        self.require_loaded()
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        all_threads = self.loaded.threads
        page = all_threads[offset:offset + limit]
        out = []
        for t in page:
            state = t.get("state", "unknown")
            if self.format == "elf_core" and t.get("thread_id") == getattr(self.loaded, "crash_thread", None):
                state = "crashed"
            item = {
                "thread_id": t.get("thread_id"),
                "state": state,
            }
            if t.get("signal") is not None:
                item["signal"] = t["signal"]
            pc = t.get("pc")
            if pc is not None:
                item["pc"] = f"0x{pc:x}"
                item["pc_str"] = self.loaded.addr_str(pc)
            item["stack_summary"] = "available via crash_stack"
            out.append(item)
        return {
            "total": len(all_threads),
            "offset": offset,
            "limit": limit,
            "threads": out,
        }

    def stack(self, thread_id, limit, offset) -> Dict[str, Any]:
        self.require_loaded()
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        if self.format == "elf_core":
            # use gdb if available
            gdb_res = self.loaded.gdb_backtrace(self.binary_paths)
            if gdb_res.get("available") and gdb_res.get("traces"):
                key = str(thread_id)
                frames_raw = gdb_res["traces"].get(key)
                if frames_raw is None:
                    # try LWP match or numeric match
                    for k, v in gdb_res["traces"].items():
                        if k == key:
                            frames_raw = v
                            break
                if frames_raw is None:
                    available_keys = ", ".join(gdb_res["traces"].keys())
                    return {
                        "thread_id": thread_id,
                        "source": "gdb",
                        "error": f"thread {thread_id} not found in gdb output (available: {available_keys})",
                        "frames": [],
                    }
                frames = []
                for i, line in enumerate(frames_raw or []):
                    frames.append({"index": i, "text": line})
                total = len(frames)
                frames = frames[offset:offset + limit]
                return {
                    "thread_id": thread_id,
                    "source": "gdb",
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "frames": frames,
                    "gdb_error": gdb_res.get("error"),
                }
            # gdb not available or no traces
            reason = gdb_res.get("error") or "gdb produced no backtrace"
            # fallback: maybe registers only
            t = self._find_thread(thread_id)
            if t is None:
                return {"error": f"thread {thread_id} not found", "frames": []}
            return {
                "thread_id": thread_id,
                "source": "none",
                "error": f"stack trace unavailable: {reason}",
                "registers": t.get("registers", {}),
                "pc": (f"0x{t['pc']:x}" if t.get("pc") is not None else None),
            }
        # minidump
        res = self.loaded.stack_frames(thread_id, limit + offset, 0)
        if "error" in res:
            return res
        frames = res.get("frames", [])
        total = res.get("total", len(frames))
        frames = frames[offset:offset + limit]
        out = []
        for i, fr in enumerate(frames):
            out.append({"index": offset + i, "address": f"0x{fr['address']:x}",
                        "address_str": fr.get("address_str")})
        return {
            "thread_id": thread_id,
            "source": "frame-pointer-walk",
            "total": total,
            "offset": offset,
            "limit": limit,
            "frames": out,
            "note": res.get("note"),
        }

    def _find_thread(self, thread_id):
        for t in self.loaded.threads:
            if t.get("thread_id") == thread_id:
                return t
        return None

    def disassemble(self, address: int, before: int, after: int) -> Dict[str, Any]:
        self.require_loaded()
        before = max(0, min(before, 32))
        after = max(0, min(after, 32))
        try:
            addr_int = int(address, 0) if isinstance(address, str) else int(address)
        except Exception:
            raise CrashSessionError(f"invalid address: {address}")
        try:
            insns = self.loaded.disassemble(addr_int, before, after)
        except Exception as e:
            raise CrashSessionError(str(e))
        lines = []
        for ins in insns:
            lines.append(f"0x{ins['address']:x}: {ins['mnemonic']} {ins['op_str']}")
        return {
            "address": f"0x{addr_int:x}",
            "address_str": self.loaded.addr_str(addr_int),
            "before": before,
            "after": after,
            "instructions": insns,
            "text": "\n".join(lines),
        }

    def compare(self, other_path: str, binary_paths=None) -> Dict[str, Any]:
        self.require_loaded()
        binary_paths = self.binary_paths
        # build second analyzer
        other = CrashAnalyzer()
        try:
            other.load(other_path, binary_paths, self.symbols_path)
        except Exception as e:
            raise CrashSessionError(f"failed to load second dump: {e}")
        a = self.loaded
        b = other.loaded
        # format-specific compare
        if self.format == "elf_core" and other.format == "elf_core":
            res = {
                "format_a": "elf_core", "format_b": "elf_core",
                "arch_a": a.arch, "arch_b": b.arch,
                "crash_signal_a": a.crash_signal, "crash_signal_b": b.crash_signal,
                "crash_pc_a": (f"0x{a.crash_pc:x}" if a.crash_pc is not None else "unknown"),
                "crash_pc_b": (f"0x{b.crash_pc:x}" if b.crash_pc is not None else "unknown"),
                "thread_count_a": len(a.threads), "thread_count_b": len(b.threads),
                "module_count_a": len(a.modules), "module_count_b": len(b.modules),
            }
        elif self.format == "minidump" and other.format == "minidump":
            res = a.compare(b)
        else:
            # cross-format: basic
            sa = a.summary()
            sb = b.summary()
            res = {
                "format_a": self.format, "format_b": other.format,
                "arch_a": sa.get("arch"), "arch_b": sb.get("arch"),
                "crash_thread_a": sa.get("crash_thread"), "crash_thread_b": sb.get("crash_thread"),
                "thread_count_a": sa.get("thread_count"), "thread_count_b": sb.get("thread_count"),
                "note": "cross-format comparison is limited",
            }
        res["note"] = res.get("note", "best-effort comparison; symbol resolution may be incomplete")
        return res


# global session
SESSION = CrashAnalyzer()
