"""crash-mcp: inspect native crash dumps via MCP."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    from mcp.server.mcpserver import MCPServer as FastMCP

from analyzer import SESSION, CrashSessionError

mcp = FastMCP("crash")


def _ok(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False, default=str)


def _err(e: Exception) -> str:
    return f"error: {e}"


@mcp.tool()
def crash_load(dump_path: str, binary_paths: Optional[List[str]] = None,
              symbols_path: Optional[str] = None) -> str:
    """Load a crash dump (ELF core or Windows minidump) into the session.

    Use first, before any other crash_* tool. Detects format, architecture,
    threads, modules and exception info. Does not execute the dump.
    Missing binaries/symbols are reported, not guessed.
    """
    try:
        info = SESSION.load(dump_path, binary_paths or [], symbols_path)
        return _ok(info)
    except Exception as e:
        return _err(e)


@mcp.tool()
def crash_summary() -> str:
    """Return a short summary of the loaded dump.

    Use to get crash type, faulting address, faulting thread, arch, module
    and symbol resolution status. Returns unknown for missing fields.
    """
    try:
        return _ok(SESSION.summary())
    except Exception as e:
        return _err(e)


@mcp.tool()
def crash_threads(limit: int = 20, offset: int = 0) -> str:
    """List threads in the loaded dump.

    Use to find the faulting thread or inspect thread states.
    Supports limit/offset pagination.
    """
    try:
        return _ok(SESSION.threads(limit, offset))
    except Exception as e:
        return _err(e)


@mcp.tool()
def crash_stack(thread_id: Any, limit: int = 30, offset: int = 0) -> str:
    """Return stack frames for a thread.

    Use after crash_threads to inspect a specific thread. Shows symbols when
    available, otherwise module+RVA. Paginated by limit/offset.
    Reports the reason if unwinding is unavailable.
    """
    try:
        tid = int(thread_id)
    except Exception:
        return f"error: invalid thread_id: {thread_id}"
    try:
        return _ok(SESSION.stack(tid, limit, offset))
    except Exception as e:
        return _err(e)


@mcp.tool()
def crash_disassemble(address: Any, before: int = 8, after: int = 8) -> str:
    """Disassemble memory around an address in the dump.

    Use to inspect instructions near the crash address. before/after are
    instruction counts (capped). Returns an error if memory is unavailable.
    """
    before = max(0, min(int(before), 32))
    after = max(0, min(int(after), 32))
    try:
        return _ok(SESSION.disassemble(address, before, after))
    except Exception as e:
        return _err(e)


@mcp.tool()
def crash_compare(dump_path_a: str, dump_path_b: str) -> str:
    """Compare two crash dumps.

    Use to check whether two crashes have the same type/address/module/thread
    counts. Best-effort; missing symbols are reported.
    """
    try:
        SESSION.load(dump_path_a)
        return _ok(SESSION.compare(dump_path_b))
    except Exception as e:
        return _err(e)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
