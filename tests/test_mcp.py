"""End-to-end MCP smoke test for crash-mcp (stdio transport)."""

import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def ensure_core():
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from make_core import ensure

    return ensure()


def test_mcp_crash():
    ensure_core()
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def main():
        params = StdioServerParameters(command="python3", args=["server.py"], cwd=ROOT)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()

                tools = await s.list_tools()
                names = [t.name for t in tools.tools]
                assert all(
                    n in names
                    for n in [
                        "crash_load",
                        "crash_summary",
                        "crash_threads",
                        "crash_stack",
                        "crash_disassemble",
                        "crash_compare",
                    ]
                )

                await s.call_tool(
                    "crash_load",
                    {"dump_path": "tests/core", "binary_paths": ["tests/crash"]},
                )

                res = await s.call_tool("crash_summary", {})
                d = json.loads(res.content[0].text)
                assert d["format"] == "ELF core"
                assert d["crash_signal"].startswith("SIG")
                crash_pc = d["crash_pc"]

                res = await s.call_tool("crash_threads", {"limit": 5, "offset": 0})
                threads = json.loads(res.content[0].text)
                assert threads["total"] >= 1
                tid = threads["threads"][0]["thread_id"]

                res = await s.call_tool("crash_stack", {"thread_id": tid, "limit": 10})
                d2 = json.loads(res.content[0].text)
                assert d2["total"] >= 1

                res = await s.call_tool(
                    "crash_disassemble",
                    {"address": crash_pc, "before": 2, "after": 2},
                )
                d3 = json.loads(res.content[0].text)
                assert len(d3["instructions"]) >= 1

                res = await s.call_tool(
                    "crash_compare",
                    {"dump_path_a": "tests/core", "dump_path_b": "tests/core"},
                )
                d4 = json.loads(res.content[0].text)
                assert d4["crash_signal_a"] == d4["crash_signal_b"]

                # Error path: missing dump must return an error string, not raise.
                res = await s.call_tool("crash_load", {"dump_path": "/nope"})
                assert res.content[0].text.startswith("error:")

    asyncio.run(main())
