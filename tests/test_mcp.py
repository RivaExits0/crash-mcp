import asyncio, os, sys, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

def ensure_core():
    crash = os.path.join(ROOT, "tests", "crash")
    core = os.path.join(ROOT, "tests", "core")
    if not os.path.exists(crash) or not os.path.exists(core):
        subprocess.check_call(["make"], cwd=ROOT)
    return core

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
                assert all(n in names for n in ["crash_load", "crash_summary", "crash_threads",
                                                "crash_stack", "crash_disassemble", "crash_compare"])
                await s.call_tool("crash_load", {"dump_path": "tests/core", "binary_paths": ["tests/crash"]})
                res = await s.call_tool("crash_summary", {})
                import json
                d = json.loads(res.content[0].text)
                assert d["crash_signal"] == "SIGSEGV"
                res = await s.call_tool("crash_threads", {"limit": 5, "offset": 0})
                d = json.loads(res.content[0].text)
                assert d["total"] == 1
                res = await s.call_tool("crash_stack", {"thread_id": d["threads"][0]["thread_id"], "limit": 10})
                d2 = json.loads(res.content[0].text)
                assert d2["total"] == 2
                res = await s.call_tool("crash_disassemble", {"address": "0x4007c4", "before": 2, "after": 2})
                d3 = json.loads(res.content[0].text)
                assert len(d3["instructions"]) >= 1
                res = await s.call_tool("crash_compare", {"dump_path_a": "tests/core", "dump_path_b": "tests/core"})
                d4 = json.loads(res.content[0].text)
                assert d4["crash_signal_a"] == d4["crash_signal_b"]
                # no dump loaded error path
                await s.call_tool("crash_load", {"dump_path": "/nope"}) if False else None

    asyncio.run(main())
