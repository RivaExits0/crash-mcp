# crash-mcp

[![CI](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**crash-mcp** is an MCP server that inspects native crash dumps (ELF core and
Windows minidump) and presents the crash reason, faulting thread, and stack
trace to an AI assistant. It never executes the dump.

## Platform support

| Platform | ELF core (gdb) | Windows minidump | Notes |
|----------|----------------|------------------|-------|
| Linux    | ✅ Full        | ✅ Yes           | gdb required for ELF core stack traces |
| Windows  | ⚠️ Summary only| ✅ Full          | gdb is not available; minidump is the primary path |
| macOS    | ⚠️ Summary only| ✅ Yes           | gdb may not be installed |

On Windows, ELF core dumps can still be parsed for basic info (arch, threads,
modules), but stack traces via `gdb` are unavailable. Windows minidump files
are fully supported.

## Install

```bash
pip install "mcp>=1.0" pyelftools minidump capstone
```

Optional: install `gdb` for ELF core stack traces (Linux only).

## Build the test fixture (Linux)

```bash
make
```

Compiles `tests/crash` and generates `tests/core`. Requires `gcc` and a kernel
that allows core dumps. On Windows, skip this step; minidump tests use mocks.

## Run

```bash
python server.py
```

The server speaks MCP over stdio.

## OpenCode integration

```json
{
  "mcp": {
    "crash": {
      "type": "local",
      "command": ["python", "/path/to/crash-mcp/server.py"],
      "enabled": true
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `crash_load(dump_path, binary_paths=[], symbols_path=None)` | Load a dump (ELF core or Windows minidump) and detect its format. |
| `crash_summary()` | Crash type, faulting address, thread, arch, module, symbols. |
| `crash_threads(limit=20, offset=0)` | List threads (paginated). |
| `crash_stack(thread_id, limit=30, offset=0)` | Stack frames for a thread. |
| `crash_disassemble(address, before=8, after=8)` | Disassemble around an address. |
| `crash_compare(dump_path_a, dump_path_b)` | Compare two dumps. |

## Testing

### Linux (full suite)

```bash
make test
```

Runs the full pytest suite: ELF core integration (real core dump + gdb),
minidump parser, MCP smoke test, error paths, pagination.

### Windows (minidump only)

```bash
python -m pytest tests/test_minidump_mock.py tests/test_extra.py -q
```

Runs minidump mock tests and session/validation tests that do not require a
core dump or gdb.

## Architecture

```
server.py           MCP tool definitions (stdio transport)
analyzer.py         Session management and common reporting
elf_core.py         ELF core parsing and gdb-based stack traces (Linux)
minidump_reader.py  Windows minidump parsing
```

## Security

- No `shell=True`; external commands use argument lists with timeouts.
- No dump execution, no network, no filesystem scanning beyond provided paths.
- Sensitive memory is not returned by default; only registers, addresses, frames.

## Limitations

- ELF core stack traces require gdb (Linux only).
- Minidump stack traces are best-effort frame-pointer walks.
- Minidump thread context parsing depends on the minidump library version.
- On Windows, ELF core stack traces are unavailable (no gdb).

## License

MIT - see [LICENSE](LICENSE).
