# crash-mcp

[![CI](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**crash-mcp** is an MCP server that inspects native crash dumps (ELF core and
Windows minidump) and presents the crash reason, faulting thread, and stack
trace to an AI assistant. It never executes the dump.

## Features

- Parse ELF core dumps with pyelftools: architecture, process name, signal,
  faulting PC, threads, modules (with base/size).
- Parse Windows minidumps with the `minidump` library.
- Stack traces via `gdb` (safe subprocess, no `shell=True`, timeout enforced).
- Capstone disassembly around any address present in dump memory.
- Compare two dumps.
- Pagination for threads and frames.
- Clear errors for missing dumps, bad formats, missing gdb, timeouts.

## Install

```bash
pip install "mcp>=1.0" pyelftools minidump capstone
```

Optional: install `gdb` for ELF core stack traces.

## Build the test fixture

```bash
make
```

Compiles `tests/crash` and generates `tests/core`.

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
| `crash_load(dump_path, binary_paths=[], symbols_path=None)` | Load a dump and detect its format. |
| `crash_summary()` | Crash type, faulting address, thread, arch, module, symbols. |
| `crash_threads(limit=20, offset=0)` | List threads (paginated). |
| `crash_stack(thread_id, limit=30, offset=0)` | Stack frames for a thread. |
| `crash_disassemble(address, before=8, after=8)` | Disassemble around an address. |
| `crash_compare(dump_path_a, dump_path_b)` | Compare two dumps. |

## Testing

```bash
make test
```

Runs the pytest suite (ELF core integration, minidump parser, MCP smoke,
error paths, pagination).

## Architecture

```
server.py           MCP tool definitions (stdio transport)
analyzer.py         Session management and common reporting
elf_core.py         ELF core parsing and gdb-based stack traces
minidump_reader.py  Windows minidump parsing
```

## Security

- No `shell=True`; external commands use argument lists with timeouts.
- No dump execution, no network, no filesystem scanning beyond provided paths.
- Sensitive memory is not returned by default; only registers, addresses, frames.

## Limitations

- ELF core stack traces require gdb.
- Minidump stack traces are best-effort frame-pointer walks.
- Minidump thread context parsing depends on the minidump library version.

## License

MIT - see [LICENSE](LICENSE).
