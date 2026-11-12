# crash-mcp

[![CI](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/crash-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**crash-mcp** is an MCP server that inspects native crash dumps (ELF core and
Windows minidump) and presents the crash reason, faulting thread, and stack
trace to an AI assistant. It never executes the dump.

> **Turkish / Türkçe:** crash-mcp, ELF core ve Windows minidump çökme dökümlerini
> inceleyen bir MCP sunucusudur. Çökme nedeni, hata veren iş parçacığı ve stack
> trace'i bir AI asistanına sunar. Döküm dosyasını asla çalıştırmadan, salt
> okunur analiz yapar.

## Platform Support

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

## Build the Test Fixture (Linux)

```bash
make
```

Compiles `tests/crash` and generates `tests/core`. Requires `gcc` and a kernel
that allows core dumps. On Windows, skip this step; minidump tests use mocks.

## Run

```bash
python server.py
```

The server speaks MCP over **stdio**.

## OpenCode Integration

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

## MCP Tools

| Tool | Description | When to call |
|------|-------------|--------------|
| `crash_load(dump_path, binary_paths=[], symbols_path=None)` | Load a dump (ELF core or Windows minidump) and detect its format. | First, before any other crash_* tool. |
| `crash_summary()` | Crash type, faulting address, thread, arch, module, symbols. | After `crash_load`. |
| `crash_threads(limit=20, offset=0)` | List threads (paginated). | To find the faulting thread. |
| `crash_stack(thread_id, limit=30, offset=0)` | Stack frames for a thread. | After `crash_threads`, to inspect a thread. |
| `crash_disassemble(address, before=8, after=8)` | Disassemble around an address. | To inspect instructions near crash PC. |
| `crash_compare(dump_path_a, dump_path_b)` | Compare two dumps. | To check if two crashes are similar. |

### Tool: `crash_load`

**Example call:**
```json
{"tool": "crash_load", "args": {"dump_path": "tests/core", "binary_paths": ["tests/crash"]}}
```

**Example output:**
```json
{
  "format": "ELF core",
  "arch": "arm64",
  "os": "Linux/Unix",
  "process_name": "crash",
  "crash_thread": 4486,
  "crash_signal": "SIGSEGV",
  "signal_code": 1,
  "crash_pc": "0x4007c4",
  "crash_pc_str": "0x4007c4 (/path/to/tests/crash+0x7c4)",
  "thread_count": 1,
  "module_count": 3,
  "gdb_available": true
}
```

### Tool: `crash_summary`

**Example call:**
```json
{"tool": "crash_summary", "args": {}}
```

**Example output:**
```json
{
  "format": "ELF core",
  "arch": "arm64",
  "crash_signal": "SIGSEGV",
  "crash_thread": 4486,
  "crash_pc": "0x4007c4",
  "process_name": "crash"
}
```

### Tool: `crash_threads`

**Example call:**
```json
{"tool": "crash_threads", "args": {"limit": 5, "offset": 0}}
```

**Example output:**
```json
{
  "total": 1,
  "offset": 0,
  "limit": 5,
  "threads": [
    {
      "thread_id": 4486,
      "state": "crashed",
      "signal": 11,
      "pc": "0x4007c4",
      "pc_str": "0x4007c4 (/path/to/tests/crash+0x7c4)"
    }
  ]
}
```

### Tool: `crash_stack`

**Example call:**
```json
{"tool": "crash_stack", "args": {"thread_id": 4486, "limit": 10, "offset": 0}}
```

**Example output:**
```json
{
  "thread_id": 4486,
  "source": "gdb",
  "total": 2,
  "offset": 0,
  "limit": 10,
  "frames": [
    {"index": 0, "text": "#0  0x00000000004007c4 in boom (x=42) at crash.c:6"},
    {"index": 1, "text": "#1  0x00000000004007e4 in main () at crash.c:10"}
  ],
  "gdb_error": null
}
```

### Tool: `crash_disassemble`

**Example call:**
```json
{"tool": "crash_disassemble", "args": {"address": "0x4007c4", "before": 2, "after": 2}}
```

**Example output:**
```json
{
  "address": "0x4007c4",
  "address_str": "0x4007c4 (/path/to/tests/crash+0x7c4)",
  "before": 2,
  "after": 2,
  "instructions": [
    {"address": 0x4007c0, "mnemonic": "str", "op_str": "w1, [x8]", "bytes": "..."},
    {"address": 0x4007c4, "mnemonic": "ret", "op_str": "", "bytes": "..."}
  ]
}
```

### Tool: `crash_compare`

**Example call:**
```json
{"tool": "crash_compare", "args": {"dump_path_a": "tests/core", "dump_path_b": "tests/core"}}
```

**Example output:**
```json
{
  "format_a": "elf_core",
  "format_b": "elf_core",
  "crash_signal_a": "SIGSEGV",
  "crash_signal_b": "SIGSEGV",
  "crash_pc_a": "0x4007c4",
  "crash_pc_b": "0x4007c4",
  "thread_count_a": 1,
  "thread_count_b": 1
}
```

## Testing

### Linux (full suite)

```bash
make test
```

Runs the full pytest suite: ELF core integration (real core dump + gdb),
minidump parser, MCP smoke test, error paths, pagination. 31 tests.

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

## Pagination (`limit` / `offset`)

`crash_threads` and `crash_stack` support `limit` and `offset`:
- `limit`: maximum number of items to return (default 20 for threads, 30 for stack)
- `offset`: number of items to skip (default 0)

Response includes a `pagination`-style object with `total`, `offset`, `limit`, `returned`, and `has_more`.

## Security

- No `shell=True`; external commands use argument lists with timeouts.
- No dump execution, no network, no filesystem scanning beyond provided paths.
- Sensitive memory is not returned by default; only registers, addresses, frames.

## Limitations

- ELF core stack traces require gdb (Linux only).
- Minidump stack traces are best-effort frame-pointer walks.
- Minidump thread context parsing depends on the minidump library version.
- On Windows, ELF core stack traces are unavailable (no gdb).
- Static analysis cannot guarantee runtime behaviour.

## License

MIT — see [LICENSE](LICENSE).
