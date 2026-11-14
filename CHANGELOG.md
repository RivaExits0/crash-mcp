# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-14

### Added
- Initial release of crash-mcp MCP server for crash dump inspection
- 6 MCP tools: `crash_load`, `crash_summary`, `crash_threads`, `crash_stack`, `crash_disassemble`, `crash_compare`
- ELF core dump parsing (Linux) with gdb-based stack traces
- Windows minidump parsing (cross-platform)
- Crash summary, thread listing, stack frame retrieval, disassembly
- Dump comparison tool for similarity analysis
- Pagination support for threads and stack frames
- Cross-platform support (Linux/Windows/macOS) via `platform_utils.py`
- Comprehensive test suite (31 tests passing): ELF core integration, minidump parser, MCP smoke test, error paths, pagination
- CI pipeline (GitHub Actions: ubuntu-latest + windows-latest + macos-latest, Python 3.10/3.11/3.12)

### Security
- No dump execution, no network, no filesystem scanning beyond provided paths
- No `shell=True`; external commands use argument lists with timeouts
- Sensitive memory not returned by default

[0.1.0]: https://github.com/RivaExits0/crash-mcp/releases/tag/v0.1.0