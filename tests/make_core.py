"""Build the ELF-core test fixture.

Generates a static crashing binary and captures a real core dump, then
normalizes the kernel-specific core file name to ``tests/core``.

The script is architecture independent: it works on x86_64, aarch64, and
other Linux hosts. The resulting core is used by the pytest suite.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "crash.c")
BIN = os.path.join(HERE, "crash")
CORE = os.path.join(HERE, "core")


def build() -> str:
    """Compile the crashing helper binary."""
    cc = os.environ.get("CC") or shutil.which("gcc") or shutil.which("cc")
    if not cc:
        raise RuntimeError("no C compiler found (set CC)")
    cmd = [cc, "-O0", "-g", "-static", "-fno-pie", "-no-pie", "-o", BIN, SRC]
    subprocess.run(cmd, check=True)
    return BIN


def _core_candidates() -> list[str]:
    pats = ["core", "core.*", "*.core", "core_dump*"]
    found: list[str] = []
    for pat in pats:
        found.extend(glob.glob(os.path.join(HERE, pat)))
    return sorted(set(f for f in found if os.path.isfile(f)))


def capture_core_via_gdb() -> str | None:
    """Generate a core dump by running the binary under gdb.

    Used as a fallback when the kernel does not write core files directly
    (common on CI runners with restricted core_pattern).
    """
    try:
        subprocess.run(
            [
                "gdb", "-batch", "-nx", "-q",
                "-ex", "set pagination off",
                "-ex", "run",
                "-ex", f"generate-core-file {CORE}",
                "-ex", "quit",
                "--args", BIN,
            ],
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        pass
    return CORE if os.path.exists(CORE) else None


def capture_core() -> str | None:
    """Run the crashing binary and locate (or generate) the core dump."""
    for f in _core_candidates():
        os.remove(f)

    def _limits() -> None:
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
            # hard may already be RLIM_INFINITY (-1); raise soft to match.
            target = hard if hard != 0 else resource.RLIM_INFINITY
            resource.setrlimit(resource.RLIMIT_CORE, (target, hard))
        except Exception:
            pass

    proc = subprocess.run(
        [BIN],
        cwd=HERE,
        preexec_fn=_limits,
        capture_output=True,
        text=True,
    )
    # A crash is expected: negative return code means it died from a signal.
    if proc.returncode >= 0:
        print(f"warning: crashing binary exited normally ({proc.returncode})", file=sys.stderr)

    candidates = _core_candidates()
    if candidates:
        newest = max(candidates, key=os.path.getmtime)
        if os.path.abspath(newest) != os.path.abspath(CORE):
            shutil.copyfile(newest, CORE)
        return CORE

    # Fallback: generate core via gdb (works when kernel restricts core files).
    print("direct core capture failed; trying gdb generate-core-file", file=sys.stderr)
    return capture_core_via_gdb()


def ensure() -> str:
    """Build the binary and core dump if they are missing."""
    if not os.path.exists(BIN):
        build()
    if not os.path.exists(CORE):
        core = capture_core()
        if core is None:
            raise RuntimeError(
                "could not capture a core dump; the host may forbid core dumps "
                "(check /proc/sys/kernel/core_pattern and RLIMIT_CORE)"
            )
    return CORE


def main() -> int:
    build()
    core = capture_core()
    if core is None:
        print("error: no core dump produced", file=sys.stderr)
        return 1
    print(f"core dump: {core} ({os.path.getsize(core)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
