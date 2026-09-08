#!/usr/bin/env python3
"""Keep standalone UI builds and console tests subject to the SID 0007 size gate."""
from pathlib import Path
import sys

MAX_BYTES = 300 * 1024


def check(path):
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise SystemExit(f"console-ui: {size} bytes exceeds the {MAX_BYTES}-byte Wasm budget")
    with path.open("rb") as artifact:
        if artifact.read(8) != b"\x00asm\x01\x00\x00\x00":
            raise SystemExit("console-ui: expected a version-1 WebAssembly artifact")
    print(f"console-ui: {size} / {MAX_BYTES} bytes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: console_wasm_check.py <console.wasm>")
    check(Path(sys.argv[1]))
