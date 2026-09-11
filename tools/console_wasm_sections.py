#!/usr/bin/env python3
"""Report the section sizes of a console WebAssembly artifact for budget reviews."""
from pathlib import Path
import sys

NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
    12: "datacount",
}


def integer(data, offset):
    result, shift = 0, 0
    while True:
        value = data[offset]
        offset += 1
        result |= (value & 127) << shift
        shift += 7
        if value < 128:
            return result, offset


def sections(data):
    if data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("expected a version-1 WebAssembly artifact")
    offset = 8
    while offset < len(data):
        kind = data[offset]
        length, offset = integer(data, offset + 1)
        name = NAMES.get(kind, str(kind))
        if kind == 0:
            label_length, start = integer(data, offset)
            name = "custom:" + data[start:start + label_length].decode("utf-8", "replace")
        yield name, length
        offset += length


def main(argv):
    if len(argv) != 2:
        print("usage: console_wasm_sections.py <console.wasm>", file=sys.stderr)
        return 2
    data = Path(argv[1]).read_bytes()
    for name, length in sections(data):
        print(f"{length:>9}  {name}")
    print(f"{len(data):>9}  total")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
