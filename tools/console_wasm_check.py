#!/usr/bin/env python3
"""Keep standalone UI builds and console tests subject to the SID 0007 size gate."""
from pathlib import Path
import sys

MAX_BYTES = 384 * 1024
EXPORTS = {
    "memory": 2,
    **dict.fromkeys((
        "sb_event", "sb_init", "sb_geometry_loaded", "sb_geometry_capacity",
        "sb_geometry_input", "sb_commands_length", "sb_commands", "sb_html_length",
        "sb_html", "sb_input_capacity", "sb_input", "sb_frame_html", "sb_frame",
    ), 0),
}


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        if length > len(self.data) - self.offset:
            raise ValueError("truncated section")
        start = self.offset
        self.offset += length
        return self.data[start:self.offset]

    def byte(self):
        return self.take(1)[0]

    def integer(self):
        result = 0
        for shift in range(0, 35, 7):
            value = self.byte()
            if shift == 28 and value > 15:
                raise ValueError("invalid u32 operand")
            result |= (value & 127) << shift
            if value < 128:
                return result
        raise ValueError("unterminated u32 operand")

    def remaining(self):
        return len(self.data) - self.offset


def contract(data):
    """Check linker-owned ABI metadata; browsers validate and execute the actual code."""
    module = Reader(data)
    if module.take(8) != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("expected a version-1 WebAssembly artifact")
    checked = set()
    while module.remaining():
        kind = module.byte()
        section = Reader(module.take(module.integer()))
        if kind not in (2, 5, 7):
            continue
        if kind in checked:
            raise ValueError("duplicate ABI section")
        checked.add(kind)
        count = section.integer()
        if kind == 2 and count != 0:
            raise ValueError("UI must not import host functions or memory")
        if kind == 5:
            if count != 1 or section.integer() != 1:
                raise ValueError("expected one unshared memory with an explicit maximum")
            if section.integer() != 64 or section.integer() != 64:
                raise ValueError("initial and maximum memory must both be 4 MiB")
        if kind == 7:
            exports = {}
            for _ in range(count):
                name = section.take(section.integer()).decode("utf-8")
                if name in exports:
                    raise ValueError("duplicate export name")
                exports[name] = section.byte()
                index = section.integer()
                if name == "memory" and index != 0:
                    raise ValueError("wrong exported memory")
            if exports != EXPORTS:
                raise ValueError("exports do not match the fixed browser bridge")
        if section.remaining():
            raise ValueError("trailing ABI section bytes")
    if not {5, 7} <= checked:
        raise ValueError("missing memory or exports")


def check(path, output=None):
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise SystemExit(f"console-ui: {size} bytes exceeds the {MAX_BYTES}-byte Wasm budget")
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SystemExit("console-ui: input changed beyond the Wasm budget")
    try:
        contract(data)
    except (ValueError, UnicodeDecodeError) as error:
        raise SystemExit(f"console-ui: {error}") from error
    if output is not None:
        output.write_bytes(data)
    print(f"console-ui: {len(data)} / {MAX_BYTES} bytes")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: console_wasm_check.py <console.wasm> [checked-output.wasm]")
    check(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) == 3 else None)
