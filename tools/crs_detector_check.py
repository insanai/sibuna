#!/usr/bin/env python3
"""Compare native detector stages with the exact libinjection pin (development only)."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from urllib.request import urlopen


class Token(c.Structure):
    _fields_ = [("position", c.c_size_t), ("length", c.c_size_t), ("count", c.c_ubyte),
                ("kind", c.c_ubyte), ("open", c.c_ubyte), ("close", c.c_ubyte),
                ("value", c.c_ubyte * 32)]


class Stats(c.Structure):
    _fields_ = [("tokens", c.c_size_t), ("dash_comment", c.c_size_t), ("hash", c.c_size_t)]


def source_files(directory, download):
    manifest = json.loads(Path("vendor/libinjection/provenance.json").read_text())
    root = "https://raw.githubusercontent.com/libinjection/libinjection/"
    for entry in manifest["oracle_sources"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or entry["bytes"] > 256 * 1024:
            raise ValueError("invalid pinned detector source")
        path = directory / relative
        if not path.exists() and download:
            with urlopen(root + manifest["commit"] + "/" + entry["path"], timeout=20) as response:
                data = response.read(256 * 1024 + 1)
            if (len(data) != entry["bytes"] or
                    hashlib.sha256(data).hexdigest() != entry["sha256"]):
                raise ValueError(f"pinned detector download mismatch: {relative}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        with path.open("rb") as file:
            data = file.read(256 * 1024 + 1)
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"pinned detector source mismatch: {relative}")


def oracle(directory, download):
    source_files(directory, download)
    path = directory / "oracle.so"
    shared = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    subprocess.run(["cc", "-std=c99", "-O2", shared, "-fPIC", '-DLIBINJECTION_VERSION="pinned"',
                    "-I", str(directory / "src"), "tools/crs_detector_oracle.c",
                    str(directory / "src/libinjection_sqli.c"), "-o", str(path)], check=True)
    library = c.CDLL(str(path.resolve()))
    library.crs_oracle_tokens.argtypes = [c.c_void_p, c.c_size_t, c.c_int,
                                        c.POINTER(Token), c.c_size_t, c.POINTER(Stats)]
    library.crs_oracle_tokens.restype = c.c_size_t
    return library


def expected(library, data, flags):
    storage = (Token * (len(data) + 1))()
    stats = Stats()
    count = library.crs_oracle_tokens(data, len(data), flags, storage, len(storage), c.byref(stats))
    if count > len(storage):
        raise ValueError("oracle token capacity exhausted")
    lines = []
    for token in storage[:count]:
        metadata = [token.kind, token.position, token.length, token.count, token.open, token.close]
        lines.append(" ".join(map(str, metadata)) + " " + bytes(token.value[:token.length]).hex())
    lines.append(f"s {stats.tokens} {stats.dash_comment} {stats.hash}")
    return "\n".join(lines) + "\n"


def inputs():
    yield b""
    for byte in range(256):
        yield bytes([byte])
    for value in [b"SELECT.1", b"SELECT`column`", b"USER_ID()", b"@@`version`", b"@@'var'",
                  b"--xyz\n1", b"-- \n1", b"#xyz\n1", b"/* nested /* */", b"/*!12345 x*/",
                  b"'a''b'", b"'a\\'b'", b"'a\\\\'b'", b"q'[a]b]'", b"nq'<value>'",
                  b"Q'\xffabc\xff'", b"U&'abc'", b"E'abc'", b"N'abc'", b"X'00af'", b"B'01'",
                  b"B'\0'", b"0x\0ab", b"0b011", b"1234.e", b"1e+", b"1fUNION", b"$.word",
                  b"$1,000.00", b"$$abc$$", b"$tag$abc$tag$", b"$tag$abc", b"@\0x",
                  b"[missing", b"[a]1", b"a\0b", b"<=>", b"\\N", b"a" * 80]:
        yield value
    random_source = random.Random(0x6372736465746563)
    alphabet = b"aAbBeEnNuUqQxX01239$@.[]`'\"\\/*-#=!&| \0\xff\xa0\n"
    for _ in range(128):
        yield bytes(random_source.choice(alphabet) for _ in range(random_source.randrange(1, 129)))
    for _ in range(32):
        yield bytes(random_source.randrange(256) for _ in range(64))
    yield b"$" + b"a" * 256 + b"$" + b"a$" * 1024 + b"$" + b"a" * 256 + b"$"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--source", type=Path,
                        default=Path(".zig-cache/crs-review/libinjection-reference"))
    args = parser.parse_args()
    library = oracle(args.source, args.download)
    count = 0
    for index, data in enumerate(inputs()):
        for flags in [9, 17, 10, 18, 12, 20]:
            result = subprocess.run([str(args.binary.resolve()), "tokens", str(flags), data.hex()],
                                    capture_output=True, text=True, timeout=5, check=False)
            wanted = expected(library, data, flags)
            if result.returncode != 0 or result.stdout != wanted:
                raise AssertionError(f"tokens:{index} flags:{flags} input:{data.hex()}\n"
                                     f"native:{result.stdout!r}\nreference:{wanted!r}\n"
                                     f"error:{result.stderr}")
            count += 1
    print(f"Pinned libinjection lexical check: {count} token streams passed")


if __name__ == "__main__":
    main()
