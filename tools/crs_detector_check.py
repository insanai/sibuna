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
from crs_detector_corpus import inputs as corpus_inputs


class Token(c.Structure):
    _fields_ = [("position", c.c_size_t), ("length", c.c_size_t), ("count", c.c_ubyte),
                ("kind", c.c_ubyte), ("open", c.c_ubyte), ("close", c.c_ubyte),
                ("value", c.c_ubyte * 32)]


class Stats(c.Structure):
    _fields_ = [("tokens", c.c_size_t), ("dash_comment", c.c_size_t),
                ("hash", c.c_size_t), ("folds", c.c_size_t)]


class HtmlToken(c.Structure):
    _fields_ = [("position", c.c_size_t), ("length", c.c_size_t), ("kind", c.c_ubyte)]


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
                    str(directory / "src/libinjection_sqli.c"),
                    str(directory / "src/libinjection_html5.c"),
                    str(directory / "src/libinjection_xss.c"), "-o", str(path)], check=True)
    library = c.CDLL(str(path.resolve()))
    library.crs_oracle_tokens.argtypes = [c.c_void_p, c.c_size_t, c.c_int,
                                        c.POINTER(Token), c.c_size_t, c.POINTER(Stats)]
    library.crs_oracle_tokens.restype = c.c_size_t
    library.crs_oracle_fingerprint.argtypes = [c.c_void_p, c.c_size_t, c.c_int,
                                              c.POINTER(Token), c.POINTER(Stats),
                                              c.POINTER(c.c_ubyte)]
    library.crs_oracle_fingerprint.restype = c.c_size_t
    library.crs_oracle_detect.argtypes = [c.c_void_p, c.c_size_t, c.POINTER(c.c_ubyte)]
    library.crs_oracle_detect.restype = c.c_int
    library.crs_oracle_html.argtypes = [c.c_void_p, c.c_size_t, c.c_int,
                                      c.POINTER(HtmlToken), c.c_size_t]
    library.crs_oracle_html.restype = c.c_size_t
    library.libinjection_xss.argtypes = [c.c_void_p, c.c_size_t]
    library.libinjection_xss.restype = c.c_int
    return library


def expected(library, data, flags, mode):
    # The C XSS pin reads a fixed event-name length past short attribute tokens.
    # Zero padding keeps that test oracle's backing allocation readable; its
    # advertised input length and every native token bound remain unchanged.
    backing = data + b"\0" * 64
    if mode == "xss":
        return f"x {library.libinjection_xss(backing, len(data))}\n"
    if mode == "html":
        storage = (HtmlToken * (2 * len(data) + 8))()
        count = library.crs_oracle_html(backing, len(data), flags, storage, len(storage))
        if count > len(storage):
            raise ValueError("oracle HTML token capacity exhausted")
        lines = []
        for token in storage[:count]:
            end = token.position + token.length
            if end > len(data):
                raise ValueError("oracle HTML token outside input")
            lines.append(f"{token.kind} {token.position} {token.length} " +
                         data[token.position:end].hex() + "\n")
        return "".join(lines)
    if mode == "sqli":
        signature = (c.c_ubyte * 8)()
        matched = library.crs_oracle_detect(backing, len(data), signature)
        value = bytes(signature).split(b"\0", 1)[0]
        return f"d {matched} {value.hex()}\n"
    storage = (Token * (len(data) + 1))()
    stats = Stats()
    signature = (c.c_ubyte * 8)()
    if mode == "tokens":
        count = library.crs_oracle_tokens(backing, len(data), flags, storage, len(storage),
                                         c.byref(stats))
    else:
        count = library.crs_oracle_fingerprint(backing, len(data), flags, storage,
                                              c.byref(stats), signature)
    if count > len(storage):
        raise ValueError("oracle token capacity exhausted")
    lines = [] if mode == "tokens" else ["f " + bytes(signature[:count]).hex()]
    for token in storage[:count]:
        metadata = [token.kind, token.position, token.length, token.count, token.open, token.close]
        lines.append(" ".join(map(str, metadata)) + " " + bytes(token.value[:token.length]).hex())
    footer = f"s {stats.tokens} {stats.dash_comment} {stats.hash}"
    lines.append(footer if mode == "tokens" else footer + f" {stats.folds}")
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
                  b"[missing", b"[a]1", b"a\0b", b"<=>", b"\\N", b"a" * 80,
                  b"1 UNION SELECT password FROM users", b"1 OR 1=1-- ",
                  b"' OR 'a'='a", b"' UNION SELECT NULL,NULL#", b"1; DROP TABLE users",
                  b"ascii(substring(version() from 1 for 1))", b"1--sp_password",
                  b"1#sp_password", b"1--SP_PASSWORD", b"ordinary application text",
                  b"USER()", b"IF(1,2,3)", b"{`}", b"(1,2,3)", b"'hello' + 'world'",
                  b"1 /* harmless */", b"name--comment", b"one two three four five six",
                  b"SELECT/*gap*/password FROM users", b"1::int", b"1 NOT IN (2,3)"]:
        yield value
    random_source = random.Random(0x6372736465746563)
    alphabet = b"aAbBeEnNuUqQxX01239$@.[]`'\"\\/*-#=!&| \0\xff\xa0\n"
    for _ in range(128):
        yield bytes(random_source.choice(alphabet) for _ in range(random_source.randrange(1, 129)))
    for _ in range(32):
        yield bytes(random_source.randrange(256) for _ in range(64))
    yield b"$" + b"a" * 256 + b"$" + b"a$" * 1024 + b"$" + b"a" * 256 + b"$"


def html_inputs():
    yield b""
    for byte in range(256):
        yield bytes([byte])
    for value in [b"text<a href='url'/>tail", b"</a>", b"</a attr>", b"<a", b"<a x",
                  b"<a x=", b"<a x=>", b"<a x=''>", b"<a x=unquoted>", b"<a x=\0y>",
                  b"<script>alert(1)</script>", b"<svg onload=alert(1)>", b"<?xml?>",
                  b"<!doctype html>", b"<!DoCtYpE x>", b"<![CDATA[x]]>", b"<![cdata[x]]>",
                  b"<!---->", b"<!--x-!>tail", b"<!--x-\0->tail", b"<!--x-\0!>tail",
                  b"<!---", b"<!-", b"<%x%>tail", b"<%x%y%>tail", b"<%x%",
                  b"<\0script>", b"<scr\0ipt>", b"</>", b"<<", b"<>tail", b"<a///>",
                  b"<a x='a'y=b/>", b"<a x=`a`>", b"<a x='a'\0y=b>", b"' ><script>",
                  b"<a" + b"/" * 8192 + b">", b"<!--" + b"-\0x" * 1024,
                  b"<![CDATA[" + b"]x" * 1024, b"<%" + b"%x" * 1024,
                  b"<a href=javascript:alert(1)>", b"<a href='&#106;avascript:alert(1)'>",
                  b"<a href='&#x1004a;ava'>", b"<a href='&'>", b"<a href='&#'>",
                  b"<a href='&#x'>", b"<a href='&#9999999999;'>", b"<a onloadextra=1>",
                  b"<a onclick>", b"<a style=''>", b"<a style>", b"<a dataformatas=1>",
                  b"<a attributename='href'>", b"<a on\0load=1>", b"<a onlo=1>",
                  b"<a xmlnsfoo=1>", b"<svgi>", b"<xslfoo>", b"<?IMPORT x>",
                  b"<!--ENTITY x-->", b"<!--[if IE]>x<![endif]-->", b"<!--x`y-->"]:
        yield value
    random_source = random.Random(0x63727368746d6c35)
    alphabet = b"aAxX<>/=!-?%[]`'\"&; \0\xff\t\n"
    for _ in range(256):
        yield bytes(random_source.choice(alphabet) for _ in range(random_source.randrange(1, 129)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--source", type=Path,
                        default=Path(".zig-cache/crs-review/libinjection-reference"))
    args = parser.parse_args()
    library = oracle(args.source, args.download)
    corpus = corpus_inputs(args.source, args.download)
    sql_inputs = list(inputs())
    for category in ["tokens", "folding", "sqli"]:
        sql_inputs.extend(data for _, data in corpus[category])
    count = 0
    for index, data in enumerate(sql_inputs):
        for flags in [9, 17, 10, 18, 12, 20]:
            modes = ["tokens", "fingerprint"] + (["sqli"] if flags == 9 else [])
            for mode in modes:
                result = subprocess.run([str(args.binary.resolve()), mode, str(flags), data.hex()],
                                        capture_output=True, text=True, timeout=5, check=False)
                wanted = expected(library, data, flags, mode)
                if result.returncode != 0 or result.stdout != wanted:
                    raise AssertionError(f"{mode}:{index} flags:{flags} input:{data.hex()}\n"
                                         f"native:{result.stdout!r}\nreference:{wanted!r}\n"
                                         f"error:{result.stderr}")
                count += 1
    print(f"Pinned libinjection stage check: {count} token/fingerprint/decision results passed")
    count = 0
    html_cases = list(html_inputs()) + [data for _, data in corpus["html5"]]
    for index, data in enumerate(html_cases):
        for flags in range(6):
            mode = "html" if flags < 5 else "xss"
            result = subprocess.run([str(args.binary.resolve()), mode, str(flags), data.hex()],
                                    capture_output=True, text=True, timeout=5, check=False)
            wanted = expected(library, data, flags, mode)
            if result.returncode != 0 or result.stdout != wanted:
                raise AssertionError(f"{mode}:{index} flags:{flags} input:{data.hex()}\n"
                                     f"native:{result.stdout!r}\nreference:{wanted!r}\n"
                                     f"error:{result.stderr}")
            count += 1
    print(f"Pinned libinjection XSS check: {count} token streams and decisions passed")


if __name__ == "__main__":
    main()
