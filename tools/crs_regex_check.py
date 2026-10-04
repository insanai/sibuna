#!/usr/bin/env python3
"""Differential native-regex checks against PCRE2; PCRE2 is a test dependency."""
import ctypes
import ctypes.util
import itertools
import json
import subprocess
import sys


def oracle():
    path = ctypes.util.find_library("pcre2-8")
    if not path:
        raise RuntimeError("PCRE2-8 is required for the differential check")
    lib = ctypes.CDLL(path)
    size = ctypes.c_size_t
    pointer = ctypes.c_void_p
    signatures = {
        "pcre2_compile_8": (pointer, [pointer, size, ctypes.c_uint32,
                                    ctypes.POINTER(ctypes.c_int), ctypes.POINTER(size), pointer]),
        "pcre2_code_free_8": (None, [pointer]),
        "pcre2_match_data_create_from_pattern_8": (pointer, [pointer, pointer]),
        "pcre2_match_data_free_8": (None, [pointer]),
        "pcre2_match_context_create_8": (pointer, [pointer]),
        "pcre2_match_context_free_8": (None, [pointer]),
        "pcre2_set_match_limit_8": (ctypes.c_int, [pointer, ctypes.c_uint32]),
        "pcre2_match_8": (ctypes.c_int, [pointer, pointer, size, size,
                                       ctypes.c_uint32, pointer, pointer]),
        "pcre2_get_ovector_pointer_8": (ctypes.POINTER(size), [pointer]),
        "pcre2_get_ovector_count_8": (ctypes.c_uint32, [pointer]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(lib, name)
        function.restype = result
        function.argtypes = arguments
    return lib


def compare(lib, binary, pattern, inputs):
    error = ctypes.c_int()
    offset = ctypes.c_size_t()
    code = lib.pcre2_compile_8(pattern, len(pattern), 0, ctypes.byref(error),
                             ctypes.byref(offset), None)
    if not code:
        raise AssertionError(f"reference rejected {pattern!r}: {error.value} at {offset.value}")
    data = lib.pcre2_match_data_create_from_pattern_8(code, None)
    context = lib.pcre2_match_context_create_8(None)
    if not data or not context:
        raise RuntimeError("reference matcher allocation failed")
    try:
        lib.pcre2_set_match_limit_8(context, 100_000)
        for text in inputs:
            matched = lib.pcre2_match_8(code, text, len(text), 0, 0, data, context)
            if matched < -1:
                raise AssertionError(f"reference limit/error {matched} for {pattern!r}")
            expected = None
            if matched >= 0:
                spans = lib.pcre2_get_ovector_pointer_8(data)
                count = lib.pcre2_get_ovector_count_8(data)
                absent = ctypes.c_size_t(-1).value
                expected = [[None if spans[i] == absent else spans[i],
                             None if spans[i + 1] == absent else spans[i + 1]]
                            for i in range(0, count * 2, 2)]
            result = subprocess.run([binary, pattern.hex(), text.hex()], capture_output=True,
                                    timeout=5, check=True, text=True)
            actual = json.loads(result.stdout)
            if actual != expected:
                raise AssertionError(f"{pattern!r} / {text!r}: {actual!r} != {expected!r}")
    finally:
        lib.pcre2_match_context_free_8(context)
        lib.pcre2_match_data_free_8(data)
        lib.pcre2_code_free_8(code)


def main():
    lib = oracle()
    patterns = [b"", b"a", b"a|ab", b"ab|a", b"a*", b"a*?", b"a+", b"a+?",
                b"(a+)(b?)", b"(a|b)*", b"(a|(b))+", b"(?:a?)*", b"(?:a?)*?",
                b"(?:a*)*", b"(?:ab|a)+?b", b"a{0,3}", b"(ab){1,3}?", b"^a$",
                b"(?m)^a$", b"(?s)a.b", b"(?i)aB", b"(?i:a)b", b"[a-b]+",
                b"[^a]+", rb"\ba\b", rb"\Ba\B", rb"[\x00-\x{ff}]+",
                rb"a\z", rb"a\Z", rb"\Aa", b"(?i)a|b", b"(a)?(b)?"]
    inputs = [bytes(chars) for length in range(4)
              for chars in itertools.product(b"ab\n", repeat=length)]
    inputs += [b"AB", b"AaB", b" a ", b"zaaaab", b"\x00\xff", b"\xff\x00"]
    total = 0
    for pattern in patterns:
        compare(lib, sys.argv[1], pattern, inputs)
        total += len(inputs)
    for pattern in [b"(a?)*", b"(a?)*?", b"(a*)*"]:
        result = subprocess.run([sys.argv[1], pattern.hex(), ""], capture_output=True,
                                timeout=5, text=True)
        if result.returncode == 0 or "UnsupportedRegex" not in result.stderr:
            raise AssertionError(f"empty captured repetition was not rejected: {pattern!r}")
    release = subprocess.run([sys.argv[1], "--stock"], capture_output=True,
                             timeout=10, check=True, text=True)
    stock = [json.loads(line) for line in release.stdout.splitlines()]
    if len(stock) != 320:
        raise AssertionError(f"expected 320 stock regexes, found {len(stock)}")
    payloads = [b"", b"hello", b"1", b"/etc/passwd", b"<script>alert(1)</script>",
                b"1' or 1=1--", b"UNION SELECT password FROM users", b"../../etc/passwd",
                b"application/json", b"Mozilla/5.0", b"https://example.com/?q=x",
                b"\x00\xff", b"${jndi:ldap://example.com/a}", b"cmd.exe /c whoami",
                b"eval($_GET['x']);"]
    for entry in stock:
        compare(lib, sys.argv[1], entry["pattern"].encode(), payloads)
        total += len(payloads)
    print(f"PCRE2 differential check: {total} matches/captures and 3 rejections passed")


if __name__ == "__main__":
    main()
