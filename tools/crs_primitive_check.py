#!/usr/bin/env python3
"""Check primitive results against the corpus pinned by ModSecurity 3.0.14.

Vectors remain external test inputs. --download retrieves missing files from the pinned
official commit; every file is bounded and checked against its committed digest and count.
This checks a stated subset, not full CRS compatibility or daemon behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.request import urlopen


class UndefinedVector(ValueError):
    """The reference runner reads an uninitialized sscanf result for this encoding."""


def json_bytes(value):
    # Pinned test/unit/unit_test.cc constructs std::string from YAJL's C string
    # before json2bin expands literal \\xNN and \\uNNNN to a single low byte.
    # Direct JSON NULs therefore truncate; escaped binary NULs remain length-aware.
    result = value.encode("utf-8").split(b"\0", 1)[0]
    for prefix, width in [(b"x", 2), (b"u", 4)]:
        pattern = re.compile(rb"\\" + prefix + rb"([a-zA-Z0-9]{" + str(width).encode() + rb"})")
        while match := pattern.search(result):
            digits = re.match(rb"[0-9a-fA-F]+", match[1])
            if digits is None:
                raise UndefinedVector(f"reference sscanf cannot decode {match[0]!r}")
            number = int(digits[0], 16)
            result = result.replace(match[0], bytes([number & 255]))
    return result


def read_pinned(directory, manifest, entry, download):
    root = "https://raw.githubusercontent.com/owasp-modsecurity/secrules-language-tests/"
    relative = Path(entry["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid pinned corpus path")
    path = directory / relative
    if not path.exists() and download:
        with urlopen(root + manifest["corpus_commit"] + "/" + entry["path"],
                     timeout=20) as response:
            data = response.read(65537)
        if len(data) > 65536 or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"download digest/size mismatch: {relative}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with path.open("rb") as source:
        data = source.read(65537)
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"corpus digest/size mismatch: {relative}")
    return data


def vectors(directory, manifest, download):
    total = 0
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        data = read_pinned(directory, manifest, entry, download)
        cases = json.loads(data)
        if len(cases) != entry["cases"]:
            raise ValueError(f"corpus count mismatch: {relative}")
        for index, case in enumerate(cases):
            total += 1
            reason = entry.get("undefined_encoding", {}).get(str(index))
            if reason is not None:
                try:
                    json_bytes(case["input"])
                    json_bytes(case.get("output", ""))
                except UndefinedVector:
                    print(f"Undefined upstream fixture: {relative}:{index}: {reason}")
                    continue
                raise ValueError(f"stale undefined-encoding exception: {relative}:{index}")
            yield relative, index, case, entry.get("failed_initialization", {}).get(str(index))
    expected = manifest["cases"]
    if total != expected:
        raise ValueError(f"expected {expected} pinned primitive cases, found {total}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("corpus", type=Path, nargs="?",
                        default=Path(".zig-cache/crs-review/seclang-tests"))
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(Path(__file__).with_name("crs_primitive_vectors.json").read_text())
    resources = {entry["parameter"].encode(): read_pinned(args.corpus, manifest, entry, args.download)
                 for entry in manifest.get("resources", [])}
    count = 0
    for path, index, case, failed_init in vectors(args.corpus, manifest, args.download):
        kind = case["type"]
        # The pinned corpus predates the canonical CRS spelling of this action.
        aliases = {"cmd_line": "cmdLine", "normalisePath": "normalizePath",
                   "normalisePathWin": "normalizePathWin"}
        name = aliases.get(case["name"], case["name"])
        input_bytes = json_bytes(case["input"])
        parameter = case.get("param", "").encode("utf-8").split(b"\0", 1)[0]
        if name == "pmFromFile":
            parameter = resources[parameter]
        result = subprocess.run([str(args.binary.resolve()), kind, name,
                                 input_bytes.hex(), parameter.hex()], check=False,
                                capture_output=True, timeout=5, text=True)
        if failed_init is not None:
            if name != "validateByteRange" or kind != "op" or result.returncode == 0:
                raise AssertionError(f"{path}:{index}: invalid initialization was not rejected")
            if "InvalidRange" not in result.stderr:
                raise AssertionError(f"{path}:{index}: unexpected rejection: {result.stderr}")
            # The reference unit runner ignores failed init and evaluates its empty
            # table. Verify that historical result without allowing activation of it.
            result = subprocess.run([str(args.binary.resolve()), "op-uninitialized", name,
                                     input_bytes.hex(), parameter.hex()], check=False,
                                    capture_output=True, timeout=5, text=True)
        if result.returncode != 0:
            raise AssertionError(f"{path}:{index}: probe failed: {result.stderr.strip()}")
        if kind == "op":
            expected = "true" if case["ret"] else "false"
        elif kind == "tfn":
            # The reference transformation runner compares bytes, not the legacy ret flag.
            expected = json_bytes(case["output"]).hex()
        else:
            raise ValueError(f"unsupported test kind: {kind}")
        actual = result.stdout.rstrip("\n")
        if actual != expected:
            raise AssertionError(f"{path}:{index}: {actual!r} != {expected!r}")
        count += 1
    print(f"Pinned SecLang primitive check: {count} cases passed (compatibility subset)")


if __name__ == "__main__":
    main()
