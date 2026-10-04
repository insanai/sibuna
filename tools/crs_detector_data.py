#!/usr/bin/env python3
"""Reproduce the pinned native SQL detector dictionary; never activate daemon rules."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.request import urlopen


def build(source, manifest):
    if hashlib.sha256(source).hexdigest() != manifest["source_sha256"]:
        raise ValueError("detector source digest mismatch")
    entries = re.findall(rb'\{"([^"\\]*)", \'(.)\'\}', source)
    if len(entries) != manifest["entries"]:
        raise ValueError("detector dictionary count mismatch")
    kinds = set(b"Ffkt onTvEUB1&A".replace(b" ", b""))
    previous = b""
    for key, kind in entries:
        if not 0 < len(key) <= 29 or any(byte == 0 or byte >= 128 for byte in key):
            raise ValueError("invalid detector dictionary key")
        if key != key.upper() or key <= previous or kind[0] not in kinds:
            raise ValueError("invalid dictionary ordering or type")
        previous = key
    index = bytearray()
    data = bytearray()
    for key, kind in entries:
        index.extend(struct.pack("<IHBx", len(data), len(key), kind[0]))
        data.extend(key)
    return b"SBSQ001\0" + struct.pack("<I", len(entries)) + index + data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path(".zig-cache/crs-review/libinjection-reference/src/"
                                     "libinjection_sqli_data.h"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = Path("vendor/libinjection")
    manifest = json.loads((directory / "provenance.json").read_text())
    if not args.source.exists() and args.download:
        with urlopen(manifest["source_url"], timeout=20) as response:
            source = response.read(256 * 1024 + 1)
        if len(source) != manifest["source_bytes"]:
            raise ValueError("detector source size mismatch")
        if hashlib.sha256(source).hexdigest() != manifest["source_sha256"]:
            raise ValueError("detector source digest mismatch")
        args.source.parent.mkdir(parents=True, exist_ok=True)
        args.source.write_bytes(source)
    with args.source.open("rb") as file:
        source = file.read(256 * 1024 + 1)
    if len(source) != manifest["source_bytes"]:
        raise ValueError("detector source size mismatch")
    result = build(source, manifest)
    if (len(result) != manifest["asset_bytes"] or
            hashlib.sha256(result).hexdigest() != manifest["asset_sha256"]):
        raise ValueError("generated detector asset digest/size mismatch")
    path = directory / "sqli-table.bin"
    if args.check:
        if path.read_bytes() != result:
            raise ValueError("committed detector asset differs from pinned source")
    else:
        path.write_bytes(result)
    print(f"Pinned detector dictionary: {manifest['entries']} entries verified")


if __name__ == "__main__":
    main()
