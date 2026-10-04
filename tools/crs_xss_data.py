#!/usr/bin/env python3
"""Reproduce native XSS classification tables from the pinned libinjection source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from crs_detector_check import source_files


def build(source):
    text = source.decode("ascii")
    tables = []
    for symbol, name in [("BLACKATTREVENT", "events"), ("BLACKATTR", "attributes"),
                         ("BLACKTAG", "tags")]:
        match = re.search(r"\b" + symbol + r"\[\]\s*=\s*\{(.*?)\n\};", text, re.S)
        if not match:
            raise ValueError("missing XSS classification table")
        block = re.sub(r"/\*.*?\*/", "", match[1], flags=re.S)
        if name == "attributes":
            entries = re.findall(r'\{\s*"([A-Z:]+)",\s*TYPE_([A-Z_]+)\s*\}', block)
            kinds = {"BLACK": "black", "ATTR_URL": "url", "STYLE": "style",
                     "ATTR_INDIRECT": "indirect"}
            lines = [f'    .{{ "{key}", .{kinds[kind]} }},' for key, kind in entries]
            declaration = "pub const attributes = [_]struct { []const u8, Attribute }{"
        else:
            entries = sorted(set(re.findall(r'"([A-Z:]+)"', block)))
            lines = [f'    "{key}",' for key in entries]
            declaration = f"pub const {name} = [_][]const u8{{"
        expected = {"events": 298, "attributes": 20, "tags": 20}[name]
        if len(entries) != expected:
            raise ValueError(f"XSS {name} count mismatch: {len(entries)}")
        tables.append(declaration + "\n" + "\n".join(lines) + "\n};\n")
    header = ("//! Generated from pinned libinjection; tools/crs_xss_data.py.\n"
              "//! Copyright 2012-2016 Nick Galbreath; BSD-3-Clause, see LICENSE.\n"
              "pub const Attribute = enum { none, black, url, style, indirect };\n\n")
    return (header + "\n".join(tables)).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path(".zig-cache/crs-review/libinjection-reference"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source_files(args.source, args.download)
    result = build((args.source / "src/libinjection_xss.c").read_bytes())
    manifest = json.loads(Path("vendor/libinjection/provenance.json").read_text())
    expected = manifest["xss_tables"]
    if (len(result) != expected["bytes"] or
            hashlib.sha256(result).hexdigest() != expected["sha256"]):
        raise ValueError("generated XSS table digest/size mismatch")
    path = Path("vendor/libinjection/xss_tables.zig")
    if args.check:
        if path.read_bytes() != result:
            raise ValueError("committed XSS tables differ from pinned source")
    else:
        path.write_bytes(result)
    print("Pinned XSS classification tables verified")


if __name__ == "__main__":
    main()
