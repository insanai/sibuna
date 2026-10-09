#!/usr/bin/env python3
"""Stage verified SQLite sources for an offline distribution build.

Run in an unpacked source tree, never in the release checkout. Inputs are extracted
SQLite 3.50.4 and sqlite-vec 0.1.9 amalgamations, fetched by the package manager.
These file digests qualify the locally pinned inputs; they are not archive hashes.
"""
import argparse
import hashlib
from pathlib import Path
import re


DEPENDENCIES = {
    "sqlite": {
        "url": "https://sqlite.org/2025/sqlite-amalgamation-3500400.zip",
        "hash": "N-V-__8AAHCbqABM_X5RTjbDBDBWErxZE8tJzmtEnLOLRHGx",
        "files": {
            "shell.c": "c446ff8f3109335ce6d0731b6f7d65e57f1d1747c9bfc8b18b50db8f48cd253a",
            "sqlite3.c": "e3f5d6901e7492af4a1fc8c4d745cae84c264942524c3fbfc02b82a5ca8818c8",
            "sqlite3.h": "abd1514e0351f79393d1be882830afdb40a8099e8257f311f0bfdf8486f11bea",
            "sqlite3ext.h": "9a91de0d5e5ccc04ec59041275c67972d6f8894f7543a10033e387b69987beb5",
        },
    },
    "sqlite_vec": {
        "url": "https://github.com/asg017/sqlite-vec/releases/download/v0.1.9/"
               "sqlite-vec-0.1.9-amalgamation.zip",
        "hash": "N-V-__8AAFjlBACTHqSZPx-m0Y-NHDBK6_c28UfnIp9rxqgX",
        "files": {
            "sqlite-vec.c": "ba081a47fa02eadc3cf6b16c314b695b84081269349aac722b4efa338fe8fd85",
            "sqlite-vec.h": "8e4d7bfcd779c89bd19a6b2959fce24ee391b2eaf79a85a979377a36627cb060",
        },
    },
}


def prepare(root, sources):
    manifest = root / "vendor/zaxonlite/build.zig.zon"
    original = manifest.read_text()
    updated = original
    verified = {}
    # Validate every input and lock entry before creating any staged output.
    for name, dependency in DEPENDENCIES.items():
        for filename, expected in dependency["files"].items():
            source = sources[name] / filename
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"{name}: missing regular source file {filename}")
            content = source.read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError(f"{name}: source digest mismatch for {filename}")
            verified[name, filename] = content
        pattern = (r"\." + name + r" = \.\{\s*\.url = \"" +
                   re.escape(dependency["url"]) + r"\",\s*\.hash = \"" +
                   re.escape(dependency["hash"]) + r"\",\s*\},")
        replacement = f'.{name} = .{{ .path = "../distribution-{name}" }},'
        updated, count = re.subn(pattern, replacement, updated)
        if count != 1:
            raise ValueError(f"{name}: dependency lock differs or is already staged")
        destination = root / "vendor" / f"distribution-{name}"
        if destination.exists():
            raise ValueError(f"{name}: staging directory already exists")
    for name, dependency in DEPENDENCIES.items():
        destination = root / "vendor" / f"distribution-{name}"
        destination.mkdir()
        for filename in dependency["files"]:
            (destination / filename).write_bytes(verified[name, filename])
    manifest.write_text(updated)
    print("distribution-source: verified SQLite 3.50.4 and sqlite-vec 0.1.9; no remote dependencies")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--sqlite-vec", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.root.resolve(), {"sqlite": args.sqlite.resolve(),
                                      "sqlite_vec": args.sqlite_vec.resolve()})
    except (OSError, ValueError) as error:
        parser.exit(1, f"distribution-source: {error}\n")
