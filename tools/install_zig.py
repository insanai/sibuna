#!/usr/bin/env python3
"""Install the pinned official Zig toolchain after checking its archive digest."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tarfile
import urllib.request
import zipfile
from prepare_build import prepare


def main():
    lock = json.loads(Path(__file__).with_name("zig-release.json").read_text())
    machine = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(),
                                                            platform.machine())
    system = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}[platform.system()]
    entry = lock["platforms"][f"{machine}-{system}"]
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / Path(entry["tarball"]).name
    with urllib.request.urlopen(entry["tarball"], timeout=120) as response:
        with archive.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != entry["shasum"]:
        raise SystemExit("Official Zig archive checksum mismatch")
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(destination)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")
    executable = "zig.exe" if system == "windows" else "zig"
    toolchain = next(destination.glob(f"zig-*/{executable}")).parent
    prepare(toolchain / executable)
    if path_file := os.environ.get("GITHUB_PATH"):
        with open(path_file, "a") as output:
            output.write(str(toolchain) + "\n")
    print(toolchain / executable)


if __name__ == "__main__":
    main()
