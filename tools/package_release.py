#!/usr/bin/env python3
"""Package a verified executable with licenses and exact corresponding-source provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from check_release_version import ROOT, version

from release_targets import TARGETS


def package(binary, target, destination):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise SystemExit("Release archives require a clean working tree")
    release = version()
    source = f"https://github.com/insanai/sibuna/tree/v{release}"
    manifest = {
        "version": release, "commit": commit, "source": source,
        "target": TARGETS[target], "package": target, "zig": json.loads((ROOT / "tools/zig-release.json").read_text())["version"],
        "optimization": "safe", "stripped": True,
        "features": {"storage": True, "console": True, "cluster": False},
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "license": "AGPL-3.0", "engine_license": "LGPL-3.0",
        "signed": False,
        "requirements": "Windows 10 / Server 2019 or later" if target.startswith("windows") else
                        "macOS 15 or later" if target.startswith("macos") else "Linux 5.10 or later",
    }
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        shutil.copyfile(binary, root / binary.name)
        (root / binary.name).chmod(0o755)
        for name in ("README.md", "LICENSE", "NOTICE"):
            shutil.copyfile(ROOT / name, root / name)
        # Each archive carries only the C runtime notices its executable links.
        linked = {"musl-COPYRIGHT.txt": target.startswith("linux"),
                  "mingw-w64-ZPL-2.1.txt": target.startswith("windows"),
                  "mingw-w64-gdtoa.txt": target.startswith("windows")}
        shutil.copytree(ROOT / "LICENSES", root / "LICENSES",
                        ignore=lambda _, names: [n for n in names if not linked.get(n, True)])
        (root / "sibuna.build.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (root / "SOURCE.txt").write_text(
            f"Corresponding source: {source}\nCommit: {commit}\n"
            f"Source archive: https://github.com/insanai/sibuna/archive/refs/tags/v{release}.tar.gz\n"
            "Build: zig build -Doptimize=safe -Dstrip=true "
            f"-Dtarget={TARGETS[target]} -j2\n"
            "Pinned dependencies and their sources: build.zig.zon and NOTICE.\n"
            "Full license texts and notices: LICENSE, LICENSES/ and NOTICE.\n")
        if target.startswith("windows"):
            archive = destination / f"sibuna-{target}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for file in sorted(root.rglob("*")):
                    if file.is_file():
                        bundle.write(file, file.relative_to(root))
        else:
            archive = destination / f"sibuna-{target}.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for file in sorted(root.iterdir()):
                    bundle.add(file, arcname=file.name)
        print(archive)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    package(args.binary.resolve(), args.target, args.output)
