#!/usr/bin/env python3
"""Build committed console CSS explicitly; verify input/output digests without npm."""
import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "apps/console-ui/web"
MANIFEST = WEB / "assets/MANIFEST.md"


def manifest():
    files = sorted((ROOT / "apps/console-ui/src").glob("*.zig"))
    files += [WEB / name for name in ("tailwind.css", "package.json", "package-lock.json",
                                      "shell.html", "glue.js", "assets/console.css")]
    files += [Path(__file__).resolve()]
    lines = ["# Console asset input/output digests", "", "```text"]
    for path in sorted(files):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}")
    return "\n".join(lines + ["```", ""])


if __name__ == "__main__":
    if sys.argv[1:] == ["build"]:
        subprocess.run(["npm", "ci", "--ignore-scripts"], cwd=WEB, check=True)
        subprocess.run(["npm", "run", "build"], cwd=WEB, check=True)
        MANIFEST.write_text(manifest())
    elif sys.argv[1:] == ["check"]:
        if not MANIFEST.exists() or MANIFEST.read_text() != manifest():
            raise SystemExit("Console assets are stale. Run zig build console-assets and commit outputs.")
        print("console-assets: committed inputs and outputs match")
    else:
        raise SystemExit("usage: console_assets.py build|check")
